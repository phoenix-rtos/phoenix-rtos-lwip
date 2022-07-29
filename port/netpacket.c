/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP packet sockets
 *
 * Copyright 2018 Phoenix Systems
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "lwip/opt.h"

#if LWIP_NETPACKET

#include "lwip/memp.h"
#include "lwip/sockets.h"
#include "netpacket.h"

#include <net/ethernet.h>


static void netpacket_linkoutput_full(struct netif *netif, struct pbuf *p, struct netpacket_pcb *from_pcb);


static struct netpacket_pcb *netpacket_pcbs;


struct netpacket_pcb *netpacket_new(struct netconn *conn, u16_t proto)
{
	struct netpacket_pcb *pcb;

	LWIP_ASSERT_CORE_LOCKED();

	pcb = (struct netpacket_pcb *)memp_malloc(MEMP_NETPACKET_PCB);
	if (pcb != NULL) {
		pcb->conn = conn;
		pcb->netif = NULL;
		pcb->type = (conn->type == NETCONN_NETPACKET_RAW) ? SOCK_RAW : SOCK_DGRAM;
		pcb->protocol = proto;
		pcb->next = netpacket_pcbs;
		netpacket_pcbs = pcb;
	}

	return pcb;
}


void netpacket_remove(struct netpacket_pcb *pcb)
{
	struct netpacket_pcb *curr_pcb;

	LWIP_ASSERT_CORE_LOCKED();

	if (netpacket_pcbs == pcb) {
		netpacket_pcbs = netpacket_pcbs->next;
	}
	else {
		for (curr_pcb = netpacket_pcbs; curr_pcb != NULL; curr_pcb = curr_pcb->next) {
			if (curr_pcb->next != NULL && curr_pcb->next == pcb) {
				curr_pcb->next = pcb->next;
				break;
			}
		}
	}

	memp_free(MEMP_NETPACKET_PCB, pcb);
}


err_t netpacket_bind_netif(struct netpacket_pcb *pcb, struct netif *netif)
{
	LWIP_ASSERT_CORE_LOCKED();

	if (netif != NULL) {
		pcb->netif = netif;
		return ERR_OK;
	}
	else {
		return ERR_VAL;
	}
}


err_t netpacket_send(struct netpacket_pcb *pcb, struct pbuf *p)
{
	return netpacket_sendto(pcb, p, NULL, 0);
}


err_t netpacket_sendto(struct netpacket_pcb *pcb, struct pbuf *p, u8_t *dst_addr, u8_t dst_addr_len)
{
	struct pbuf *packet = NULL;

	LWIP_ASSERT_CORE_LOCKED();

	switch (pcb->type) {
		case SOCK_RAW:
			LWIP_ASSERT("netpacket_sendto: dst_addr must be NULL in SOCK_RAW connection", dst_addr == NULL);

			/* data in given buffer contains full ethernet frame - do nothing */
			packet = p;
			break;
		case SOCK_DGRAM: {
			LWIP_ASSERT("netpacket_sendto: dst_addr cannot be NULL in SOCK_DGRAM connection", dst_addr != NULL);

			/* prefix data in given buffer with ethernet header */
			packet = pbuf_alloc(PBUF_RAW, sizeof(struct eth_hdr), PBUF_POOL);
			pbuf_chain(packet, p);

			struct eth_hdr *header = (struct eth_hdr *)packet->payload;
			SMEMCPY(&header->dest, dst_addr, dst_addr_len);
			SMEMCPY(&header->src, pcb->netif->hwaddr, pcb->netif->hwaddr_len);
			header->type = ntohs(pcb->protocol);
			break;
		}
	}

	netpacket_linkoutput_full(pcb->netif, packet, pcb);
	err_t ret = pcb->netif->linkoutput(pcb->netif, packet);
	if (pcb->type == SOCK_DGRAM) {
		pbuf_dechain(packet);
		pbuf_free(packet);
	}

	return ret;
}


static void netpacket_recv(struct netpacket_pcb *pcb, struct pbuf *p, struct eth_addr *src_addr)
{
	struct pbuf *q;
	struct netbuf *buf;
	struct netconn *conn = pcb->conn;

	if ((conn != NULL) && sys_mbox_valid(&conn->recvmbox)) {
#if LWIP_SO_RCVBUF
		int recv_avail;
		SYS_ARCH_GET(conn->recv_avail, recv_avail);
		if ((recv_avail + (int)(p->tot_len)) > conn->recv_bufsize) {
			return;
		}
#endif /* LWIP_SO_RCVBUF */
		/* copy the whole packet into new pbufs */
		q = pbuf_clone(PBUF_RAW, PBUF_RAM, p);
		if (q != NULL) {
			u16_t len;
			buf = (struct netbuf *)memp_malloc(MEMP_NETBUF);
			if (buf == NULL) {
				pbuf_free(q);
				return;
			}

			/* copy packet type flags */
			q->flags = p->flags & (PBUF_FLAG_MCASTLOOP | PBUF_FLAG_LLMCAST | PBUF_FLAG_HOST | PBUF_FLAG_OTHERHOST);

			buf->p = q;
			buf->ptr = q;
			SMEMCPY(buf->netpacket_hwaddr, src_addr, sizeof(struct eth_addr));
			buf->netpacket_hwaddr_len = sizeof(struct eth_addr);
			buf->port = pcb->protocol;

			len = q->tot_len;
			if (sys_mbox_trypost(&conn->recvmbox, buf) != ERR_OK) {
				netbuf_delete(buf);
				return;
			}

#if LWIP_SO_RCVBUF
			SYS_ARCH_INC(conn->recv_avail, len);
#endif
			/* Register event with callback */
			API_EVENT(conn, NETCONN_EVT_RCVPLUS, len);
		}
	}
}


int netpacket_input(struct pbuf *p, struct netif *netif)
{
	if (p->len < sizeof(struct eth_hdr))
		return 1;

	struct eth_hdr *ethhdr = (struct eth_hdr *)p->payload;
	u16_t type = htons(ethhdr->type);

	/* find netpacket pcb's that are binded to this netif */
	struct netpacket_pcb *pcb = NULL;
	for (pcb = netpacket_pcbs; pcb != NULL && pcb->netif != NULL; pcb = pcb->next) {
		if (netif_get_index(pcb->netif) != netif_get_index(netif))
			continue;

		if ((pcb->protocol != ETH_P_ALL) && (pcb->protocol != type))
			continue;

		struct eth_addr src_addr;
		SMEMCPY(&src_addr, &ethhdr->src.addr, sizeof(struct eth_addr));

		if (pcb->type == SOCK_DGRAM) {
			/* remove ethernet header */
			pbuf_remove_header(p, sizeof(struct eth_hdr));
		}
		else {
#if ETH_PAD_SIZE
			/* remove ethernet header padding */
			pbuf_remove_header(p, ETH_PAD_SIZE);
#endif
		}

		netpacket_recv(pcb, p, &src_addr);

		if (pcb->type == SOCK_DGRAM) {
			/* restore ethernet header */
			pbuf_add_header_force(p, sizeof(struct eth_hdr));
		}
		else {
#if ETH_PAD_SIZE
			/* restore ethernet header padding */
			pbuf_add_header_force(p, ETH_PAD_SIZE);
#endif
		}
	}

	/* never filter out by packet type */
	return 1;
}


void netpacket_linkoutput(struct netif *netif, struct pbuf *p)
{
	netpacket_linkoutput_full(netif, p, NULL);
}


static void netpacket_linkoutput_full(struct netif *netif, struct pbuf *p, struct netpacket_pcb *from_pcb)
{
	if (p->len < sizeof(struct eth_hdr))
		return;

	struct eth_hdr *ethhdr = (struct eth_hdr *)p->payload;
	u16_t type = htons(ethhdr->type);

	/* find netpacket pcb's that are binded to this netif */
	struct netpacket_pcb *pcb = NULL;
	for (pcb = netpacket_pcbs; pcb != NULL && pcb->netif != NULL; pcb = pcb->next) {
		if (pcb == from_pcb)
			continue;

		if (netif_get_index(pcb->netif) != netif_get_index(netif))
			continue;

		if ((pcb->protocol != ETH_P_ALL) && (pcb->protocol != type))
			continue;

		struct eth_addr src_addr;
		SMEMCPY(&src_addr, netif->hwaddr, sizeof(struct eth_addr));

		if (pcb->type == SOCK_DGRAM) {
			/* remove ethernet header */
			pbuf_remove_header(p, sizeof(struct eth_hdr));
		}
		else {
#if ETH_PAD_SIZE
			/* remove ethernet header padding */
			pbuf_remove_header(p, ETH_PAD_SIZE);
#endif
		}

		netpacket_recv(pcb, p, &src_addr);

		if (pcb->type == SOCK_DGRAM) {
			/* restore ethernet header */
			pbuf_add_header_force(p, sizeof(struct eth_hdr));
		}
		else {
#if ETH_PAD_SIZE
			/* restore ethernet header padding */
			pbuf_add_header_force(p, ETH_PAD_SIZE);
#endif
		}
	}
}

#endif /* LWIP_NETPACKET */
