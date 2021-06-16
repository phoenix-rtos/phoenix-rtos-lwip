/*
 * embedded IPsec
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 */

/** @file ipsecdev.c
 *  @brief IPsec network adapter for lwIP
 *
 *  @author Christian Scheurer <http://www.christianscheurer.ch> <BR>
 * 
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */

#include <ipv4/lwip/inet.h>
#include <ipv4/lwip/ip4.h>
#include <lwip/udp.h>
#include <lwip/tcp_impl.h>
#include "lwip/mem.h"
#include "debug.h"
#include "sa.h"
#include "sadb.h"
#include "ipsec.h"
#include "util.h"
#include "ipsecdev.h"

#define IPSEC_FLAGS_ENABLED		1

struct ipsec_priv
{
	u32	sentbytes;
	u32	flags;
	struct netif	*hw_netif;
	netif_output_fn	hw_output;
	netif_input_fn	hw_input;
	netif_linkoutput_fn	hw_linkoutput;
	netif_input_fn	hw_ip_input;
	db_set_netif	db_sets;
	mutex_t		mutex;
};


static void update_ip_csum(u16 *csum, u32 dcsum_folded)
{
	/* RFC 1624 incremental csum update */
	u32 tmp = (u16)~*csum + dcsum_folded;
	tmp = (tmp >> 16) + (tmp & 0xFFFF);
	tmp = (tmp >> 16) + (tmp & 0xFFFF);
	*csum = ~tmp;
}

static void ipsecdev_apply_static_nat(struct ip_hdr *ip, u32 addr, int src)
{
	u32 dcsum = ~(src ? ip->src.addr : ip->dest.addr) + addr;
	if (dcsum < addr)
		++dcsum;	// sum overflowed -> add 1 for U1
	dcsum = (dcsum >> 16) + (dcsum & 0xFFFF);

	if (src)
		ip->src.addr = addr;
	else
		ip->dest.addr = addr;

	update_ip_csum(&ip->_chksum, dcsum);

	if (ip->_proto == IP_PROTO_UDP) {
		struct udp_hdr *udph = (void *)((char *)ip + IPH_HL(ip) * 4);
		update_ip_csum(&udph->chksum, dcsum);
	} else if (ip->_proto == IP_PROTO_TCP) {
		struct tcp_hdr *tcph = (void *)((char *)ip + IPH_HL(ip) * 4);
		update_ip_csum(&tcph->chksum, dcsum);
	}
}


/**
 * This function is used to process incoming IP packets.
 *
 * This function is called by the physical network driver when a new packet has been
 * received. To decide how to handle the packet, the Security Policy Database 
 * is called. ESP and AH packets are directly forwarded to ipsec_input() while other 
 * packets must pass the SPD lookup.
 *
 * @param p      pbuf containing the received packet
 * @param inp    lwIP network interface data structure for this device. The structure must be
 *               initialized with IP, netmask and gateway address.
 * @return err_t return code
 */
static err_t ipsecdev_ip_input(struct pbuf *p, struct netif *netif)
{
	int retcode;
	int payload_offset	= 0;
	int payload_size	= 0;
	unsigned proto;
	struct ipsec_priv *state;
	spd_entry_t *spd;
	struct ip_hdr *iph = (void *)p->payload;

	assert(netif->ipsecdev != NULL);
	assert(netif->ipsecdev != netif);
	assert(netif->ipsecdev->ipsecdev == netif->ipsecdev);

	state = (struct ipsec_priv *)netif->ipsecdev->state;

	if ((state->flags & IPSEC_FLAGS_ENABLED) == 0)
		return state->hw_ip_input(p, netif);

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, "ipsecdev_ip_input", "p=%p, netif=%p, state=%p", p, netif, state);

	if(p == NULL || p->payload == NULL)
 	{
		IPSEC_LOG_DBG("ipsecdev_input", IPSEC_STATUS_DATA_SIZE_ERROR, "Packet has no payload. Can't pass it to higher level protocol stacks.");
		pbuf_free(p);
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_input", "return = %d (no payload)", ERR_OK );
		return EOK;
	}
	if(p->next != NULL)
	{
		IPSEC_LOG_DBG("ipsecdev_input", IPSEC_STATUS_DATA_SIZE_ERROR, "can not handle chained pbuf - (packet must be < %d bytes )", PBUF_POOL_BUFSIZE - PBUF_LINK_HLEN - IPSEC_HLEN) ;
		/* in case of error, free pbuf and return ERR_OK as lwIP does */
		pbuf_free(p) ;
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_input", "return = %d (chained)", ERR_OK );
		return ERR_OK;
	}

	proto = iph->_proto;
	if(proto == IP_PROTO_ESP || proto == IP_PROTO_AH || proto == IP_PROTO_UDP) {
		/* we got an IPsec packet which must be handled by the IPsec engine */
		retcode = ipsec_input(p->payload, p->len, &payload_offset, &payload_size, &state->db_sets);

		if (proto != IP_PROTO_UDP || retcode != IPSEC_STATUS_NO_SA_FOUND)
			IPSEC_LOG_DBG("ipsecdev_input", retcode, "outer-IP src %08lx dest %08lx proto %u len %u",
				lwip_ntohl(iph->src.addr), lwip_ntohl(iph->dest.addr), iph->_proto, p->len );

		if(retcode == IPSEC_STATUS_SUCCESS) {
			/* remove ESP headers */
			pbuf_header(p, -payload_offset);
			p->len = payload_size;
			p->tot_len = payload_size;

			iph = p->payload;
			IPSEC_LOG_DBG("ipsecdev_input", IPSEC_STATUS_SUCCESS, "inner-IP src %08lx dest %08lx proto %u len %u",
				lwip_ntohl(iph->src.addr), lwip_ntohl(iph->dest.addr), iph->_proto, p->len );

			/* check what the policy says about IPsec traffic */
			spd = ipsec_spd_lookup(p->payload, &state->db_sets.inbound_spd, IPSEC_MATCH_BOTH);

			if (!spd || spd->policy != IPSEC_POLICY_IPSEC) {
				retcode = IPSEC_STATUS_FAILURE;
				IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_input", "return = (%d) (no policy; %d+%d)",
					 retcode, payload_offset, payload_size );
				pbuf_free(p);
				return retcode;
			}

			/* change in-tunnel dst-IP if needed (Virtual IP) */
			if (!ip_addr_isany(&(netif->ipsecdev->ip_addr))
					&& ip_addr_cmp(&iph->dest, &netif->ipsecdev->ip_addr)
					&& !ip_addr_isany(&netif->ip_addr)) {
				IPSEC_LOG_DBG("ipsecdev_input", IPSEC_STATUS_SUCCESS, "%s: DNAT after IPsec: %08lx to %08lx",
					netif->name, lwip_ntohl(iph->dest.addr), lwip_ntohl(netif->ip_addr.addr));
				ipsecdev_apply_static_nat(iph, netif->ip_addr.addr, 0);
			}

			retcode = state->hw_ip_input(p, netif);
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_ip_input", "return = (%d) (unpacked; %d+%d)", retcode, payload_offset, payload_size );
			return retcode;
		}

		if (proto != IP_PROTO_UDP || retcode != IPSEC_STATUS_NO_SA_FOUND) {
			IPSEC_LOG_ERR("ipsecdev_input", retcode, "error on ipsec_input() processing (retcode = %d)", retcode);
			pbuf_free(p) ;
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_ip_input", "return = %d (dropped on error)", retcode );
			return retcode;
		}
	}

	/* check what the policy says about non-IPsec traffic */
	spd = ipsec_spd_lookup(p->payload, &state->db_sets.inbound_spd, IPSEC_MATCH_BOTH);

	IPSEC_LOG_DBG("ipsecdev_input", spd && spd->policy == IPSEC_POLICY_BYPASS ? IPSEC_STATUS_SUCCESS : IPSEC_STATUS_FAILURE,
		"IP src %08lx dest %08lx proto %u len %u",
		lwip_ntohl(iph->src.addr), lwip_ntohl(iph->dest.addr), iph->_proto, p->len );

	if(spd == NULL) {
		pbuf_free(p);
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_input", "return = %d (no policy)", ERR_CONN );
		return ERR_CONN;
	}

	retcode = ERR_CONN;
	switch(spd->policy)	{
		case IPSEC_POLICY_IPSEC:
			pbuf_free(p) ;
			break;
		case IPSEC_POLICY_DISCARD:
			pbuf_free(p) ;
			break;
		case IPSEC_POLICY_BYPASS:
			retcode = state->hw_ip_input(p, netif);
			break;
		default:
			pbuf_free(p) ;
			IPSEC_LOG_ERR("ipsecdev_input", IPSEC_STATUS_FAILURE, ("IPSEC_STATUS_FAILURE: dropping packet")) ;
			IPSEC_LOG_AUD("ipsecdev_input", IPSEC_AUDIT_FAILURE, ("unknown Security Policy: dropping packet")) ;
	}

	/* usually return ERR_OK as lwIP does */
	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_ip_input", "return = %d, policy %s", retcode,
		spd->policy == IPSEC_POLICY_IPSEC ? "IPSEC" : spd->policy == IPSEC_POLICY_BYPASS ? "BYPASS" : "DISCARD" );
	return retcode;
}


/**
 * This function is used to send a packet out to the network device.
 *
 * IPsec processing for outbound traffic is done here before forwarding the IP packet 
 * to the physical network device. The SPD is queried in order to know how
 * the packet must be handled.
 *
 * @param  netif   initialized lwIP network interface data structure of this device
 * @param  p       pbuf containing a complete IP packet as payload
 * @param  ipaddr  destination IP address
 * @return err_t   status
 */
static err_t ipsecdev_output(struct netif *netif, struct pbuf *p, struct ip_addr *ipaddr)
{
	struct pbuf *p_cpy = NULL;
	struct ipsec_priv *state;
	int payload_size ;
	int payload_offset ;
	spd_entry_t *spd;
	sad_entry_t *sa;
	ipsec_status status;
	struct ip_hdr *ip;
	struct ip_addr dest_addr;
	ip_addr_p_t dst;
	int retcode = ERR_CONN;

	assert(netif->ipsecdev != NULL);

	if (netif->ipsecdev == netif) {
		// somebody tried to route packet directly via ipsec device, abort!
		IPSEC_LOG_ERR("ipsecdev_output", IPSEC_STATUS_FAILURE, ("tried to output packet directly via IPSEC virtual device")) ;
		return ERR_RTE;
	}

	assert(netif->ipsecdev->ipsecdev == netif->ipsecdev);

	state = (struct ipsec_priv *)netif->ipsecdev->state;

	if ((state->flags & IPSEC_FLAGS_ENABLED) == 0)
		return state->hw_output(state->hw_netif, p, ipaddr);

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, "ipsecdev_output", "pbuf=%p, netif=%s", p, netif->name);

	if(p->next != NULL)
 	{
		pbuf_ref(p);
		p = pbuf_coalesce(p, PBUF_TRANSPORT);
		if (p->next != NULL) {
			pbuf_free(p);
			IPSEC_LOG_DBG("ipsecdev_output", IPSEC_STATUS_DATA_SIZE_ERROR, "can not handle chained pbuf - use pbuf size of %d bytes", 1600 /*XXX*/);
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_output", "return = %d", ERR_CONN );
			return ERR_CONN;
		}
	}

	if(p->ref != 1)
 	{
		assert(0);
		IPSEC_LOG_DBG("ipsecdev_output", IPSEC_STATUS_DATA_SIZE_ERROR, "can not handle pbuf->ref != 1 - p->ref == %d", p->ref);
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_output", "return = %d", ERR_CONN );
		return ERR_CONN;
	}


	/** backup of physical destination IP address (inner IP header may become encrypted) */
	memcpy(&dest_addr, ipaddr, sizeof(struct ip_addr));

	/**@todo this static access to the HW device must be replaced by a more flexible method */

	/* RFC conform IPsec processing */
	ip = (struct ip_hdr*)p->payload;
	spd = ipsec_spd_lookup(ip, &state->db_sets.outbound_spd, IPSEC_MATCH_DST);
	if(spd == NULL) {
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_output", "return = %d", ERR_CONN );
		return ERR_CONN;
	}

	IPSEC_LOG_DBG("ipsecdev_output", IPSEC_STATUS_SUCCESS, "orig-IP src %08lx dest %08lx proto %u len %u policy %s",
		lwip_ntohl(ip->src.addr), lwip_ntohl(ip->dest.addr), ip->_proto, p->len,
		spd->policy == IPSEC_POLICY_IPSEC ? "IPSEC" : spd->policy == IPSEC_POLICY_BYPASS ? "BYPASS" : "DISCARD" );

	/* change in-tunnle src-IP (Virtual IP) */
	if (spd->policy == IPSEC_POLICY_IPSEC && !ip_addr_isany(&(netif->ipsecdev->ip_addr))
			&& !ip_addr_cmp(&ip->src, &netif->ipsecdev->ip_addr)) {
		IPSEC_LOG_DBG("ipsecdev_output", IPSEC_STATUS_SUCCESS, "%s: SNAT before IPsec: %08lx as %08lx",
			netif->name, lwip_ntohl(ip->src.addr), lwip_ntohl(netif->ipsecdev->ip_addr.addr));
		ipsecdev_apply_static_nat(ip, netif->ipsecdev->ip_addr.addr, 1);
	}

	switch(spd->policy) {
		case IPSEC_POLICY_IPSEC:
			dst.addr = spd->tunnel_dest ? spd->tunnel_dest : ip->dest.addr;
			sa = ipsec_sad_lookup(dst, ip->_proto, 0, &state->db_sets.outbound_sad);
			if (sa == NULL) {
				main_printf(ATTR_DEBUG, "%s(): no SA for IP 0x%x, proto: %d\n", __func__, (unsigned)dst.addr, (unsigned)ip->_proto);
				break;
			}

			/** @todo lwIP TCP ESP outbound processing needs to add data after the original packet.
			 *        Since the lwIP TCP does leave any room after the original packet, we
			 *        copy the packet into a larger buffer. This step can be avoided if enough
			 *        room is left after the packet when TCP allocates memory.
			 */
			p_cpy = p;
			if(sa->proto == IP_PROTO_ESP || p->next != NULL)
			{
				// alloc 50 more bytes for ESP trailer and the optional ESP authentication data
				p_cpy = pbuf_alloc(PBUF_TRANSPORT, p->tot_len + 32 /* possible padding + MACV */, PBUF_RAM);

				if(p_cpy != NULL) {
					p_cpy->len = p->tot_len;
					p_cpy->tot_len = p->tot_len;
					pbuf_copy(p_cpy, p);
				}
				else {
					IPSEC_LOG_ERR("ipsecdev_output", IPSEC_AUDIT_FAILURE, "can't alloc new pbuf for lwIP ESP TCP workaround!") ;
				}
			}

			status = ipsec_output(p_cpy->payload, p_cpy->len, &payload_offset, &payload_size, state->hw_netif->ip_addr, sa);

			if(status == IPSEC_STATUS_SUCCESS)
			{
				/* adjust pbuf structure according to the real packet size */
				assert(!pbuf_header(p_cpy, -payload_offset));	// failed == packet overflowed and corrupted struct memory
				p_cpy->len = payload_size;
				p_cpy->tot_len = payload_size;

				ip = p_cpy->payload;
				IPSEC_LOG_DBG("ipsecdev_output", IPSEC_STATUS_SUCCESS, "out-IP src %08lx dest %08lx proto %u len %u",
					lwip_ntohl(ip->src.addr), lwip_ntohl(ip->dest.addr), ip->_proto, p_cpy->len );

				retcode = state->hw_output(state->hw_netif, p_cpy, &sa->addr);
				if(sa->proto == IP_PROTO_ESP) pbuf_free(p_cpy);
			}
			else {
				IPSEC_LOG_ERR("ipsec_output", status, ("error on ipsec_output() processing"));
				if(sa->proto == IP_PROTO_ESP) pbuf_free(p_cpy);
				break;
			}

			retcode = ERR_OK;
			break;
		case IPSEC_POLICY_DISCARD:
			IPSEC_LOG_AUD("ipsecdev_output", IPSEC_AUDIT_DISCARD, ("POLICY_DISCARD: dropping packet")) ;
			break;
		case IPSEC_POLICY_BYPASS:
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_output", "(bypass)");
			return state->hw_output(state->hw_netif, p, &dest_addr);
		default:
			IPSEC_LOG_ERR("ipsecdev_input", IPSEC_STATUS_FAILURE, ("POLICY_DIRCARD: dropping packet")) ;
			IPSEC_LOG_AUD("ipsecdev_input", IPSEC_AUDIT_FAILURE, ("unknown Security Policy: dropping packet")) ;
	}

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_output", "return = %d", retcode );
	return retcode;
}


/**
 * This function is used to send a packet directly out of the network device.
 *
 * The packet is directly sent as-is the network device output function.
 * It is used to serve ARP traffic.
 *
 * @param  netif  initialized lwIP network interface data structure of this device
 * @param  p      pbuf containing a complete IP packet as payload
 * @return err_t  status
 */
static err_t ipsecdev_netlink_output(struct netif *netif, struct pbuf *p)
{
	struct ipsec_priv *state = (struct ipsec_priv *)netif->ipsecdev->state;

	assert(0);
	return state->hw_linkoutput(state->hw_netif, p);
}


static int ipsecdev_init(struct netif *netif)
{
	struct ipsec_priv *state = netif->state;

	netif->flags = NETIF_FLAG_LINK_UP | NETIF_FLAG_BROADCAST;	/* device is always connected and supports broadcasts */
  	netif->hwaddr_len = state->hw_netif->hwaddr_len;
	memcpy(netif->hwaddr, state->hw_netif->hwaddr, netif->hwaddr_len);


	netif->ipsecdev = netif;
	netif->output = ipsecdev_output;
	netif->linkoutput = ipsecdev_netlink_output;
	strcpy(netif->name, "ipsec");

	state->hw_netif->ipsecdev = netif;
	state->hw_netif->ip_input = ipsecdev_ip_input;
	state->hw_netif->output = ipsecdev_output;

	netif->mtu = state->hw_netif->mtu;
	if (state->hw_netif->mtu > 1500 - 98)
		/* IPsec tunnel max overhead: IP+UDP+ESP+IV+PAD+MAC */
		state->hw_netif->mtu = 1500 - 98;

	ipsec_sadbInitCheckingTimeouts();

	return EOK;
}


db_set_netif *ipsecdev_dbsget(char *dev)
{
	struct netif *netif;

	if ((netif = netif_find(dev)) == NULL)
		return NULL;

	if (netif->ipsecdev != netif)
		return NULL;

	return &((struct ipsec_priv *)netif->state)->db_sets;
}


void ipsecdev_enable(char *dev)
{
	struct netif *netif;
	struct ipsec_priv *state;

	if ((netif = netif_find(dev)) == NULL)
		return;

	assert(netif->ipsecdev == netif);
	if (netif->ipsecdev != netif)
		return;

	state = (struct ipsec_priv *)netif->ipsecdev->state;

	proc_mutexLock(&state->mutex);
	state->flags |= IPSEC_FLAGS_ENABLED;
	proc_mutexUnlock(&state->mutex);

	ipsec_sadbStartCheckingTimeouts();
}


void ipsecdev_disable(char *dev)
{
	struct netif *netif;
	struct ipsec_priv *state;

	if ((netif = netif_find(dev)) == NULL)
		return;

	assert(netif->ipsecdev == netif);
	if (netif->ipsecdev != netif)
		return;

	state = (struct ipsec_priv *)netif->ipsecdev->state;

	proc_mutexLock(&state->mutex);
	state->flags &= ~IPSEC_FLAGS_ENABLED;
	proc_mutexUnlock(&state->mutex);

	ipsec_sadbStopCheckingTimeouts();
}


u32 ipsecdev_getIP(char *dev)
{
	struct netif *netif;
	struct ipsec_priv *state;
	u32 ip;

	if ((netif = netif_find(dev)) == NULL)
		return 0;

	assert(netif->ipsecdev == netif);
	if (netif->ipsecdev != netif)
		return 0;

	state = (struct ipsec_priv *)netif->ipsecdev->state;
	proc_mutexLock(&state->mutex);
	ip = state->hw_netif->ip_addr.addr;
	proc_mutexUnlock(&state->mutex);
	return ip;
}


int ipsecdev_attach(char *basedev)
{
	struct ipsec_priv *priv;
	struct netif *netif, *base_netif;


	if ((base_netif = netif_find(basedev)) == NULL)
		return -ENODEV;

	if ((priv = vm_kmalloc(sizeof(struct ipsec_priv))) == NULL)
		return -ENOMEM;

	if ((netif = vm_kmalloc(sizeof(struct netif))) == NULL) {
		vm_kfree(priv);
		return -ENOMEM;
	}

	ipsec_db_init(&priv->db_sets);
	priv->sentbytes = 0;
	priv->flags = 0;
	proc_mutexCreate(&priv->mutex);
	priv->hw_netif = base_netif;
	priv->hw_linkoutput = base_netif->linkoutput;
	priv->hw_input = base_netif->input;
	priv->hw_ip_input = base_netif->ip_input;
	priv->hw_output = base_netif->output;

	if (netif_add(netif, NULL, NULL, NULL, priv, ipsecdev_init, ip_input) == NULL) {
		vm_kfree(priv);
		vm_kfree(netif);
		return -EIO;
	}
	return EOK;
}
