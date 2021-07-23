/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP packet sockets
 *
 * Copyright 2018 Phoenix Systems
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PHOENIX_NETPACKET_H_
#define PHOENIX_NETPACKET_H_

#include "lwip/opt.h"

#if LWIP_NETPACKET

#include "lwip/netifapi.h"

#include <netpacket/packet.h>

struct netpacket_pcb {
	struct netpacket_pcb *next;
	struct netconn *conn;
	struct netif *netif;
	u8_t type;
	u16_t protocol;
};

struct netpacket_pcb *netpacket_new(struct netconn *conn, u16_t proto);
void netpacket_remove(struct netpacket_pcb *pcb);
err_t netpacket_bind_netif(struct netpacket_pcb *pcb, struct netif *netif);
err_t netpacket_send(struct netpacket_pcb *pcb, struct pbuf *p);
err_t netpacket_sendto(struct netpacket_pcb *pcb, struct pbuf *p, u8_t *dst_addr, u8_t dst_addr_len);
int netpacket_input(struct pbuf *p, struct netif *netif);
void netpacket_linkoutput(struct netif *netif, struct pbuf *p);

#endif /* LWIP_NETPACKET */

#endif /* PHOENIX_NETPACKET_H_ */
