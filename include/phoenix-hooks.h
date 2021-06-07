/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP hooks
 *
 * Copyright 2019 Phoenix Systems
 * Author: Kamil Amanowicz
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PHOENIX_HOOKS_H_
#define PHOENIX_HOOKS_H_

#include <lwip/sockets.h>
#include <lwipopts.h>
#include "route.h"
#include "filter.h"
#include "netpacket.h"

#define LWIP_HOOK_ETHARP_GET_GW(netif, dest) route_get_gw(netif, dest)
#define LWIP_HOOK_IP4_ROUTE(dest) route_find(dest)

#if LWIP_EXT_PF
#define LWIP_HOOK_ETH_INPUT(pbuf, input_netif) pf_filterIn(pbuf, input_netif)
#endif

#if LWIP_NETPACKET
#define LWIP_HOOK_NETPACKET_NEW(conn, proto)                       netpacket_new(conn, proto)
#define LWIP_HOOK_NETPACKET_REMOVE(pcb)                            netpacket_remove(pcb)
#define LWIP_HOOK_NETPACKET_BIND_IF(pcb, netif)                    netpacket_bind_netif(pcb, netif)
#define LWIP_HOOK_NETPACKET_SEND(pcb, p)                           netpacket_send(pcb, p)
#define LWIP_HOOK_NETPACKET_SENDTO(pcb, p, dst_addr, dst_addr_len) netpacket_sendto(pcb, p, dst_addr, dst_addr_len)
#define LWIP_HOOK_NETPACKET_INPUT(p, netif)                        netpacket_input(p, netif)
#define LWIP_HOOK_NETPACKET_LINKOUTPUT(netif, p)                   netpacket_linkoutput(netif, p)
#endif

#endif /* PHOENIX_HOOKS_H_ */
