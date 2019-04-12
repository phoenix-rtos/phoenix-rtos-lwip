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
#include "lwipopts.h"
#include "route.h"
#include "filter.h"

#define LWIP_HOOK_ETHARP_GET_GW(netif, dest) route_get_gw(netif, dest)
#define LWIP_HOOK_IP4_ROUTE(dest) route_find(dest)

#ifdef HAVE_IP_FILTER
#define LWIP_HOOK_IP4_INPUT(pbuf, input_netif) ip_filter(pbuf, input_netif)
#endif

#ifdef HAVE_MAC_FILTER
#define LWIP_HOOK_ETH_INPUT(pbuf, input_netif) mac_filter(pbuf, input_netif)
#endif

#endif /* PHOENIX_HOOKS_H_ */
