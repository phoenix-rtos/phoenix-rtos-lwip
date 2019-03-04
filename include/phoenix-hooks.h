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

#include<lwip/sockets.h>
#include "route.h"

#define LWIP_HOOK_ETHARP_GET_GW(netif, dest) route_get_gw(netif, dest)
#define LWIP_HOOK_IP4_ROUTE(dest) route_find(dest)

#endif /* PHOENIX_HOOKS_H_ */
