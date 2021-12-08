/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP advanced routing
 *
 * Copyright 2019 Phoenix Systems
 * Author: Kamil Amanowicz
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _LWIP_PHOENIX_ROUTE_H_
#define _LWIP_PHOENIX_ROUTE_H_

#include <lwip/ip4_addr.h>
#include <lwip/netif.h>
#include <net/route.h>
#include <sys/list.h>
#include <sys/types.h>


typedef struct _rt_entry {
	struct _rt_entry *next;
	struct _rt_entry *prev;

	ip4_addr_t dst;
	ip4_addr_t gw;
	ip4_addr_t genmask;
	short flags;
	short metric;
	struct netif *netif;
} rt_entry_t;


struct rt_table {
	rt_entry_t *entries;
	handle_t lock;
};


extern struct rt_table rt_table;


void route_init(void);


int route_add(struct netif *netif, struct rtentry *rt);


int route_del(struct netif *netif, struct rtentry *rt);


ip4_addr_t *route_get_gw(struct netif *netif, const ip4_addr_t *dest);


struct netif *route_find(const ip4_addr_t *dest);


#endif
