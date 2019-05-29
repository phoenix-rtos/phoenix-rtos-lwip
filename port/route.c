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

#include <string.h>
#include <netinet/in.h>
#include "route.h"


struct rt_table rt_table = { 0 };


static int route_table_add(rt_entry_t *entry)
{
	rt_entry_t **table;

	if (rt_table.used >= rt_table.size) {
		table = realloc(rt_table.entries, sizeof(rt_entry_t *) * (rt_table.size + 5));
		if (table == NULL)
			return -ENOMEM;

		memset(table + rt_table.used, 0, 5 * sizeof(rt_entry_t *));
		rt_table.entries = table;
		rt_table.size += 5;
	}

	rt_table.entries[rt_table.used++] = entry;

	return 0;
}


static int route_table_del(rt_entry_t *entry)
{
	int i;
	rt_entry_t *victim;
	rt_entry_t **table;

	for (i = 0; i < rt_table.used; i++) {
		if (!memcmp(entry, rt_table.entries[i], sizeof(rt_entry_t))) {
			victim = rt_table.entries[i];
			rt_table.entries[i] = NULL;
			rt_table.entries[i] = rt_table.entries[--rt_table.used];
			free(victim);

			if (!(rt_table.used % 5)) {
				table = realloc(rt_table.entries, sizeof(rt_entry_t *) * (rt_table.used));
				rt_table.entries = table;
				rt_table.size = rt_table.used;
			}
			return 0;
		}
	}

	return -ENOENT;
}


static void route_fill_entry(struct rtentry *rt, rt_entry_t *entry, struct netif *netif)
{
	memset(entry, 0, sizeof(rt_entry_t));
	entry->dst.addr = ((struct sockaddr_in *)&rt->rt_dst)->sin_addr.s_addr;

	if (rt->rt_flags & RTF_GATEWAY)
		entry->gw.addr = ((struct sockaddr_in *)&rt->rt_gateway)->sin_addr.s_addr;
	else
		entry->gw.addr = 0;

	if (rt->rt_flags & RTF_HOST)
		entry->genmask.addr = 0xffffffff;
	else
		entry->genmask.addr = ((struct sockaddr_in *)&rt->rt_genmask)->sin_addr.s_addr;

	entry->metric = rt->rt_metric;
	entry->flags = rt->rt_flags;
	entry->netif = netif;

}


int route_add(struct netif *netif, struct rtentry *rt)
{
	ip4_addr_t ipaddr;
	struct sockaddr_in *sin = (struct sockaddr_in *)&rt->rt_dst;
	rt_entry_t *entry;

	if (sin->sin_addr.s_addr == 0) {
		if (rt->rt_flags & RTF_GATEWAY) {
			sin = (struct sockaddr_in *)&rt->rt_gateway;
			ipaddr.addr = sin->sin_addr.s_addr;
			netif_set_gw(netif, &ipaddr);
		}
		netif_set_default(netif);
		return 0;
	}

	entry = malloc(sizeof(rt_entry_t));

	if (entry == NULL)
		return -ENOMEM;

	route_fill_entry(rt, entry, netif);

	return route_table_add(entry);
}


int route_del(struct netif *netif, struct rtentry *rt)
{
	rt_entry_t entry;
	ip4_addr_t ipaddr;
	struct sockaddr_in *sin = (struct sockaddr_in *)&rt->rt_dst;

	if (sin->sin_addr.s_addr == 0) {
		if (rt->rt_flags & RTF_GATEWAY) {
			sin = (struct sockaddr_in *)&rt->rt_gateway;
			ipaddr.addr = sin->sin_addr.s_addr;
			netif_set_gw(netif, &ipaddr);
		}
		netif_set_default(NULL);
		return 0;
	}

	if (rt_table.entries == NULL)
		return -ENOENT;

	route_fill_entry(rt, &entry, netif);

	return route_table_del(&entry);
}


struct netif *route_find(const ip4_addr_t *dest)
{
	int i;

	if (rt_table.entries == NULL)
		return NULL;

	for (i = 0; i < rt_table.used; i++) {
		if (rt_table.entries[i]->dst.addr == (dest->addr & rt_table.entries[i]->genmask.addr))
			return rt_table.entries[i]->netif;
	}

	return NULL;
}


ip4_addr_t *route_get_gw(struct netif *netif, const ip4_addr_t *dest)
{
	int i;
	if (rt_table.entries == NULL)
		return NULL;

	for (i = 0; i < rt_table.used; i++) {
		if (rt_table.entries[i]->dst.addr == (dest->addr & rt_table.entries[i]->genmask.addr)
				&& netif == rt_table.entries[i]->netif)
			return &rt_table.entries[i]->gw;
	}

	return NULL;
}
