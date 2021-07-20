/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP advanced routing
 *
 * Copyright 2019 Phoenix Systems
 * Author: Kamil Amanowicz, Jan Sikorski
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <sys/threads.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <syslog.h>
#include "lwip/netif.h"
#include "route.h"


struct rt_table rt_table;


static int route_after(rt_entry_t *e1, rt_entry_t *e2)
{
	int score1, score2;

	/* Put lower metric first */
	if (e1->metric != e2->metric)
		return e1->metric > e2->metric;

	/* Put more specific first */
	score1 = __builtin_popcount(e1->genmask.addr);
	score2 = __builtin_popcount(e2->genmask.addr);

	return score1 < score2;
}


static int route_table_add(rt_entry_t *entry)
{
	rt_entry_t *e;

	if ((e = rt_table.entries) == NULL) {
		rt_table.entries = entry;
	}
	else {
		do {
			if (route_after(e, entry))
				break;
		}
		while ((e = e->next) != rt_table.entries);
	}

	if (e == rt_table.entries) {
		LIST_ADD(&rt_table.entries, entry);

		if (route_after(rt_table.entries, entry))
			rt_table.entries = entry;
	}
	else {
		LIST_ADD(&e, entry);
	}

	return 0;
}


static int route_same(rt_entry_t *e1, rt_entry_t *e2)
{
	return e1->dst.addr == e2->dst.addr && ((e1->gw.addr == 0) || (e1->gw.addr == e2->gw.addr)) &&
		e1->genmask.addr == e2->genmask.addr && e1->netif == e2->netif;
}


static int route_table_del(rt_entry_t *entry)
{
	rt_entry_t *e;

	if ((e = rt_table.entries) == NULL)
		return -ENOENT;

	do {
		if (route_same(entry, e)) {
			LIST_REMOVE(&rt_table.entries, e);
			free(e);
			return EOK;
		}
	}
	while ((e = e->next) != rt_table.entries);
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


static int _route_add(struct netif *netif, struct rtentry *rt)
{
	rt_entry_t *entry;

#if 0
	ip4_addr_t ipaddr;
	struct sockaddr_in *sin = (struct sockaddr_in *)&rt->rt_dst;

	if (sin->sin_addr.s_addr == 0) {
		if (rt->rt_flags & RTF_GATEWAY) {
			sin = (struct sockaddr_in *)&rt->rt_gateway;
			ipaddr.addr = sin->sin_addr.s_addr;
			netif_set_gw(netif, &ipaddr);
		}
		netif_set_default(netif);
		return 0;
	}
#endif

	entry = malloc(sizeof(rt_entry_t));

	if (entry == NULL)
		return -ENOMEM;

	route_fill_entry(rt, entry, netif);
	return route_table_add(entry);
}


static int _route_del(struct netif *netif, struct rtentry *rt)
{
	rt_entry_t entry;

#if 0
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
#endif

	if (rt_table.entries == NULL)
		return -ENOENT;

	route_fill_entry(rt, &entry, netif);

	return route_table_del(&entry);
}


static struct netif *_route_find(const ip4_addr_t *dest)
{
	rt_entry_t *e;

	if ((e = rt_table.entries) == NULL)
		return NULL;

	do {
		if (e->dst.addr == (dest->addr & e->genmask.addr) && netif_is_up(e->netif) && netif_is_link_up(e->netif))
			return e->netif;
	}
	while ((e = e->next) != rt_table.entries);

	return NULL;
}


static ip4_addr_t *_route_get_gw(struct netif *netif, const ip4_addr_t *dest)
{
	rt_entry_t *e;

	if ((e = rt_table.entries) == NULL)
		return NULL;

	do {
		if (e->dst.addr == (dest->addr & e->genmask.addr) && netif == e->netif)
			return e->flags & RTF_GATEWAY ? &e->gw : NULL;
	}
	while ((e = e->next) != rt_table.entries);

	return NULL;
}

 
void route_init(void)
{
	mutexCreate(&rt_table.lock);
}


int route_add(struct netif *netif, struct rtentry *rt)
{
	int res;
	mutexLock(rt_table.lock);
	res = _route_add(netif, rt);
	mutexUnlock(rt_table.lock);
	return res; 
}


 
int route_del(struct netif *netif, struct rtentry *rt)
{
	int res;
	mutexLock(rt_table.lock);
	res = _route_del(netif, rt);
	mutexUnlock(rt_table.lock);
	return res; 
}


 
struct netif *route_find(const ip4_addr_t *dest)
{
	struct netif *res;
	mutexLock(rt_table.lock);
	res = _route_find(dest);
	mutexUnlock(rt_table.lock);
	return res; 
}


 
ip4_addr_t *route_get_gw(struct netif *netif, const ip4_addr_t *dest)
{
	ip4_addr_t *res;
	mutexLock(rt_table.lock);
	res = _route_get_gw(netif, dest);
	mutexUnlock(rt_table.lock);
	return res; 
}
