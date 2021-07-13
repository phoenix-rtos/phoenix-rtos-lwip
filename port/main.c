/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer - TCP/IP thread wrapper
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "arch/cc.h"
#include "lwip/tcpip.h"
#include "filter.h"
#include "netif-driver.h"

#include <lwipopts.h>

#include <sys/msg.h>
#include <posix/utils.h>

#include <lwip/sockets.h>
#include <lwip/inet.h>
#include <lwip/dns.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "netif.h"
#include "route.h"
#include "filter.h"


#define SNPRINTF_APPEND(fmt, ...) do { \
		write = snprintf(buffer, size, fmt, ##__VA_ARGS__); \
		if (offset > write) { \
			offset -= write; \
			write = 0; \
		} else if (write > size) { \
			return -ERANGE; \
		} else if (offset) { \
			write -= offset; \
			memmove(buffer, buffer + offset, write); \
			offset = 0; \
		} \
		size -= write; \
		buffer += write; \
	} while (0)


#ifdef LWIP_LINKMONITOR_DEV
static struct {
	int disconnected;
	int reconnected;
	int last_link;
} main_common;
#endif


static int writeRoutes(char *buffer, size_t bufSize, size_t offset)
{
	rt_entry_t *entry;
	struct netif *netif;
	size_t write, size = bufSize;


	SNPRINTF_APPEND("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n");

	/* FIXME: route table locking */
	if ((entry = rt_table.entries) != NULL) {
		do {
			SNPRINTF_APPEND("%2s%u\t%08X\t%08X\t%04X\t%d\t%u\t%d\t%08X\t%d\t%u\t%u\n",
				entry->netif->name, entry->netif->num,
				ip4_addr_get_u32(&entry->dst),                                                          /* Destination */
				ip4_addr_get_u32(entry->flags & RTF_GATEWAY ? &entry->gw : netif_ip4_gw(entry->netif)), /* Gateway */
				entry->flags, 0, 0,                                                                     /* Flags, RefCnt, Use */
				entry->metric,
				ip4_addr_get_u32(&entry->genmask),
				entry->netif->mtu,
				0, 0); /* Window, IRTT */
		}
		while ((entry = entry->next) != rt_table.entries);
	}

	/* add per-netif routing (LwIP uses it regardless of our routing table) - with highest priority (apart for our custom GW) */
	for (netif = netif_list; netif != NULL; netif = netif->next) {
		uint32_t prefix = ((netif->ip_addr.addr) & (netif->netmask.addr));
		unsigned int flags = netif_is_up(netif) ? RTF_UP : 0;
		if (netif->gw.addr != 0)
			flags |= RTF_GATEWAY;

		SNPRINTF_APPEND("%2s%u\t%08X\t%08X\t%04X\t%d\t%u\t%d\t%08X\t%d\t%u\t%u\n",
			netif->name, netif->num,
			prefix,                                /* Destination */
			ip4_addr_get_u32(netif_ip4_gw(netif)), /* Gateway */
			flags, 0, 0,                           /* Flags, RefCnt, Use */
			0,                                     /* Metric */
			ip4_addr_get_u32(netif_ip4_netmask(netif)),
			netif->mtu,
			0, 0); /* Window, IRTT */
	}

	return bufSize - size;
}


static int writeStatus(char *buffer, size_t bufSize, size_t offset)
{
	struct netif *netif;
	size_t write, size = bufSize;
	netif_driver_t *drv;
	unsigned int i;

	for (netif = netif_list; netif != NULL; netif = netif->next) {
		SNPRINTF_APPEND("%2s%d_up=%u\n", netif->name, netif->num, netif_is_up(netif));
		SNPRINTF_APPEND("%2s%d_link=%u\n", netif->name, netif->num, netif_is_link_up(netif));
		SNPRINTF_APPEND("%2s%d_ip=%s\n", netif->name, netif->num, inet_ntoa(netif->ip_addr));
		if (!netif_is_ppp(netif) && !netif_is_tun(netif)) {
#if LWIP_DHCP
			SNPRINTF_APPEND("%2s%d_dhcp=%u\n", netif->name, netif->num, netif_is_dhcp(netif));
#endif
			SNPRINTF_APPEND("%2s%d_netmask=%s\n", netif->name, netif->num, inet_ntoa(netif->netmask));
			SNPRINTF_APPEND("%2s%d_gateway=%s\n", netif->name, netif->num, inet_ntoa(netif->gw));
#if LWIP_DHCP_GET_MOBILE_AGENT
			if (netif_is_dhcp(netif))
				SNPRINTF_APPEND("%2s%d_mobile_agent=%s\n", netif->name, netif->num, inet_ntoa(netif->mobile_agent));
#endif
		} else {
			SNPRINTF_APPEND("%2s%d_ptp=%s\n", netif->name, netif->num, inet_ntoa(netif->gw));
		}

		if (strcmp("lo", netif->name) && (drv = netif_driver(netif)) && drv->media != NULL)
			SNPRINTF_APPEND("%2s%d_media=%s\n", netif->name, netif->num, drv->media(netif));
	}

#if LWIP_DNS
	for (i = 0; i < LWIP_DHCP_MAX_DNS_SERVERS; ++i)
		SNPRINTF_APPEND("dns_%u=%s\n", i, inet_ntoa(*dns_getserver(i)));
#endif

	return bufSize - size;
}


#ifdef LWIP_LINKMONITOR_DEV
static int write_linkmonitor(char *buffer, size_t bufSize, size_t offset)
{
	struct netif *netif;
	size_t write, size = bufSize;

	netif = netif_find(LWIP_LINKMONITOR_DEV);
	if (!netif)
		return -EINVAL;

	/* initialize link status on first read */
	if (main_common.last_link == -1)
		main_common.last_link = netif_is_link_up(netif);

	SNPRINTF_APPEND("link=%u\n", main_common.last_link);
	SNPRINTF_APPEND("disconnected=%u\n", main_common.disconnected);
	SNPRINTF_APPEND("reconnected=%u\n", main_common.reconnected);

	/* clear disconnected/reconnected flags on every read */
	main_common.disconnected = 0;
	main_common.reconnected = 0;

	return bufSize - size;
}


static void linkmonitor_callback(struct netif *netif)
{
	uint8_t link = netif_is_link_up(netif);

	/* link monitoring starts on first read */
	if (main_common.last_link == -1)
		return;

	if (!link && main_common.last_link)
		main_common.disconnected = 1;

	if (link && !main_common.last_link)
		main_common.reconnected = 1;

	main_common.last_link = link;
}


static void linkmonitor(const char *dev)
{
	struct netif *netif;

	main_common.disconnected = 0;
	main_common.reconnected = 0;
	main_common.last_link = -1;

	if ((netif = netif_find(dev)))
		netif_set_link_callback(netif, linkmonitor_callback);
}
#endif /* LWIP_LINKMONITOR_DEV */


#if LWIP_EXT_PF
static int readPf(void *buffer, size_t size, size_t offset)
{
	pfrule_array_t *input = (pfrule_array_t *)buffer;

	if (buffer == NULL || !size || size != input->len * sizeof(pfrule_t) + sizeof(pfrule_array_t))
		return -EINVAL;

	return pf_rulesUpdate(input);
}
#endif


static void mainLoop(void)
{
	msg_t msg = {0};
	unsigned long int rid;
	unsigned port;
	oid_t route_oid = {0, 0};
	oid_t status_oid = {0, 1};
#if LWIP_EXT_PF
	oid_t pf_oid = {0, 2};
#endif
#ifdef LWIP_LINKMONITOR_DEV
	oid_t linkmonitor_oid = { 0, 3 };
#endif

	if (portCreate(&port) < 0) {
		printf("phoenix-rtos-lwip: can't create port\n");
		return;
	}

	route_oid.port = port;
	status_oid.port = port;
#if LWIP_EXT_PF
	pf_oid.port = port;
#endif
#ifdef LWIP_LINKMONITOR_DEV
	linkmonitor_oid.port = port;
#endif

	if (create_dev(&route_oid, "/dev/route") < 0) {
		printf("phoenix-rtos-lwip: can't create /dev/route\n");
		return;
	}

	if (create_dev(&status_oid, "/dev/ifstatus") < 0) {
		printf("phoenix-rtos-lwip: can't create /dev/ifstatus\n");
		return;
	}

#if LWIP_EXT_PF
	if (create_dev(&pf_oid, "/dev/pf") < 0) {
		printf("phoenix-rtos-lwip: can't create /dev/pf\n");
		return;
	}
#endif

#ifdef LWIP_LINKMONITOR_DEV
	if (create_dev(&linkmonitor_oid, "/dev/linkmonitor") < 0) {
		printf("phoenix-rtos-lwip: can't create /dev/linkmonitor\n");
		return;
	}
#endif

	for (;;) {
		if (msgRecv(port, &msg, &rid) < 0)
			continue;

		switch (msg.type) {
		case mtRead:
				if (msg.i.io.oid.id == route_oid.id) {
					mutexLock(rt_table.lock);
					msg.o.io.err = writeRoutes(msg.o.data, msg.o.size, msg.i.io.offs);
					mutexUnlock(rt_table.lock);
				}
				else if (msg.i.io.oid.id == status_oid.id)
					msg.o.io.err = writeStatus(msg.o.data, msg.o.size, msg.i.io.offs);
#ifdef LWIP_LINKMONITOR_DEV
				else if (msg.i.io.oid.id == linkmonitor_oid.id)
					msg.o.io.err = write_linkmonitor(msg.o.data, msg.o.size, msg.i.io.offs);
#endif
				else
					msg.o.io.err = -EINVAL;
			break;

		case mtWrite:
#if LWIP_EXT_PF
				if (msg.i.io.oid.id == pf_oid.id) {
					msg.o.io.err = readPf(msg.i.data, msg.i.size, msg.i.io.offs);
				}
				else
#endif
				{
					msg.o.io.err = -EINVAL;
				}
			break;

		default:
			break;
		}

		msgRespond(port, &msg, rid);
	}
}


int main(int argc, char **argv)
{
	size_t have_intfs = 0;

#ifndef HAVE_WORKING_INIT_ARRAY
	void init_lwip_tcpip(void);
	void init_lwip_sockets(void);
	void register_driver_rtl(void);
	void register_driver_enet(void);
	void register_driver_pppos(void);
	void register_driver_pppou(void);
	void register_driver_tun(void);
	void register_driver_tap(void);

	init_lwip_tcpip();
	init_lwip_sockets();
#ifdef HAVE_DRIVER_rtl
	register_driver_rtl();
#endif
#ifdef HAVE_DRIVER_enet
	register_driver_enet();
#endif
#ifdef HAVE_DRIVER_pppos
	register_driver_pppos();
#endif
#ifdef HAVE_DRIVER_pppou
	register_driver_pppou();
#endif
#ifdef HAVE_DRIVER_tuntap
	register_driver_tun();
	register_driver_tap();
#endif
#endif

	mutexCreate(&rt_table.lock);

#if LWIP_EXT_PF
	init_filters();
#endif

	while (++argv, --argc) {
		int err = create_netif(*argv);

		if (!err)
			++have_intfs;
		else
			printf("phoenix-rtos-lwip: can't init netif from cfg \"%s\": %s\n", *argv, strerror(err));
	}

	/* printf("netsrv: %zu interface%s\n", have_intfs, have_intfs == 1 ? "" : "s"); */
	if (!have_intfs)
		exit(1);

#ifdef LWIP_LINKMONITOR_DEV
	linkmonitor(LWIP_LINKMONITOR_DEV);
#endif

	mainLoop();

	return 1;
}
