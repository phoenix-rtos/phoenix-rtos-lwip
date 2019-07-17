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
#include "netif-driver.h"

#include <sys/msg.h>
#include <posix/utils.h>

#include<lwip/sockets.h>
#include<lwip/inet.h>

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


static int writeRoutes(char *buffer, size_t bufSize, size_t offset)
{
	rt_entry_t *entry;
	size_t write, size = bufSize, retval;

	const char *format = "    %2s%d    %08x    %08x    %08x    %8x    %8d    %8d\n";

	SNPRINTF_APPEND("%7s%12s%12s%12s%12s%12s%12s\n", "Iface", "Dest", "Mask", "Gateway", "Flags", "MTU", "Metric");

	if ((entry = rt_table.entries) != NULL) {
		do {
			SNPRINTF_APPEND(format, entry->netif->name, entry->netif->num, ntohl(ip_addr_get_ip4_u32(&entry->dst)),
					ntohl(ip_addr_get_ip4_u32(&entry->genmask)), ntohl(ip_addr_get_ip4_u32(entry->flags & RTF_GATEWAY ? &entry->gw : &entry->netif->gw)),
					entry->flags, entry->netif->mtu, entry->metric);
		}
		while ((entry = entry->next) != rt_table.entries);
	}

	if (netif_default != NULL) {
		SNPRINTF_APPEND(format, netif_default->name, netif_default->num, 0, 0,
			ntohl(ip_addr_get_ip4_u32(&netif_default->gw)), netif_default->flags, netif_default->mtu, -1);
	}

	retval = bufSize - size;
	return retval;
}


static int writeStatus(char *buffer, size_t bufSize, size_t offset)
{
	struct netif *netif;
	size_t write, size = bufSize;
	netif_driver_t *drv;

	for (netif = netif_list; netif != NULL; netif = netif->next) {

		SNPRINTF_APPEND("%2s%d_up=%u\n", netif->name, netif->num, netif_is_up(netif));
		SNPRINTF_APPEND("%2s%d_link=%u\n", netif->name, netif->num, netif_is_link_up(netif));
		SNPRINTF_APPEND("%2s%d_ip=%s\n", netif->name, netif->num, inet_ntoa(netif->ip_addr));
		if (!netif_is_ppp(netif) && !netif_is_tun(netif)) {
			SNPRINTF_APPEND("%2s%d_dhcp=%u\n", netif->name, netif->num, netif_is_dhcp(netif));
			SNPRINTF_APPEND("%2s%d_netmask=%s\n", netif->name, netif->num, inet_ntoa(netif->netmask));
			if (netif == netif_default)
				SNPRINTF_APPEND("%2s%d_gateway=%s\n", netif->name, netif->num, inet_ntoa(netif->gw));
		} else {
			SNPRINTF_APPEND("%2s%d_ptp=%s\n", netif->name, netif->num, inet_ntoa(netif->gw));
		}

		if (strcmp("lo", netif->name) && (drv = netif_driver(netif)) && drv->media != NULL)
			SNPRINTF_APPEND("%2s%d_media=%s\n", netif->name, netif->num, drv->media(netif));
	}

	return bufSize - size;
}


static void mainLoop(void)
{
	msg_t msg = {0};
	unsigned int rid;
	unsigned port;
	oid_t route_oid = {0, 0};
	oid_t status_oid = {0, 1};

	if (portCreate(&port) < 0) {
		printf("can't create port\n");
		return;
	}

	route_oid.port = port;
	status_oid.port = port;

	if (create_dev(&route_oid, "/dev/route") < 0) {
		printf("can't create /dev/route\n");
		return;
	}

	if (create_dev(&status_oid, "/dev/ifstatus") < 0) {
		printf("can't create /dev/ifstatus\n");
		return;
	}

	for (;;) {
		if (msgRecv(port, &msg, &rid) < 0)
			continue;

		switch (msg.type) {
		case mtRead:
				if (msg.i.io.oid.id == route_oid.id)
					msg.o.io.err = writeRoutes(msg.o.data, msg.o.size, msg.i.io.offs);
				else
					msg.o.io.err = writeStatus(msg.o.data, msg.o.size, msg.i.io.offs);
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
#ifdef HAVE_DRIVER_tuntap
	register_driver_tun();
	register_driver_tap();
#endif
#endif

	mutexCreate(&rt_table.lock);

#if defined(HAVE_IP_FILTER) || defined(HAVE_MAC_FILTER)
	init_filters();
#endif

	while (++argv, --argc) {
		int err = create_netif(*argv);

		if (!err)
			++have_intfs;
		else
			printf("can't init netif from cfg \"%s\": %s\n", *argv, strerror(err));
	}

	/* printf("netsrv: %zu interface%s\n", have_intfs, have_intfs == 1 ? "" : "s"); */
	if (!have_intfs)
		exit(1);

	mainLoop();
}
