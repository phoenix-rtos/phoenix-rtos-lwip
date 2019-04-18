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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/msg.h>
#include <posix/utils.h>

#include<lwip/sockets.h>
#include "route.h"
#include "filter.h"

static int writeRoutes(char *buffer, size_t bufSize, size_t offset)
{
	int i;
	rt_entry_t *entry;
	size_t write, size = bufSize, retval;

	const char *format = "    %2s%d    %08x    %08x    %08x    %8x    %8d\n";

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

	SNPRINTF_APPEND("%7s%12s%12s%12s%12s%12s\n", "Iface", "Dest", "Mask", "Gateway", "Flags", "MTU");

	for (i = 0; i < rt_table.used; i++) {
		entry = rt_table.entries[i];
		SNPRINTF_APPEND(format, entry->netif->name, entry->netif->num, ntohl(ip_addr_get_ip4_u32(&entry->dst)),
			ntohl(ip_addr_get_ip4_u32(&entry->genmask)), ntohl(ip_addr_get_ip4_u32(&entry->gw)),
			entry->flags, entry->netif->mtu);
	}

	if (netif_default != NULL) {
		SNPRINTF_APPEND(format, netif_default->name, netif_default->num, 0, 0,
			ntohl(ip_addr_get_ip4_u32(&netif_default->gw)), netif_default->flags, netif_default->mtu);
	}

#undef ROUTE_APPEND

	retval = bufSize - size;
	return retval;
}


static void mainLoop(void)
{
	msg_t msg = {0};
	unsigned int rid;
	oid_t oid = {0, 0};

	if (portCreate(&oid.port) < 0) {
		printf("can't create port\n");
		return;
	}

	if (create_dev(&oid, "/dev/route") < 0) {
		printf("can't create /dev/route\n");
		return;
	}

	for (;;) {
		if (msgRecv(oid.port, &msg, &rid) < 0)
			continue;

		switch (msg.type) {
		case mtRead:
			msg.o.io.err = writeRoutes(msg.o.data, msg.o.size, msg.i.io.offs);
			break;

		default:
			break;
		}

		msgRespond(oid.port, &msg, rid);
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

	mainLoop();
}
