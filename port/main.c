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
#include <sys/minmax.h>
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


#define DEV_ROUTE_ID       0
#define DEV_IFSTATUS_ID    1
#define DEV_PF_ID          2
#define DEV_LINKMONITOR_ID 3


#define SNPRINTF_APPEND(fmt, ...) do { \
		if (!overflow) { \
			int n = snprintf(buf, size, fmt, ##__VA_ARGS__); \
			if (n >= size) \
				overflow = 1; \
			else { \
				size -= n; \
				buf += n; \
			} \
		} \
	} while (0)


static struct {
	struct {
		int busy;
		char buf[1024];
		int len;
	} route;
	struct {
		int busy;
		char buf[512];
		int len;
	} ifstatus;
#if LWIP_EXT_PF
	struct {
		int busy;
	} pf;
#endif
#ifdef LWIP_LINKMONITOR_DEV
	struct {
		int busy;
		int disconnected;
		int reconnected;
		int last_link;
		char buf[64];
		int len;
	} linkmonitor;
#endif
} main_common;


static int route_open(int flags)
{
	rt_entry_t *entry;
	struct netif *netif;
	char *buf;
	size_t size;
	int overflow = 0;

	if (flags & (O_WRONLY | O_RDWR))
		return -EACCES;

	if (main_common.route.busy)
		return -EBUSY;

	mutexLock(rt_table.lock);

	buf = main_common.route.buf;
	size = sizeof(main_common.route.buf);

	SNPRINTF_APPEND("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n");

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

	mutexUnlock(rt_table.lock);

	if (overflow)
		return -EFBIG;

	main_common.route.busy = 1;
	main_common.route.len = buf - main_common.route.buf;

	return 0;
}


static int route_close(void)
{
	if (!main_common.route.busy)
		return -EBADF;
	main_common.route.busy = 0;
	return 0;
}


static int route_read(char *data, size_t size, size_t offset)
{
	int read;

	if (offset > main_common.route.len)
		return -ERANGE;

	read = min(size, main_common.route.len - offset);
	memcpy(data, main_common.route.buf + offset, read);

	return read;
}


static int ifstatus_open(int flags)
{
	struct netif *netif;
	netif_driver_t *drv;
	unsigned int i;
	char *buf;
	size_t size;
	int overflow = 0;

	if (flags & (O_WRONLY | O_RDWR))
		return -EACCES;

	if (main_common.ifstatus.busy)
		return -EBUSY;

	buf = main_common.ifstatus.buf;
	size = sizeof(main_common.ifstatus.buf);

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

	if (overflow)
		return -EFBIG;

	main_common.ifstatus.busy = 1;
	main_common.ifstatus.len = buf - main_common.ifstatus.buf;

	return 0;
}


static int ifstatus_close(void)
{
	if (!main_common.ifstatus.busy)
		return -EBADF;
	main_common.ifstatus.busy = 0;
	return 0;
}


static int ifstatus_read(char *data, size_t size, size_t offset)
{
	int read;

	if (offset > main_common.ifstatus.len)
		return -ERANGE;

	read = min(size, main_common.ifstatus.len - offset);
	memcpy(data, main_common.ifstatus.buf + offset, read);

	return read;
}


#ifdef LWIP_LINKMONITOR_DEV
static int linkmonitor_open(int flags)
{
	struct netif *netif;
	char *buf;
	size_t size;
	int overflow = 0;

	if (flags & (O_WRONLY | O_RDWR))
		return -EACCES;

	if (main_common.linkmonitor.busy)
		return -EBUSY;

	netif = netif_find(LWIP_LINKMONITOR_DEV);
	if (!netif)
		return -EINVAL;

	/* initialize link status on first open */
	if (main_common.linkmonitor.last_link == -1)
		main_common.linkmonitor.last_link = netif_is_link_up(netif);

	buf = main_common.linkmonitor.buf;
	size = sizeof(main_common.linkmonitor.buf);

	SNPRINTF_APPEND("link=%u\n", main_common.linkmonitor.last_link);
	SNPRINTF_APPEND("disconnected=%u\n", main_common.linkmonitor.disconnected);
	SNPRINTF_APPEND("reconnected=%u\n", main_common.linkmonitor.reconnected);

	if (overflow)
		return -EFBIG;

	/* clear disconnected/reconnected flags on every open */
	main_common.linkmonitor.disconnected = 0;
	main_common.linkmonitor.reconnected = 0;

	main_common.linkmonitor.busy = 1;
	main_common.linkmonitor.len = buf - main_common.linkmonitor.buf;

	return 0;
}


static int linkmonitor_close(void)
{
	if (!main_common.linkmonitor.busy)
		return -EBADF;
	main_common.linkmonitor.busy = 0;
	return 0;
}


static int linkmonitor_read(char *data, size_t size, size_t offset)
{
	int read;

	if (offset > main_common.linkmonitor.len)
		return -ERANGE;

	read = min(size, main_common.linkmonitor.len - offset);
	memcpy(data, main_common.linkmonitor.buf + offset, read);

	return read;
}


static void linkmonitor_callback(struct netif *netif)
{
	uint8_t link = netif_is_link_up(netif);

	/* link monitoring starts on first read */
	if (main_common.linkmonitor.last_link == -1)
		return;

	if (!link && main_common.linkmonitor.last_link)
		main_common.linkmonitor.disconnected = 1;

	if (link && !main_common.linkmonitor.last_link)
		main_common.linkmonitor.reconnected = 1;

	main_common.linkmonitor.last_link = link;
}


static void linkmonitor_init(const char *dev)
{
	struct netif *netif;

	main_common.linkmonitor.disconnected = 0;
	main_common.linkmonitor.reconnected = 0;
	main_common.linkmonitor.last_link = -1;

	if ((netif = netif_find(dev)))
		netif_set_link_callback(netif, linkmonitor_callback);
}
#endif /* LWIP_LINKMONITOR_DEV */


#if LWIP_EXT_PF
static int pf_open(int flags)
{
	if (flags & (O_RDONLY | O_RDWR))
		return -EACCES;

	if (main_common.pf.busy)
		return -EBUSY;

	main_common.pf.busy = 1;

	return 0;
}


static int pf_close(void)
{
	if (!main_common.pf.busy)
		return -EBADF;
	main_common.pf.busy = 0;
	return 0;
}


static int pf_write(char *data, size_t size)
{
	pfrule_array_t *input = (pfrule_array_t *)data;

	if (input == NULL || !size || size != input->len * sizeof(pfrule_t) + sizeof(pfrule_array_t))
		return -EINVAL;

	return pf_rulesUpdate(input);
}
#endif


static int dev_init(unsigned int port)
{
	oid_t route_oid = { port, DEV_ROUTE_ID };
	oid_t ifstatus_oid = { port, DEV_IFSTATUS_ID };
#if LWIP_EXT_PF
	oid_t pf_oid = { port, DEV_PF_ID };
#endif
#ifdef LWIP_LINKMONITOR_DEV
	oid_t linkmonitor_oid = { port, DEV_LINKMONITOR_ID };
#endif

	if (create_dev(&route_oid, "/dev/route") < 0) {
		printf("phoenix-rtos-lwip: can't create /dev/route\n");
		return -1;
	}

	if (create_dev(&ifstatus_oid, "/dev/ifstatus") < 0) {
		printf("phoenix-rtos-lwip: can't create /dev/ifstatus\n");
		return -1;
	}

#if LWIP_EXT_PF
	if (create_dev(&pf_oid, "/dev/pf") < 0) {
		printf("phoenix-rtos-lwip: can't create /dev/pf\n");
		return -1;
	}
#endif

#ifdef LWIP_LINKMONITOR_DEV
	if (create_dev(&linkmonitor_oid, "/dev/linkmonitor") < 0) {
		printf("phoenix-rtos-lwip: can't create /dev/linkmonitor\n");
		return -1;
	}
#endif

	return 0;
}


static int dev_open(id_t id, int flags)
{
	switch (id) {
		case DEV_ROUTE_ID:
			return route_open(flags);
		case DEV_IFSTATUS_ID:
			return ifstatus_open(flags);
#if LWIP_EXT_PF
		case DEV_PF_ID:
			return pf_open(flags);
#endif
#ifdef LWIP_LINKMONITOR_DEV
		case DEV_LINKMONITOR_ID:
			return linkmonitor_open(flags);
#endif
	}
	return -ENOENT;
}

static int dev_close(id_t id)
{
	switch (id) {
		case DEV_ROUTE_ID:
			return route_close();
		case DEV_IFSTATUS_ID:
			return ifstatus_close();
#if LWIP_EXT_PF
		case DEV_PF_ID:
			return pf_close();
#endif
#ifdef LWIP_LINKMONITOR_DEV
		case DEV_LINKMONITOR_ID:
			return linkmonitor_close();
#endif
	}
	return -ENOENT;
}


static int dev_read(id_t id, void *data, size_t size, size_t offset)
{
	switch (id) {
		case DEV_ROUTE_ID:
			return route_read(data, size, offset);
		case DEV_IFSTATUS_ID:
			return ifstatus_read(data, size, offset);
#if LWIP_EXT_PF
		case DEV_PF_ID:
			return -EACCES;
#endif
#ifdef LWIP_LINKMONITOR_DEV
		case DEV_LINKMONITOR_ID:
			return linkmonitor_read(data, size, offset);
#endif
	}
	return -ENOENT;
}


static int dev_write(id_t id, void *data, size_t size, size_t offset)
{
	switch (id) {
		case DEV_ROUTE_ID:
		case DEV_IFSTATUS_ID:
#ifdef LWIP_LINKMONITOR_DEV
		case DEV_LINKMONITOR_ID:
#endif
			return -EACCES;
#if LWIP_EXT_PF
		case DEV_PF_ID:
			return pf_write(data, size);
#endif
	}
	return -ENOENT;
}


static void mainLoop(void)
{
	msg_t msg = { 0 };
	unsigned long int rid;
	unsigned port;

	if (portCreate(&port) < 0) {
		printf("phoenix-rtos-lwip: can't create port\n");
		return;
	}

	if (dev_init(port) < 0)
		return;

	for (;;) {
		if (msgRecv(port, &msg, &rid) < 0)
			continue;

		switch (msg.type) {
			case mtOpen:
				msg.o.io.err = dev_open(msg.i.openclose.oid.id, msg.i.openclose.flags);
				break;

			case mtClose:
				msg.o.io.err = dev_close(msg.i.openclose.oid.id);
				break;

			case mtRead:
				msg.o.io.err = dev_read(msg.i.openclose.oid.id, msg.o.data, msg.o.size, msg.i.io.offs);
				break;

			case mtWrite:
				msg.o.io.err = dev_write(msg.i.openclose.oid.id, msg.i.data, msg.i.size, msg.i.io.offs);
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
	linkmonitor_init(LWIP_LINKMONITOR_DEV);
#endif

	mainLoop();

	return 1;
}
