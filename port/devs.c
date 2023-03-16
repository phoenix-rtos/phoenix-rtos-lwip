/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP status devices
 *
 * Copyright 2021, 2022 Phoenix Systems
 * Author: Ziemowit Leszczynski, Maciej Purski
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "lwipopts.h"

#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/dns.h"
#include "lwip/stats.h"

#include "netif.h"
#include "netif-driver.h"
#include "route.h"
#include "filter.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/msg.h>
#include <sys/threads.h>
#include <sys/minmax.h>
#include <posix/utils.h>


/* "/dev/route" and "/dev/ifstatus" are available by default */
#ifndef LWIP_ROUTE_DEV
#define LWIP_ROUTE_DEV 1
#endif
#ifndef LWIP_ROUTE_DEV_BUFFER_SIZE
#define LWIP_ROUTE_DEV_BUFFER_SIZE 1024
#endif
#ifndef LWIP_IFSTATUS_DEV
#define LWIP_IFSTATUS_DEV 1
#endif
#ifndef LWIP_IFSTATUS_DEV_BUFFER_SIZE
#define LWIP_IFSTATUS_DEV_BUFFER_SIZE 512
#endif
#ifndef LWIP_LINKMONITOR_DEV
#define LWIP_LINKMONITOR_DEV 0
#endif
#ifndef LWIP_LINKMONITOR_DEV_NAME
#define LWIP_LINKMONITOR_DEV_NAME "en1"
#endif
#ifndef LWIP_STATS_DEV
#define LWIP_STATS_DEV "/dev/ipstats"
#endif
#ifndef LWIP_STATS_DEV_BUFFER_SIZE
#define LWIP_STATS_DEV_BUFFER_SIZE 4096
#endif

#define DEV_ROUTE_ID       0
#define DEV_IFSTATUS_ID    1
#define DEV_PF_ID          2
#define DEV_LINKMONITOR_ID 3
#define DEV_STATS_ID       4

#define SNPRINTF_APPEND(fmt, ...) \
	do { \
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


#if (LWIP_ROUTE_DEV || LWIP_IFSTATUS_DEV || LWIP_EXT_PF || LWIP_LINKMONITOR_DEV || LWIP_STATS)
static struct {
#if LWIP_ROUTE_DEV
	struct {
		int busy;
		char buf[LWIP_ROUTE_DEV_BUFFER_SIZE];
		int len;
	} route;
#endif
#if LWIP_IFSTATUS_DEV
	struct {
		int busy;
		char buf[LWIP_IFSTATUS_DEV_BUFFER_SIZE];
		int len;
	} ifstatus;
#endif
#if LWIP_EXT_PF
	struct {
		int busy;
	} pf;
#endif
#if LWIP_LINKMONITOR_DEV
	struct {
		int busy;
		int disconnected;
		int reconnected;
		int last_link;
		char buf[64];
		int len;
	} linkmonitor;
#endif
#if LWIP_STATS
	struct {
		int busy;
		size_t len;
		char buf[LWIP_STATS_DEV_BUFFER_SIZE];
	} stats;
#endif
} devs_common;
#endif /* (LWIP_ROUTE_DEV || LWIP_IFSTATUS_DEV || LWIP_EXT_PF || LWIP_LINKMONITOR_DEV || LWIP_STATS) */


#if LWIP_ROUTE_DEV
static int route_open(int flags)
{
	rt_entry_t *entry;
	struct netif *netif;
	char *buf;
	size_t size;
	int overflow = 0;

	if (flags & (O_WRONLY | O_RDWR))
		return -EACCES;

	if (devs_common.route.busy)
		return -EBUSY;

	mutexLock(rt_table.lock);

	buf = devs_common.route.buf;
	size = sizeof(devs_common.route.buf);

	SNPRINTF_APPEND("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n");

	if ((entry = rt_table.entries) != NULL) {
		do {
			SNPRINTF_APPEND("%.2s%u\t%08X\t%08X\t%04X\t%d\t%u\t%d\t%08X\t%d\t%u\t%u\n",
				entry->netif->name, entry->netif->num,
				ip4_addr_get_u32(&entry->dst),                                                          /* Destination */
				ip4_addr_get_u32(entry->flags & RTF_GATEWAY ? &entry->gw : netif_ip4_gw(entry->netif)), /* Gateway */
				entry->flags, 0, 0,                                                                     /* Flags, RefCnt, Use */
				entry->metric,
				ip4_addr_get_u32(&entry->genmask),
				entry->netif->mtu,
				0, 0); /* Window, IRTT */
		} while ((entry = entry->next) != rt_table.entries);
	}

	/* add per-netif routing (LwIP uses it regardless of our routing table) - with highest priority (apart for our custom GW) */
	for (netif = netif_list; netif != NULL; netif = netif->next) {
		uint32_t prefix = ip4_addr_get_u32(netif_ip4_addr(netif)) & ip4_addr_get_u32(netif_ip4_netmask(netif));
		unsigned int flags = netif_is_up(netif) ? RTF_UP : 0;
		if (ip4_addr_get_u32(netif_ip4_gw(netif)) != 0)
			flags |= RTF_GATEWAY;

		SNPRINTF_APPEND("%.2s%u\t%08X\t%08X\t%04X\t%d\t%u\t%d\t%08X\t%d\t%u\t%u\n",
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

	devs_common.route.busy = 1;
	devs_common.route.len = buf - devs_common.route.buf;

	return 0;
}


static int route_close(void)
{
	if (!devs_common.route.busy)
		return -EBADF;
	devs_common.route.busy = 0;
	return 0;
}


static int route_read(char *data, size_t size, size_t offset)
{
	int read;

	if (offset > devs_common.route.len)
		return -ERANGE;

	read = min(size, devs_common.route.len - offset);
	memcpy(data, devs_common.route.buf + offset, read);

	return read;
}
#endif /* LWIP_ROUTE_DEV */


#if LWIP_IFSTATUS_DEV
static int ifstatus_open(int flags)
{
	struct netif *netif;
	netif_driver_t *drv;
	char *buf;
	size_t size;
	int overflow = 0;

	if (flags & (O_WRONLY | O_RDWR))
		return -EACCES;

	if (devs_common.ifstatus.busy)
		return -EBUSY;

	buf = devs_common.ifstatus.buf;
	size = sizeof(devs_common.ifstatus.buf);

	for (netif = netif_list; netif != NULL; netif = netif->next) {
		SNPRINTF_APPEND("%.2s%d_up=%u\n", netif->name, netif->num, netif_is_up(netif));
		SNPRINTF_APPEND("%.2s%d_link=%u\n", netif->name, netif->num, netif_is_link_up(netif));
		SNPRINTF_APPEND("%.2s%d_ip=%s\n", netif->name, netif->num, inet_ntoa(netif->ip_addr));
		if (!netif_is_ppp(netif) && !netif_is_tun(netif)) {
#if LWIP_DHCP
			SNPRINTF_APPEND("%.2s%d_dhcp=%u\n", netif->name, netif->num, netif_is_dhcp(netif));
#endif
			SNPRINTF_APPEND("%.2s%d_netmask=%s\n", netif->name, netif->num, inet_ntoa(netif->netmask));
			SNPRINTF_APPEND("%.2s%d_gateway=%s\n", netif->name, netif->num, inet_ntoa(netif->gw));
#if LWIP_DHCP_GET_MOBILE_AGENT
			if (netif_is_dhcp(netif))
				SNPRINTF_APPEND("%.2s%d_mobile_agent=%s\n", netif->name, netif->num, inet_ntoa(netif->mobile_agent));
#endif
		}
		else {
			SNPRINTF_APPEND("%.2s%d_ptp=%s\n", netif->name, netif->num, inet_ntoa(netif->gw));
		}

		if (strncmp("lo", netif->name, sizeof(netif->name)) != 0 && strncmp("wl", netif->name, sizeof(netif->name)) != 0 && strncmp("sc", netif->name, sizeof(netif->name)) != 0) {
			drv = netif_driver(netif);
			if (drv != NULL && drv->media != NULL)
				SNPRINTF_APPEND("%.2s%d_media=%s\n", netif->name, netif->num, drv->media(netif));
		}
	}

#if LWIP_DNS
	for (unsigned int i = 0; i < LWIP_DHCP_MAX_DNS_SERVERS; ++i)
		SNPRINTF_APPEND("dns_%u=%s\n", i, inet_ntoa(*dns_getserver(i)));
#endif

	if (overflow)
		return -EFBIG;

	devs_common.ifstatus.busy = 1;
	devs_common.ifstatus.len = buf - devs_common.ifstatus.buf;

	return 0;
}


static int ifstatus_close(void)
{
	if (!devs_common.ifstatus.busy)
		return -EBADF;
	devs_common.ifstatus.busy = 0;
	return 0;
}


static int ifstatus_read(char *data, size_t size, size_t offset)
{
	int read;

	if (offset > devs_common.ifstatus.len)
		return -ERANGE;

	read = min(size, devs_common.ifstatus.len - offset);
	memcpy(data, devs_common.ifstatus.buf + offset, read);

	return read;
}
#endif /* LWIP_IFSTATUS_DEV */


#if LWIP_STATS
static void stats_append(const char *fmt, ...)
{
	char *ptr = devs_common.stats.buf + devs_common.stats.len;
	int left;
	int n;
	va_list arg;

	left = sizeof(devs_common.stats.buf) - devs_common.stats.len;
	if (left == 0)
		return;

	va_start(arg, fmt);
	n = vsnprintf(ptr, left, fmt, arg);
	if (n > 0)
		devs_common.stats.len += min(n, left);
	va_end(arg);
}


static void stats_proto_append(const struct stats_proto *proto, const char *name)
{
	stats_append("%s.xmit=%" STAT_COUNTER_F "\n", name, proto->xmit);
	stats_append("%s.recv=%" STAT_COUNTER_F "\n", name, proto->recv);
	stats_append("%s.fw=%" STAT_COUNTER_F "\n", name, proto->fw);
	stats_append("%s.drop=%" STAT_COUNTER_F "\n", name, proto->drop);
	stats_append("%s.chkerr=%" STAT_COUNTER_F "\n", name, proto->chkerr);
	stats_append("%s.lenerr=%" STAT_COUNTER_F "\n", name, proto->lenerr);
	stats_append("%s.memerr=%" STAT_COUNTER_F "\n", name, proto->memerr);
	stats_append("%s.rterr=%" STAT_COUNTER_F "\n", name, proto->rterr);
	stats_append("%s.proterr=%" STAT_COUNTER_F "\n", name, proto->proterr);
	stats_append("%s.opterr=%" STAT_COUNTER_F "\n", name, proto->opterr);
	stats_append("%s.err=%" STAT_COUNTER_F "\n", name, proto->err);
	stats_append("%s.cachehit=%" STAT_COUNTER_F "\n\n", name, proto->cachehit);
}


#if MEM_STATS
static void stats_mem_append(const struct stats_mem *mem, const char *name)
{
	stats_append("%s.avail=%" MEM_SIZE_F "\n", name, mem->avail);
	stats_append("%s.used=%" MEM_SIZE_F "\n", name, mem->used);
	stats_append("%s.max=%" MEM_SIZE_F "\n", name, mem->max);
	stats_append("%s.err=%" STAT_COUNTER_F "\n\n", name, mem->err);
}
#endif /* MEM_STATS */


#if SYS_STATS
static void stats_sys_append(const struct stats_sys *sys)
{
	stats_append("sys.sem.used=%" STAT_COUNTER_F "\n", sys->sem.used);
	stats_append("sys.sem.max=%" STAT_COUNTER_F "\n", sys->sem.max);
	stats_append("sys.sem.err=%" STAT_COUNTER_F "\n", sys->sem.err);
	stats_append("sys.mutex.used=%" STAT_COUNTER_F "\n", sys->mutex.used);
	stats_append("sys.mutex.max=%" STAT_COUNTER_F "\n", sys->mutex.max);
	stats_append("sys.mutex.err=%" STAT_COUNTER_F "\n", sys->mutex.err);
	stats_append("sys.mbox.used=%" STAT_COUNTER_F "\n", sys->mbox.used);
	stats_append("sys.mbox.max=%" STAT_COUNTER_F "\n", sys->mbox.max);
	stats_append("sys.mbox.err=%" STAT_COUNTER_F "\n\n", sys->mbox.err);
}
#endif /* SYS_STATS */


static int stats_open(int flags)
{
	if (flags & (O_WRONLY | O_RDWR))
		return -EACCES;

	if (devs_common.stats.busy)
		return -EBUSY;

	devs_common.stats.busy = 1;
	devs_common.stats.len = 0;

#if LINK_STATS
	stats_proto_append(&lwip_stats.link, "link");
#endif
#if ETHARP_STATS
	stats_proto_append(&lwip_stats.etharp, "etharp");
#endif
#if IPFRAG_STATS
	stats_proto_append(&lwip_stats.ip_frag, "ipfrag");
#endif
#if IP6_FRAG_STATS
	stats_proto_append(&lwip_stats.ip6_frag, "ip6_frag");
#endif
#if IP_STATS
	stats_proto_append(&lwip_stats.ip, "ip");
#endif
#if ICMP_STATS
	stats_proto_append(&lwip_stats.icmp, "icmp");
#endif
#if ICMP6_STATS
	stats_proto_append(&lwip_stats.icmp6, "icmp6");
#endif
#if UDP_STATS
	stats_proto_append(&lwip_stats.udp, "udp");
#endif
#if TCP_STATS
	stats_proto_append(&lwip_stats.tcp, "tcp");
#endif
#if SYS_STATS
	stats_sys_append(&lwip_stats.sys);
#endif
#if MEM_STATS
	stats_mem_append(&lwip_stats.mem, "heap");
#endif
#if MEMP_STATS && (defined(LWIP_DEBUG) || LWIP_STATS_DISPLAY)
	int i;
	for (i = 0; i < MEMP_MAX; i++)
		stats_mem_append(lwip_stats.memp[i], lwip_stats.memp[i]->name);
#endif

	return 0;
}


static int stats_read(char *data, size_t size, size_t offset)
{
	int read;

	if (offset > devs_common.stats.len)
		return -ERANGE;

	read = min(size, devs_common.stats.len - offset);
	memcpy(data, devs_common.stats.buf + offset, read);

	return read;
}


static int stats_close(void)
{
	if (!devs_common.stats.busy)
		return -EBADF;

	devs_common.stats.busy = 0;

	return 0;
}

#endif /* LWIP_STATS */


#if LWIP_LINKMONITOR_DEV
static int linkmonitor_open(int flags)
{
	struct netif *netif;
	char *buf;
	size_t size;
	int overflow = 0;

	if (flags & (O_WRONLY | O_RDWR))
		return -EACCES;

	if (devs_common.linkmonitor.busy)
		return -EBUSY;

	netif = netif_find(LWIP_LINKMONITOR_DEV_NAME);
	if (!netif)
		return -EINVAL;

	/* initialize link status on first open */
	if (devs_common.linkmonitor.last_link == -1)
		devs_common.linkmonitor.last_link = netif_is_link_up(netif);

	buf = devs_common.linkmonitor.buf;
	size = sizeof(devs_common.linkmonitor.buf);

	SNPRINTF_APPEND("link=%u\n", devs_common.linkmonitor.last_link);
	SNPRINTF_APPEND("disconnected=%u\n", devs_common.linkmonitor.disconnected);
	SNPRINTF_APPEND("reconnected=%u\n", devs_common.linkmonitor.reconnected);

	if (overflow)
		return -EFBIG;

	/* clear disconnected/reconnected flags on every open */
	devs_common.linkmonitor.disconnected = 0;
	devs_common.linkmonitor.reconnected = 0;

	devs_common.linkmonitor.busy = 1;
	devs_common.linkmonitor.len = buf - devs_common.linkmonitor.buf;

	return 0;
}


static int linkmonitor_close(void)
{
	if (!devs_common.linkmonitor.busy)
		return -EBADF;
	devs_common.linkmonitor.busy = 0;
	return 0;
}


static int linkmonitor_read(char *data, size_t size, size_t offset)
{
	int read;

	if (offset > devs_common.linkmonitor.len)
		return -ERANGE;

	read = min(size, devs_common.linkmonitor.len - offset);
	memcpy(data, devs_common.linkmonitor.buf + offset, read);

	return read;
}


static void linkmonitor_callback(struct netif *netif)
{
	uint8_t link = netif_is_link_up(netif);

	/* link monitoring starts on first read */
	if (devs_common.linkmonitor.last_link == -1)
		return;

	if (!link && devs_common.linkmonitor.last_link)
		devs_common.linkmonitor.disconnected = 1;

	if (link && !devs_common.linkmonitor.last_link)
		devs_common.linkmonitor.reconnected = 1;

	devs_common.linkmonitor.last_link = link;
}


static void linkmonitor_init(const char *dev)
{
	struct netif *netif;

	devs_common.linkmonitor.disconnected = 0;
	devs_common.linkmonitor.reconnected = 0;
	devs_common.linkmonitor.last_link = -1;

	if ((netif = netif_find(dev)))
		netif_set_link_callback(netif, linkmonitor_callback);
}
#endif /* LWIP_LINKMONITOR_DEV */


#if LWIP_EXT_PF
static int pf_open(int flags)
{
	if (flags & (O_RDONLY | O_RDWR))
		return -EACCES;

	if (devs_common.pf.busy)
		return -EBUSY;

	devs_common.pf.busy = 1;

	return 0;
}


static int pf_close(void)
{
	if (!devs_common.pf.busy)
		return -EBADF;
	devs_common.pf.busy = 0;
	return 0;
}


static int pf_write(char *data, size_t size)
{
	pfrule_array_t *input = (pfrule_array_t *)data;

	if (input == NULL || !size || size != input->len * sizeof(pfrule_t) + sizeof(pfrule_array_t))
		return -EINVAL;

	return pf_rulesUpdate(input);
}
#endif /* LWIP_EXT_PF */


int devs_init(unsigned int port)
{
#if LWIP_ROUTE_DEV
	oid_t route_oid = { port, DEV_ROUTE_ID };
#endif
#if LWIP_IFSTATUS_DEV
	oid_t ifstatus_oid = { port, DEV_IFSTATUS_ID };
#endif
#if LWIP_EXT_PF
	oid_t pf_oid = { port, DEV_PF_ID };
#endif
#if LWIP_LINKMONITOR_DEV
	oid_t linkmonitor_oid = { port, DEV_LINKMONITOR_ID };
#endif
#if LWIP_STATS
	oid_t stats_oid = { port, DEV_STATS_ID };
#endif

#if LWIP_ROUTE_DEV
	if (create_dev(&route_oid, "/dev/route") < 0) {
		printf("phoenix-rtos-lwip: can't create /dev/route\n");
		return -1;
	}
#endif

#if LWIP_IFSTATUS_DEV
	if (create_dev(&ifstatus_oid, "/dev/ifstatus") < 0) {
		printf("phoenix-rtos-lwip: can't create /dev/ifstatus\n");
		return -1;
	}
#endif

#if LWIP_EXT_PF
	if (create_dev(&pf_oid, "/dev/pf") < 0) {
		printf("phoenix-rtos-lwip: can't create /dev/pf\n");
		return -1;
	}
#endif

#if LWIP_LINKMONITOR_DEV
	linkmonitor_init(LWIP_LINKMONITOR_DEV_NAME);

	if (create_dev(&linkmonitor_oid, "/dev/linkmonitor") < 0) {
		printf("phoenix-rtos-lwip: can't create /dev/linkmonitor\n");
		return -1;
	}
#endif

#if LWIP_STATS
	stats_init();

	if (create_dev(&stats_oid, LWIP_STATS_DEV) < 0) {
		printf("phoenix-rtos-lwip: can't create %s\n", LWIP_STATS_DEV);
		return -1;
	}
#endif

	return 0;
}


int dev_open(id_t id, int flags)
{
	switch (id) {
#if LWIP_ROUTE_DEV
		case DEV_ROUTE_ID:
			return route_open(flags);
#endif
#if LWIP_IFSTATUS_DEV
		case DEV_IFSTATUS_ID:
			return ifstatus_open(flags);
#endif
#if LWIP_EXT_PF
		case DEV_PF_ID:
			return pf_open(flags);
#endif
#if LWIP_LINKMONITOR_DEV
		case DEV_LINKMONITOR_ID:
			return linkmonitor_open(flags);
#endif
#if LWIP_STATS
		case DEV_STATS_ID:
			return stats_open(flags);
#endif
	}
	return -ENOENT;
}

int dev_close(id_t id)
{
	switch (id) {
#if LWIP_ROUTE_DEV
		case DEV_ROUTE_ID:
			return route_close();
#endif
#if LWIP_IFSTATUS_DEV
		case DEV_IFSTATUS_ID:
			return ifstatus_close();
#endif
#if LWIP_EXT_PF
		case DEV_PF_ID:
			return pf_close();
#endif
#if LWIP_LINKMONITOR_DEV
		case DEV_LINKMONITOR_ID:
			return linkmonitor_close();
#endif
#if LWIP_STATS
		case DEV_STATS_ID:
			return stats_close();
#endif
	}
	return -ENOENT;
}


int dev_read(id_t id, void *data, size_t size, size_t offset)
{
	switch (id) {
#if LWIP_ROUTE_DEV
		case DEV_ROUTE_ID:
			return route_read(data, size, offset);
#endif
#if LWIP_IFSTATUS_DEV
		case DEV_IFSTATUS_ID:
			return ifstatus_read(data, size, offset);
#endif
#if LWIP_EXT_PF
		case DEV_PF_ID:
			return -EACCES;
#endif
#if LWIP_LINKMONITOR_DEV
		case DEV_LINKMONITOR_ID:
			return linkmonitor_read(data, size, offset);
#endif
#if LWIP_STATS
		case DEV_STATS_ID:
			return stats_read(data, size, offset);
#endif
	}
	return -ENOENT;
}


int dev_write(id_t id, void *data, size_t size, size_t offset)
{
	switch (id) {
#if LWIP_ROUTE_DEV
		case DEV_ROUTE_ID:
			return -EACCES;
#endif
#if LWIP_IFSTATUS_DEV
		case DEV_IFSTATUS_ID:
			return -EACCES;
#endif
#if LWIP_EXT_PF
		case DEV_PF_ID:
			return pf_write(data, size);
#endif
#if LWIP_LINKMONITOR_DEV
		case DEV_LINKMONITOR_ID:
			return -EACCES;
#endif
	}
	return -ENOENT;
}
