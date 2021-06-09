/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP netif driver
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "netif-driver.h"

#include "lwip/etharp.h"
#include "lwip/netifapi.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/ethip6.h"

#include <sys/threads.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>


#ifndef MAX_MDIO_BUSSES
#define MAX_MDIO_BUSSES 1
#endif


struct mdio_bus {
	const mdio_bus_ops_t *ops;
	void *arg;
	handle_t lock;
};


static netif_driver_t *net_driver_list;
static struct mdio_bus mdio[MAX_MDIO_BUSSES];


void register_netif_driver(netif_driver_t *drv)
{
	drv->next = net_driver_list;
	net_driver_list = drv;
}


int register_mdio_bus(const mdio_bus_ops_t *ops, void *arg)
{
	int err, i;

	for (i = 0; i < MAX_MDIO_BUSSES; ++i) {
		if (mdio[i].ops)
			continue;

		if ((err = mutexCreate(&mdio[i].lock)))
			return err;

		mdio[i].ops = ops;
		mdio[i].arg = arg;
		return i;
	}

	return -ENOMEM;
}


static err_t netif_dev_init(struct netif *netif)
{
	struct netif_alloc *storage = (void *)netif;

	LWIP_ASSERT("netif != NULL", (netif != NULL));

	if (!strcmp(storage->drv->name, "enet") || !strcmp(storage->drv->name, "rtl")) {
		MIB2_INIT_NETIF(netif, snmp_ifType_ethernet_csmacd, 10000000);

		netif->mtu = 1500;
		netif->hwaddr_len = ETH_HWADDR_LEN;
		netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP | NETIF_FLAG_BROADCAST |
		NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET;

		netif->name[0] = 'e';
		netif->name[1] = 'n';
	}

	if (strcmp(storage->drv->name, "tun")) {
		netif->output = etharp_output;
#if LWIP_IPV6
		netif->output_ip6 = ethip6_output;
#endif /* LWIP_IPV6 */
	}

	switch (storage->drv->init(netif, storage->cfg)) {
	case -ENOMEM:
		return ERR_MEM;
	case 0:
		return ERR_OK;
	default:
		return ERR_VAL;
	}
}


netif_driver_t *netif_driver(struct netif *netif)
{
	struct netif_alloc *storage = (struct netif_alloc *)netif;
	return storage->drv;
}


int create_netif(char *conf)
{
	struct netif_alloc *storage;
	netif_driver_t *drv;
	struct netif *ni;
	char *arg;
	size_t sz;
	err_t err;
	int is_ppp = 0;

	arg = strchr(conf, ':');
	if (arg)
		*arg++ = 0;

	is_ppp = (arg != NULL) && (strncmp(conf, "ppp", 3) == 0);
	//printf("netif: driver '%s' args '%s' is_ppp=%d\n", conf, arg, is_ppp);

	for (drv = net_driver_list; drv != NULL; drv = drv->next)
		if (!strcmp(conf, drv->name))
			break;
	if (!drv)
		return -ENOENT;

	sz = sizeof(*storage);
	if (drv->state_align)
		sz = (sz + drv->state_align - 1) & ~(drv->state_align - 1);

	storage = malloc(sz + drv->state_sz);
	if (!storage)
		return -ENOMEM;

	ni = &storage->netif;
	storage->cfg = arg;
	storage->drv = drv;

	if (!is_ppp) {
		err = netifapi_netif_add(ni, NULL, NULL, NULL,
			(char *)storage + sz, netif_dev_init, tcpip_input);
	} else {
		ni->state = (char *)storage + sz;
		err = storage->drv->init(ni, storage->cfg);
	}

	if (err != ERR_OK)
		free(ni);

	switch (err) {
	case ERR_OK:
		return 0;
	case ERR_ARG:
	case ERR_VAL:
		return -EINVAL;
	case ERR_MEM:
		return -ENOMEM;
	default:
		return -ENXIO;
	}
}


static const struct mdio_bus *mdio_bus(unsigned bus)
{
	return bus < MAX_MDIO_BUSSES && mdio[bus].ops ? mdio + bus : NULL;
}


int mdio_lock_bus(unsigned bus)
{
	const struct mdio_bus *pb = mdio_bus(bus);

	if (pb)
		return mutexLock(pb->lock);
	else
		return -ENODEV;
}


void mdio_unlock_bus(unsigned bus)
{
	mutexUnlock(mdio_bus(bus)->lock);
}


int mdio_setup(unsigned bus, unsigned max_khz, unsigned min_hold_ns, unsigned opt_preamble)
{
	const struct mdio_bus *pb = mdio_bus(bus);
	int err;

	if (pb) {
		mutexLock(pb->lock);
		err = pb->ops->setup(pb->arg, max_khz, min_hold_ns, opt_preamble);
		mutexUnlock(pb->lock);
	} else
		err = -ENODEV;

	return err;
}


uint16_t mdio_read(unsigned bus, unsigned addr, uint16_t reg)
{
	const struct mdio_bus *pb = mdio_bus(bus);
	uint16_t v = 0;

	if (pb) {
		mutexLock(pb->lock);
		v = pb->ops->read(pb->arg, addr, reg);
		mutexUnlock(pb->lock);
	}

	return v;
}


void mdio_write(unsigned bus, unsigned addr, uint16_t reg, uint16_t val)
{
	const struct mdio_bus *pb = mdio_bus(bus);

	if (pb) {
		mutexLock(pb->lock);
		pb->ops->write(pb->arg, addr, reg, val);
		mutexUnlock(pb->lock);
	}
}
