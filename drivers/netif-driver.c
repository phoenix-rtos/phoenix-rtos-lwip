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

#include "lwip/netifapi.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>


#ifndef MAX_MDIO_BUSSES
#define MAX_MDIO_BUSSES 1
#endif


struct netif_init {
	const netif_driver_t *drv;
	char *cfg;
};


struct mdio_bus {
	const mdio_bus_ops_t *ops;
	void *arg;
};


static const ip4_addr_t default_ip = { PP_HTONL(0x0A020001) };
static const ip4_addr_t default_mask = { PP_HTONL(0xFFFFFF00) };
static const ip4_addr_t default_gw = { PP_HTONL(0x0A020002) };

static netif_driver_t *net_driver_list;
static struct mdio_bus mdio[MAX_MDIO_BUSSES];


void register_netif_driver(netif_driver_t *drv)
{
	drv->next = net_driver_list;
	net_driver_list = drv;
}


int register_mdio_bus(const mdio_bus_ops_t *ops, void *arg)
{
	int i;

	for (i = 0; i < MAX_MDIO_BUSSES; ++i) {
		if (mdio[i].ops)
			continue;

		mdio[i].ops = ops;
		mdio[i].arg = arg;
		return i;
	}

	return -ENOMEM;
}


static err_t netif_dev_init(struct netif *netif)
{
	struct netif_init *idata;

	LWIP_ASSERT("netif != NULL", (netif != NULL));
	idata = netif->state;
	LWIP_ASSERT("initdata != NULL", (idata != NULL));

	MIB2_INIT_NETIF(netif, snmp_ifType_ethernet_csmacd, 10000000);

	netif->mtu = 1514;
	netif->hwaddr_len = ETH_HWADDR_LEN;
	netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP | NETIF_FLAG_BROADCAST |
		NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET;
	netif->name[0] = 'e';
	netif->name[1] = 'n';

	netif->output = etharp_output;
#if LWIP_IPV6
	netif->output_ip6 = ethip6_output;
#endif /* LWIP_IPV6 */

	switch (idata->drv->init(netif, idata->cfg)) {
	case -ENOMEM:
		return ERR_MEM;
	case 0:
		return ERR_OK;
	default:
		return ERR_VAL;
	}
}


int create_netif(char *conf)
{
	struct netif_init *idata;
	netif_driver_t *drv;
	struct netif *ni;
	char *arg;
	ip4_addr_t ipaddr, netmask, gw;
	size_t sz, ssz;
	err_t err;

	arg = strchr(conf, ':');
	if (arg)
		*arg++ = 0;

	for (drv = net_driver_list; drv != NULL; drv = drv->next)
		if (!strcmp(conf, drv->name))
			break;
	if (!drv)
		return -ENOENT;

	ipaddr = default_ip;
	netmask = default_mask;
	gw = default_gw;

	sz = sizeof(*ni);
	if (drv->state_align)
		sz = (sz + drv->state_align - 1) & ~(drv->state_align - 1);
	ssz = drv->state_sz >= sizeof(struct netif_init) ? drv->state_sz : sizeof(struct netif_init);

	ni = malloc(sz + ssz);
	if (!ni)
		return -ENOMEM;

	idata = (void *)ni + sz;
	idata->cfg = arg;
	idata->drv = drv;

	err = netifapi_netif_add(ni, &ipaddr, &netmask, &gw,
		(void *)idata, netif_dev_init, tcpip_input);

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


void mdio_setup(unsigned bus, unsigned max_khz, unsigned min_hold_ns, unsigned opt_preamble)
{
	const struct mdio_bus *pb = mdio_bus(bus);

	if (pb)
		pb->ops->setup(pb->arg, max_khz, min_hold_ns, opt_preamble);
}


uint16_t mdio_read(unsigned bus, unsigned addr, uint16_t reg)
{
	const struct mdio_bus *pb = mdio_bus(bus);

	return pb ? pb->ops->read(pb->arg, addr, reg) : 0;
}


void mdio_write(unsigned bus, unsigned addr, uint16_t reg, uint16_t val)
{
	const struct mdio_bus *pb = mdio_bus(bus);

	if (pb)
		pb->ops->write(pb->arg, addr, reg, val);
}
