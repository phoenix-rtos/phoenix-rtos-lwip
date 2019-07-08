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
#ifndef PHOENIX_NETIF_DRIVER_H_
#define PHOENIX_NETIF_DRIVER_H_


#include "lwip/netif.h"
#include <stdint.h>


enum {
	/* MDIO bus address masks */

	NETDEV_MDIO_A_MASK = 0x1F,
	NETDEV_MDIO_B_MASK = 0x1F00,
	NETDEV_MDIO_CLAUSE45 = 0x10000,
	NETDEV_MDIO_ADDR_MASK = NETDEV_MDIO_A_MASK | NETDEV_MDIO_B_MASK | NETDEV_MDIO_CLAUSE45,

	NETDEV_MDIO_PREAMBLE_OPTIONAL = 0x1,
};


typedef struct netif_driver_ {
	struct netif_driver_ *next;
	int (*init)(struct netif *netif, char *cfg);
	size_t state_sz, state_align;
	const char *name;
	const char *(*media)(struct netif *netif);
} netif_driver_t;


struct netif_alloc {
	struct netif netif;
	netif_driver_t *drv;
	char *cfg;
};


typedef struct mdio_bus_ops_ {
	int (*setup)(void *arg, unsigned max_khz, unsigned min_hold_ns, unsigned opt_preamble);
	uint16_t (*read)(void *arg, unsigned addr, uint16_t reg);
	void (*write)(void *arg, unsigned addr, uint16_t reg, uint16_t val);
} mdio_bus_ops_t;


void register_netif_driver(netif_driver_t *drv);
int create_netif(char *conf);
netif_driver_t *netif_driver(struct netif *netif);

int register_mdio_bus(const mdio_bus_ops_t *ops, void *arg);
int mdio_setup(unsigned bus, unsigned max_khz, unsigned min_hold_ns, unsigned opt_preamble);
uint16_t mdio_read(unsigned bus, unsigned addr, uint16_t reg);
void mdio_write(unsigned bus, unsigned addr, uint16_t reg, uint16_t val);
int mdio_lock_bus(unsigned bus);
void mdio_unlock_bus(unsigned bus);


#endif /* PHOENIX_NETIF_DRIVER_H_ */
