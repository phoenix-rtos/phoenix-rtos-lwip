/*
 * Phoenix-RTOS --- networking stack
 *
 * Ethernet PHY common routines
 *
 * Copyright 2018, 2026 Phoenix Systems
 * Author: Michal Miroslaw, Julian Uziemblo
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef NET_EPHY_H_
#define NET_EPHY_H_

#include <stdbool.h>
#include <stdint.h>

#include "netif-driver.h"

#include "../gpio.h"


struct _ephy_driver_t;


typedef struct _eth_phy_state {
	unsigned int bus;
	unsigned int addr;

	uint32_t phyid;
	uint8_t boardRev;

	/* clang-format off */
	enum { ephy_irqGpio, ephy_irqMac } irqtype;
	/* clang-format on */
	gpio_info_t resetGpio, irqGpio;

	struct netif *netif;

	const struct _ephy_driver_t *driver;

	uint32_t stack[512] __attribute__((aligned(16)));
} eth_phy_state_t;


/* initialize and configure the Ethernet PHY */
int ephy_init(eth_phy_state_t *phy, char *conf, uint8_t boardRev, struct netif *netif);

/* get the current (set or autonegotiated) link speed and duplex settings */
int ephy_linkSpeed(const eth_phy_state_t *phy, int *full_duplex);

/* toggle MACPHY internal loopback for test mode */
int ephy_enableLoopback(const eth_phy_state_t *phy, bool enable);

/* called by the MAC driver if it handles the PHY IRQ */
void ephy_handleInterrupt(const eth_phy_state_t *phy);


#endif
