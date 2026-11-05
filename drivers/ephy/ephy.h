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


enum eth_linkSpeed {
	eth_linkSpeedUnknown = 0,
	eth_linkSpeed10M = 10,
	eth_linkSpeed100M = 100,
	eth_linkSpeed1G = 1000,
};


enum eth_duplex {
	eth_duplexHalf = 0,
	eth_duplexFull = 1,
};


struct _ephy_driver_t;


typedef void (*linkStateCb_t)(void *arg, bool linkUp);


typedef struct _eth_phy_state {
	unsigned int bus;
	unsigned int addr;

	uint32_t phyid;
	uint8_t boardRev;
	bool absent;

	/* clang-format off */
	enum { ephy_irqGpio, ephy_irqMac } irqtype;
	/* clang-format on */

	const struct _ephy_driver_t *driver;

	linkStateCb_t lsCb;
	void *lsCbArg;

	net_gpioInfo_t resetGpio, irqGpio;
	uint32_t stack[512] __attribute__((aligned(16)));
} eth_phy_state_t;


/* initialize and configure the Ethernet PHY */
int ephy_init(eth_phy_state_t *phy, char *conf, uint8_t boardRev, linkStateCb_t lsCb, void *lsCbArg);

/* get the current (set or autonegotiated) link speed and duplex settings */
enum eth_linkSpeed ephy_linkSpeed(const eth_phy_state_t *phy, enum eth_duplex *duplex);

/* toggle MACPHY internal loopback for test mode */
int ephy_enableLoopback(const eth_phy_state_t *phy, bool enable);

/* called by the MAC driver if it handles the PHY IRQ */
void ephy_handleInterrupt(const eth_phy_state_t *phy);


#endif
