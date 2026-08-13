/*
 * Phoenix-RTOS --- networking stack
 *
 * Ethernet PHY driver
 *
 * Copyright 2018, 2026 Phoenix Systems
 * Author: Michal Miroslaw, Julian Uziemblo
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef NET_EPHY_DRIVER_H_
#define NET_EPHY_DRIVER_H_

#include <stdint.h>
#include <stdbool.h>

#include "ephy.h"

#define EPHY_DEBUG 0

#define ephy_printf(phy, fmt, ...) printf("lwip: ephy%u.%u: " fmt "\n", phy->bus, phy->addr, ##__VA_ARGS__)

#if EPHY_DEBUG
#define ephy_debug_printf(phy, fmt, ...) ephy_printf(phy, fmt, ##__VA_ARGS__)
#else
#define ephy_debug_printf(phy, fmt, ...)
#endif


/* EPHY common registers */
enum {
	EPHY_COMMON_00_BMCR = 0x00,  /* Basic Mode Control */
	EPHY_COMMON_01_BMSR,         /* Basic Mode Status */
	EPHY_COMMON_02_PHYID1,       /* PHY Identifier 1 */
	EPHY_COMMON_03_PHYID2,       /* PHY Identifier 2 */
	EPHY_COMMON_04_ANAR,         /* Auto-Neg Advertising */
	EPHY_COMMON_05_ANLPAR,       /* Auto-Neg Link Partner Ability */
	EPHY_COMMON_06_ANER,         /* Auto-Neg Expansion */
	EPHY_COMMON_07_ANPR,         /* Auto-Neg Next Page */
	EPHY_COMMON_08_LPNPAR,       /* Link Partner Next Page Ability */
	EPHY_COMMON_09_GBCR,         /* 1000Base-T Control */
	EPHY_COMMON_0A_GBSR,         /* 1000Base-T Status */
	EPHY_COMMON_0F_GBESR = 0x0F, /* 1000Base-T Ext Status */
};

/* MMD access common registers */
enum {
	EPHY_MMD_0D_MACR = 0x0D, /* MMD Access Ctrl */
	EPHY_MMD_0E_MAADR,       /* MMD Access Addr Data */
};


enum eth_linkSpeed {
	eth_linkSpeed_unknown = 0,
	eth_linkSpeed_10M = 10,
	eth_linkSpeed_100M = 100,
	eth_linkSpeed_1G = 1000,
};


enum eth_duplex {
	eth_duplexHalf = 0,
	eth_duplexFull,
};


typedef struct _ephy_driver_t {
	struct _ephy_driver_t *prev, *next;
	const char *name;

	struct {
		struct {
			unsigned int holdTimeUs;
			unsigned int releaseTimeUs;
		} reset;

		struct {
			uint16_t mask;
			uint16_t reg;
		} irq;

		enum eth_linkSpeed maxSpeed;
	} properties;

	/* required*/
	int (*enable_irq)(const eth_phy_state_t *phy, bool enable);
	int (*link_speed)(const eth_phy_state_t *phy, enum eth_linkSpeed *speed, enum eth_duplex *duplex);

	/* optional */
	int (*specific_setup)(const eth_phy_state_t *phy);
	int (*config_adv)(const eth_phy_state_t *phy);
} ephy_driver_t;


void ephy_driverRegister(ephy_driver_t *driver);

uint16_t ephy_regRead(const eth_phy_state_t *phy, uint16_t reg);

void ephy_regWrite(const eth_phy_state_t *phy, uint16_t reg, uint16_t val);

uint16_t ephy_mmdRead(const eth_phy_state_t *phy, uint16_t devad, uint16_t addr);

void ephy_mmdWrite(const eth_phy_state_t *phy, uint16_t devad, uint16_t addr, uint16_t val);


#endif /* NET_EPHY_DRIVER_H_ */
