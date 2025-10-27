/*
 * Phoenix-RTOS --- networking stack
 *
 * Marvell Alaska Ethernet PHY
 *
 * Copyright 2025 Phoenix Systems
 * Author: Norbert Niderla
 *
 * %LICENSE%
 */

#include <string.h>
#include "ephy.h"
#include "netif-driver.h"

#define ENABLE_REG_LOG 0

/* Registers list. */
#define REG_0_0_CCR    0
#define REG_0_1_CSR    1
#define REG_0_2_PHYID1 2
#define REG_0_3_PHYID2 3
#define REG_0_4_CANR   4
#define REG_0_9_CR1000 9
#define REG_0_17_CSSR1 17
#define REG_2_21_MSCR2 21
#define REG_n_22_PA    22
#define REG_18_17_CRCC 17
#define REG_18_18_CHCR 18
#define REG_18_20_GCR1 20

/* CCR - Copper Control Register */
#define CCR_COPPER_RESET      0x8000
#define CCR_LOOPBACK          0x4000
#define CCR_SPEED_SELECT_MASK 0x2040
#define CCR_SPEED_SELECT_1000 0x0040
#define CCR_SPEED_SELECT_100  0x2000
#define CCR_SPEED_SELECT_10   0x0000
#define CCR_AN                0x1000
#define CCR_DUPLEX            0x0100
#define CCR_AN_RESTART        0x0200

/* CANR - Copper Auto-Negotiation Register */
#define CANR_100_FD_ADV 0x0100
#define CANR_100_HD_ADV 0x0080
#define CANR_10_HD_ADV  0x0020

/* CR1000 - 1000BASE-TX Control Register */
#define CR1000_FD_ADV 0x0200
#define CR1000_HD_ADV 0x0100

/* CSSR1 - Copper Specific Status Register 1 */
#define CSSR1_SPEED_MASK  0xC000
#define CSSR1_LINK_STATUS 0x0400
#define CSSR1_DUPLEX      0x2000
#define CSSR1_SPEED_1000  0x8000
#define CSSR1_SPEED_100   0x4000
#define CSSR1_SPEED_10    0x0000

/* GCR1 - General Control Register 1 */
#define GCR1_PHY_RESET         0x8000
#define GCR1_MODE_MASK         0x0007
#define GCR1_MODE_RGMII_COPPER 0x0000


#define ephy_printf(phy, fmt, ...) printf("lwip: ephy%u.%u: " fmt "\n", phy->bus, phy->addr, ##__VA_ARGS__)


static inline void ephy_mdioWrite(const eth_phy_state_t *phy, uint16_t reg, uint16_t val)
{
#if ENABLE_REG_LOG
	ephy_printf(phy, "write %d <- %04X", reg, val);
#endif
	mdio_write(phy->bus, phy->addr, reg, val);
}


static inline uint16_t ephy_mdioRead(const eth_phy_state_t *phy, uint16_t reg)
{
	uint16_t val = mdio_read(phy->bus, phy->addr, reg);
#if ENABLE_REG_LOG
	ephy_printf(phy, "read %d -> %04X", reg, val);
#endif
	return val;
}


static inline void ephy_mdioPageSet(const eth_phy_state_t *phy, uint16_t page)
{
	ephy_mdioWrite(phy, REG_n_22_PA, page);
}


static void ephy_linkStateSet(const eth_phy_state_t *phy)
{
	uint16_t cssr1 = ephy_mdioRead(phy, REG_0_17_CSSR1);
	phy->link_state_callback(phy->link_state_callback_arg, (cssr1 & CSSR1_LINK_STATUS) > 0);
}


static void ephy_anRestart(eth_phy_state_t *phy)
{
	uint16_t ccr = ephy_mdioRead(phy, REG_0_0_CCR);
	ccr |= CCR_AN_RESTART;
	ephy_mdioWrite(phy, REG_0_0_CCR, ccr);
}


static int ephy_softReset(eth_phy_state_t *phy)
{
	int res = -1;
	uint16_t ccr, gcr1;

	ccr = ephy_mdioRead(phy, REG_0_0_CCR);
	ccr |= CCR_COPPER_RESET;
	ephy_mdioWrite(phy, REG_0_0_CCR, ccr);

	for (int i = 0; i < 6; i++) {
		usleep(1000);
		if ((ephy_mdioRead(phy, REG_0_0_CCR) & CCR_COPPER_RESET) == 0) {
			res = 0;
			break;
		}

		usleep(5000000);
	}

	if (res != 0) {
		return res;
	}

	res = -1;

	ephy_mdioPageSet(phy, 18);

	gcr1 = ephy_mdioRead(phy, REG_18_20_GCR1);
	gcr1 |= GCR1_PHY_RESET;
	ephy_mdioWrite(phy, REG_18_20_GCR1, gcr1);

	for (int i = 0; i < 6; i++) {
		usleep(1000);
		if ((ephy_mdioRead(phy, REG_18_20_GCR1) & GCR1_PHY_RESET) == 0) {
			res = 0;
			break;
		}

		usleep(5000000);
	}

	ephy_mdioPageSet(phy, 0);
	return res;
}


static int ephy_config(eth_phy_state_t *phy)
{
	uint16_t canr, cr1000, gcr1;

	/* TODO At the moment I implement only 10Mbps/Full-Duplex, because examples
	with that mode were working on Trenz8080 board. All speed modes have to be implemented
	before releasing. */

	if (ephy_softReset(phy) != 0) {
		ephy_printf(phy, "First soft reset during PHY configuration failed.");
		return -1;
	}

	/* Disable 100Mbps and 10Mbps HD advertisement. */
	canr = ephy_mdioRead(phy, REG_0_4_CANR);
	canr &= ~(CANR_100_FD_ADV | CANR_100_HD_ADV | CANR_10_HD_ADV);
	ephy_mdioWrite(phy, REG_0_4_CANR, canr);

	/* Disable 1000Mbps advertisement. */
	cr1000 = ephy_mdioRead(phy, REG_0_9_CR1000);
	cr1000 &= ~(CR1000_FD_ADV | CR1000_HD_ADV);
	ephy_mdioWrite(phy, REG_0_9_CR1000, cr1000);

	/* Set RGMII mode. */
	ephy_mdioPageSet(phy, 18);
	gcr1 = ephy_mdioRead(phy, REG_18_20_GCR1);
	gcr1 = (gcr1 & ~(GCR1_MODE_MASK)) | GCR1_MODE_RGMII_COPPER;
	ephy_mdioWrite(phy, REG_18_20_GCR1, gcr1);
	ephy_mdioPageSet(phy, 0);

	/* Software reset is needed to update used configuration in PHY. */
	if (ephy_softReset(phy) != 0) {
		ephy_printf(phy, "Second soft reset during PHY configuration failed.");
		return -1;
	}

	return 0;
}


/**
 * Configuration format:
 * [model]:[phy_addr]
 */
static int ephy_confParse(eth_phy_state_t *phy, char *conf)
{
	char const *p = conf;

	ephy_printf(phy, "config string: '%s'", conf);

	if (strncmp("alaska88e1512", p, sizeof("alaska88e1512") - 1) == 0) {
		phy->model = ephy_alaska88e1512;
	}
	else {
		ephy_printf(phy, "Unreckognized PHY model.");
		return -1;
	}

	p += sizeof("alaska88e1512") - 1;

	while ((*p != '\0') && (*p != ':')) {
		p++;
	}

	if (*p != ':') {
		ephy_printf(phy, "Invalid configuration string. PHY addr is missing.");
		return -1;
	}

	p++;
	phy->addr = strtoul(p, NULL, 10);

	if (phy->addr < 0 || phy->addr > 31) {
		ephy_printf(phy, "%d is invalid PHY addr.", phy->addr);
		return -1;
	}

	ephy_printf(phy, "mdio address: %d", phy->addr);

	return 0;
}


int ephy_init(eth_phy_state_t *phy, char *conf, uint8_t board_rev, link_state_cb_t cb, void *cb_arg)
{
	if (ephy_confParse(phy, conf) != 0) {
		ephy_printf(phy, "Failed to parse configuration: '%s'", conf);
		return -1;
	}

	if (cb == NULL) {
		ephy_printf(phy, "Invalid link_state_cb - NULL.");
		return -1;
	}

	phy->link_state_callback = cb;
	phy->link_state_callback_arg = cb_arg;

	if (mdio_setup(phy->bus, 2500, 0, 0) != 0) {
		ephy_printf(phy, "MDIO setup failed.");
		return -1;
	}

	ephy_config(phy);
	ephy_linkStateSet(phy);
	ephy_anRestart(phy);

	return 0;
}


int ephy_linkSpeed(const eth_phy_state_t *phy, int *full_duplex)
{
	uint16_t cssr1 = mdio_read(phy->bus, phy->addr, REG_0_17_CSSR1);

	if (full_duplex != NULL) {
		*full_duplex = cssr1 & CSSR1_DUPLEX;
	}

	switch (cssr1 & CSSR1_SPEED_MASK) {
		case CSSR1_SPEED_1000:
			return 1000;
		case CSSR1_SPEED_100:
			return 100;
		case CSSR1_SPEED_10:
			return 10;
		default:
			return 0;
	}
}


void ephy_macInterrupt(const eth_phy_state_t *phy)
{
	/* TODO Handle interrupts */
	ephy_linkStateSet(phy);
}


int ephy_enableLoopback(const eth_phy_state_t *phy, bool enable)
{
	/* TODO */
	return 0;
}


int ephy_linkStateGet(const eth_phy_state_t *phy)
{
	return (ephy_mdioRead(phy, REG_0_17_CSSR1) & CSSR1_LINK_STATUS) > 0;
}
