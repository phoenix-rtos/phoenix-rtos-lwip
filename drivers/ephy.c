/*
 * Phoenix-RTOS --- networking stack
 *
 * Ethernet PHY common routines
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * %LICENSE%
 */
#include "ephy.h"
#include "gpio.h"
#include "netif-driver.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/msg.h>
#include <sys/threads.h>


// #define EPHY_KSZ8081RND

enum {
	EPHY_00_BMCR = 0x00,      /* Basic Mode Control */
	EPHY_01_BMSR,             /* Basic Mode Status */
	EPHY_02_PHYID1,           /* PHY Identifier 1 */
	EPHY_03_PHYID2,           /* PHY Identifier 2 */
	EPHY_04_ANAR,             /* Auto-Neg Advertising */
	EPHY_05_ANLPAR,           /* Auto-Neg Link Partner Ability */
	EPHY_06_ANER,             /* Auto-Neg Expansion */
	EPHY_07_ANPR,             /* Auto-Neg Next Page */
	EPHY_08_LPNPAR,           /* Link Partner Next Page Ability */
	EPHY_10_DRCR = 0x10,      /* Digital Reserved Control */
	EPHY_11_AFECR1,           /* AFE Control 1 */
	EPHY_15_RXER_CNTR = 0x15, /* RXER Counter */
	EPHY_16_OMSOR,            /* Operation Mode Strap Override */
	EPHY_17_OMSSR,            /* Operation Mode Strap Status*/
	EPHY_18_EXCR,             /* Expanded Control */
	EPHY_1B_ICSR = 0x1B,      /* Interrupt Control/Status */
	EPHY_1D_LMDCSR = 0x1D,    /* LinkMD Control/Status */
	EPHY_1E_PHYCR1,           /* PHY Control 1 */
	EPHY_1F_PHYCR2            /* PHY Control 2 */
};


static uint16_t ephy_regRead(eth_phy_state_t *phy, uint16_t reg)
{
	return mdio_read(phy->bus, phy->addr, reg);
}


static void ephy_regWrite(eth_phy_state_t *phy, uint16_t reg, uint16_t val)
{
	mdio_write(phy->bus, phy->addr, reg, val);
	ephy_regRead(phy, reg);
}


static void ephy_reset(eth_phy_state_t *phy)
{
	if (gpio_valid(&phy->reset)) {
		// TODO: prepare bootstrap pins
		gpio_set(&phy->reset, 1);
		usleep(phy->reset_hold_time_us);
		mdio_lock_bus(phy->bus);
		gpio_set(&phy->reset, 0);
		usleep(phy->reset_release_time_us);
		mdio_unlock_bus(phy->bus);
	}
	else {
		uint16_t res;
		int retries = 10;

		ephy_regWrite(phy, EPHY_00_BMCR, 1u << 15);
		usleep(phy->reset_release_time_us);

		while (retries-- > 0) {
			res = ephy_regRead(phy, EPHY_00_BMCR);
			if ((res & (1u << 15)) == 0) {
				return;
			}
		}
		printf("lwip: ephy%u.%u soft-reset timed out\n", phy->bus, phy->addr);
	}
}


static uint32_t ephy_readPhyId(eth_phy_state_t *phy)
{
	uint32_t oui = 0;
	uint32_t phyid = 0;
	uint16_t ret;

	ret = ephy_regRead(phy, EPHY_02_PHYID1);
	phyid = ret << 16;
	oui |= ret << 2;

	ret = ephy_regRead(phy, EPHY_03_PHYID2);
	phyid |= ret;
	oui |= (ret & 0xFC00) << (18 - 10);

	/*
		printf("lwip: ephy%u.%u id 0x%08x (vendor 0x%06x model 0x%02x rev %u)\n",
			phy->bus, phy->addr, phyid, oui, (ret >> 4) & 0x3F, ret & 0x0F);
	*/

	oui = ephy_regRead(phy, EPHY_10_DRCR);
	ret = ephy_regRead(phy, EPHY_11_AFECR1);

	/*
		printf("lwip: ephy%u.%u DigCtl 0x%04x AFECtl1 0x%04x\n",
			phy->bus, phy->addr, oui, ret);
	*/

	return phyid;
}


static void ephy_setLinkState(eth_phy_state_t *phy)
{
	uint16_t bctl, bstat, adv, lpa, pc1, pc2;
	int speed, full_duplex = 0;

	bctl = ephy_regRead(phy, EPHY_00_BMCR);
	/* 
	 * NOTE: "[Bit 2 of BMSR] indicates whether the link was
	 * lost since the last read. For the current link status,
	 * read this register twice." - RTL8201FI-VC-CG datasheet 
	 */
	bstat = ephy_regRead(phy, EPHY_01_BMSR);
	bstat = ephy_regRead(phy, EPHY_01_BMSR);
	adv = ephy_regRead(phy, EPHY_04_ANAR);
	lpa = ephy_regRead(phy, EPHY_05_ANLPAR);
	pc1 = ephy_regRead(phy, EPHY_1E_PHYCR1);
	pc2 = ephy_regRead(phy, EPHY_1F_PHYCR2);
	speed = ephy_linkSpeed(phy, &full_duplex);

	int linkup = (bstat & (1u << 2)) != 0;

	if (phy->link_state_callback != NULL) {
		phy->link_state_callback(phy->link_state_callback_arg, linkup);
	}

	printf("lwip: ephy%u.%u link is %s %uMbps/%s (ctl %04x, status %04x, adv %04x, lpa %04x, pctl %04x,%04x)\n",
			phy->bus, phy->addr, linkup ? "UP  " : "DOWN", speed, (full_duplex != 0) ? "Full" : "Half",
			bctl, bstat, adv, lpa, pc1, pc2);
}


int ephy_linkSpeed(eth_phy_state_t *phy, int *full_duplex)
{
	uint16_t pc1 = ephy_regRead(phy, EPHY_1E_PHYCR1);

	if ((pc1 & 0x7) == 0) { /* PHY still in auto-negotiation */
		return 0;
	}

	if (full_duplex != NULL) {
		*full_duplex = !!(pc1 & (1u << 2));
	}

	return ((pc1 & 0x1) != 0) ? 10 : 100;
}


static void ephy_restartAN(eth_phy_state_t *phy)
{
	/* adv: no-next-page, no-rem-fault, no-pause, no-T4, 100M/10M-FD & 10M-HD, 802.3 */
	ephy_regWrite(phy, EPHY_04_ANAR, (1u << 8) | (1u << 6) | (1u << 5) | 1u);
	/* 100M-FD, AN, restart-AN */
	ephy_regWrite(phy, EPHY_00_BMCR, (1u << 13) | (1u << 12) | (1u << 9) | (1u << 8));
}


static void ephy_linkThread(void *arg)
{
	eth_phy_state_t *phy = arg;
	uint16_t stat;
	int err;

	for (;;) {
		err = gpio_wait(&phy->irq_gpio, 1, 0);
		// FIXME: thread exit

		if (err == 0) {
			stat = ephy_regRead(phy, EPHY_1B_ICSR);
			if ((stat & 0xFF) != 0) {
				ephy_setLinkState(phy);
			}
		}
	}

	printf("lwip ephy%u.%u thread finished.\n", phy->bus, phy->addr);
	endthread();
}


/* ARGS: pfx[-]n:/dev/gpioX[:...] */
static char *ephy_parsePinArg(char *cfg, const char *pfx, size_t pfx_len, gpio_info_t *gp, unsigned flags)
{
	char *p;
	int err;

	if (strncmp(pfx, cfg, pfx_len) != 0) {
		return cfg;
	}

	cfg += pfx_len;

	p = strchr(cfg, ':');
	if (p == NULL) {
		printf("lwip: ephy: %s missing pin GPIO node\n", pfx);
		return cfg - pfx_len;
	}
	p = strchr(p + 1, ':');
	if (p != NULL) {
		*p++ = 0;
	}

	err = gpio_init(gp, cfg, flags);
	if (err != 0) {
		printf("lwip: ephy: %s bad pin info: %s (%d)\n", pfx, strerror(-err), err);
		return cfg - pfx_len;
	}

	return p;
}


/* printf("This is an Ethernet PHY driver. use: %s id mdio-bus phy-addr [irq=[-]n,/dev/gpio/X] [reset=[-]n,/dev/gpio/X]\n", argv[0]); */
/* ARGS: [bus.]id[:reset:[-]n:/dev/gpioX][:irq:[-]n:/dev/gpioX] */
static int ephy_config(eth_phy_state_t *phy, char *cfg)
{
	char *p;

	if (*cfg == '\0') {
		return -EINVAL;
	}

	phy->addr = strtoul(cfg, &p, 0);
	if (*p == '.') {
		phy->bus = phy->addr;
		cfg = ++p;

		if (*cfg == '\0') {
			return -EINVAL;
		}

		phy->addr = strtoul(cfg, &p, 0);
	}
	else {
		phy->bus = 0;
	}

	if ((phy->addr & ~NETDEV_MDIO_ADDR_MASK) != 0) {
		printf("lwip: ephy: bad PHY address: 0x%x (valid bits: 0x%x)\n", phy->addr, NETDEV_MDIO_ADDR_MASK);
		return -EINVAL;
	}

	if (*p == '\0') {
		return 0;
	}

	if (*p++ != ':') {
		return -EINVAL;
	}

	while (p != NULL && *p != '\0') {
		cfg = p;

		p = ephy_parsePinArg(p, "irq:", 4, &phy->irq_gpio, GPIO_INPUT);
		if (p == cfg) {
			p = ephy_parsePinArg(p, "reset:", 6, &phy->reset, GPIO_OUTPUT | GPIO_ACTIVE);
		}
		if (p == cfg) {
			printf("lwip: ephy: unparsed args: %s\n", cfg);
			return -EINVAL;
		}
	}

	return 0;
}


/* toggle MACPHY internal loopback for test mode */
int ephy_enableLoopback(eth_phy_state_t *phy, bool enable)
{
	uint16_t bmcr = ephy_regRead(phy, EPHY_00_BMCR);
	uint16_t phy_ctrl2 = ephy_regRead(phy, EPHY_1F_PHYCR2);

	if (enable) {
		/* disable auto-negotiation, enable: full-duplex, 100Mbps, loopback mode */
		bmcr = (bmcr & ~(1u << 12)) | (1u << 8) | (1u << 13) | (1u << 14);
		/* force link up, disable transmitter */
		phy_ctrl2 |= (1u << 11) | (1u << 3);
	}
	else {
		bmcr = (bmcr & ~((1u << 8) | (1u << 13) | (1u << 14))) | (1u << 12);
		phy_ctrl2 &= ~((1u << 11) | (1u << 3));
	}

	ephy_regWrite(phy, EPHY_00_BMCR, bmcr);
	ephy_regWrite(phy, EPHY_1F_PHYCR2, phy_ctrl2);

	if (ephy_regRead(phy, EPHY_00_BMCR) != bmcr) {
		printf("lwip: ephy: failed to set loopback mode\n");
		return -1;
	}

	if (ephy_regRead(phy, EPHY_1F_PHYCR2) != phy_ctrl2) {
		printf("lwip: ephy: failed to force link up\n");
		return -1;
	}

	return 0;
}


/* Try to set alternative MAC PHY config (alternative configurations within the same PHY ID).
 * returns:
 *   > 0 if alternative config has been set
 *     0 if no alternative config with this ID
 *   < 0 if alternative config setting has failed
 */
static int ephy_setAltConfig(eth_phy_state_t *phy, int cfg_id)
{
	/* NOTE: assuming KSZ8081 RNA/RND/RNB PHY! */

	/* CFG id:
	 * 0: KSZ8081 RND with 50 MHz RMII input clock (PHY_CTRL2[7] = 0)
	 * 1: KSZ8081 RNA/RNB with 50 MHz RMII input clock (PHY_CTRL2[7] = 1)
	 */


	/* try to set alternative MII clock frequency */
	uint16_t phy_ctrl2 = ephy_regRead(phy, EPHY_1F_PHYCR2);

	if (cfg_id == 0) {
		phy_ctrl2 &= ~(1 << 7);
	}
	else if (cfg_id == 1) {
		phy_ctrl2 |= (1 << 7);
	}
	else {
		return 0; /* unknown config ID */
	}

	ephy_regWrite(phy, EPHY_1F_PHYCR2, phy_ctrl2);
	if (ephy_regRead(phy, EPHY_1F_PHYCR2) != phy_ctrl2) {
		printf("lwip: ephy: failed to set clock\n");
		return -1;
	}

	return 1;
}


int ephy_init(eth_phy_state_t *phy, char *conf, uint8_t board_rev, link_state_cb_t cb, void *cb_arg)
{
	(void)board_rev;
	uint32_t phyid;
	int err;

	memset(phy, 0, sizeof(*phy));

	err = ephy_config(phy, conf);
	if (err != 0) {
		printf("lwip: ephy: Couldn't configure PHY: %s (%d)\n", strerror(-err), err);
		return -EINVAL;
	}

	/* for KSZ8081RNA/D, KSZ8081RNB:
	 * MDC max. 10MHz, std. 2.5MHz
	 * MDIO hold min. 10 ns
	 * preamble mandatory
	 */

	phy->reset_hold_time_us = 500 /* us */;
	phy->reset_release_time_us = 100 /* us */;

	err = mdio_setup(phy->bus, 2500 /* kHz */, 10 /* ns */, 0 /* with-preamble */);
	if (err != 0) {
		return err;
	}

	ephy_reset(phy);

	phyid = ephy_readPhyId(phy);
	if (phyid == 0u || phyid == ~0u) {
		gpio_set(&phy->reset, 1);
		return -ENODEV;
	}

	// FIXME: check phyid

	/* make address 0 not broadcast, disable NAND-tree mode */
	ephy_regWrite(phy, EPHY_16_OMSOR, (1u << 1) | (1u << 9));

	ephy_setAltConfig(phy, 0); /* KSZ8081 RND - default config */

#ifdef LWIP_EPHY_INIT_HOOK
	LWIP_EPHY_INIT_HOOK(phy, phyid, board_rev);
#endif

#if defined(EPHY_KSZ8081RNA)
	ephy_setAltConfig(phy, 1);
#elif defined(EPHY_KSZ8081RND)
	ephy_setAltConfig(phy, 0);
#endif

	phy->link_state_callback = cb;
	phy->link_state_callback_arg = cb_arg;
	ephy_setLinkState(phy);

	if (gpio_valid(&phy->irq_gpio)) {
		err = beginthread(ephy_linkThread, 0, phy->th_stack, sizeof(phy->th_stack), phy);
		if (err != 0) {
			gpio_set(&phy->reset, 1);
			return err;
		}

		/* enable link up/down IRQ signal */
		ephy_regWrite(phy, EPHY_1B_ICSR, (1u << 8) | (1u << 10));
	}

	ephy_restartAN(phy);

	return 0;
}
