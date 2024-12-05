/*
 * Phoenix-RTOS --- networking stack
 *
 * Ethernet PHY common routines
 *
 * Copyright 2018, 2024 Phoenix Systems
 * Author: Michał Mirosław, Julian Uziembło
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

#define EPHY_DEBUG 0

#define ALL_SET(bits, set_mask)     (((bits) & (set_mask)) == (set_mask))
#define ALL_RESET(bits, reset_mask) (((bits) & (reset_mask)) == 0)


/* EPHY common registers */
enum {
	EPHY_00_BMCR = 0x00, /* Basic Mode Control */
	EPHY_01_BMSR,        /* Basic Mode Status */
	EPHY_02_PHYID1,      /* PHY Identifier 1 */
	EPHY_03_PHYID2,      /* PHY Identifier 2 */
	EPHY_04_ANAR,        /* Auto-Neg Advertising */
	EPHY_05_ANLPAR,      /* Auto-Neg Link Partner Ability */
	EPHY_06_ANER         /* Auto-Neg Expansion */
};

/* KSZ8081-specific registers */
enum {
	EPHY_07_ANPR = 0x07,      /* Auto-Neg Next Page */
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

/* RTL common registers */
enum {
	EPHY_0D_MACR = 0x0D,   /* MMD Access Ctrl */
	EPHY_0E_MAADR,         /* MMD Access Addr Data */
	EPHY_1F_PAGESEL = 0x1F /* Page Select */
};

/* RTL8201-specific registers */
enum {
	/* Page 0 (default) */
	EPHY_18_PSMR = 0x18,  /* Power Saving Mode */
	EPHY_1C_FMLR = 0x1C,  /* Fiber Mode and Loopback */
	EPHY_1E_IISDR = 0x1E, /* Interrupt Indicators and SNR Display */

	/* Page 4 */
	EPHY_10_ECER = 0x10, /* EEE Capability Enable */
	EPHY_15_EECR = 0x15, /* EEE Capability */

	/* Page 7 */
	EPHY_10_RMSR = 0x10, /* RMII Mode Setting */
	EPHY_11_CLSR,        /* Customised LEDs Setting */
	EPHY_12_ELER,        /* EEE LEDs Enable */
	EPHY_13_IWELFR,      /* Interrupt, WOL Enable and LEDs Function */
	EPHY_14_MTIR,        /* MII TX Isolate */
	EPHY_18_SSCR = 0x18  /* Spread Spectrum Clock Register */
};

/* RTL8211-specific registers */
enum {
	/* Page 0 (default) */
	EPHY_07_ANNPTR = 0x07, /* Auto-Neg Next Page Tx */
	EPHY_08_ANNPRR,        /* Auto-Neg Next Page Rx */
	EPHY_09_GBCR,          /* 1000Base-T Control */
	EPHY_0A_GBSR,          /* 1000Base-T Status */
	EPHY_0F_GBESR = 0x0F,  /* 1000Base-T Ext Status */
	EPHY_12_INER = 0x12,   /* Interrupt Enable */
	EPHY_18_PHYCR1 = 0x18, /* PHY Specific Control 1 */
	EPHY_19_PHYCR2,        /* PHY Specific Control 2 */
	EPHY_1A_PHYSR,         /* PHY Specific Status */
	EPHY_1D_INSR = 0x1D,   /* Interrupt Status */
	EPHY_1E_EXTPAGESEL,    /* (hidden) Ext Page Select */

	/* Page 0xd04 */
	EPHY_10_LCR = 0x10, /* LED Control */
	EPHY_11_EEELCR,     /* EEE LEd Control */

	/* Page 0xa46 */
	EPHY_14_PHYSCR = 0x14, /* PHY Special Config */

	/* Page 0xd08 */
	EPHY_15_MIICR, /* MII Control */

	/* Page 0xd40 */
	EPHY_16_INTBCR, /* INTB Pin Control */
};


#define ephy_printf(phy, fmt, ...) printf("lwip: ephy%u.%u: " fmt "\n", phy->bus, phy->addr, ##__VA_ARGS__)

#if EPHY_DEBUG
#define ephy_debug_printf(phy, ...) ephy_printf(phy, __VA_ARGS__)
#else
#define ephy_debug_printf(...)
#endif


static uint16_t ephy_reg_read(eth_phy_state_t *phy, uint16_t reg)
{
	return mdio_read(phy->bus, phy->addr, reg);
}


static void ephy_reg_write(eth_phy_state_t *phy, uint16_t reg, uint16_t val)
{
	mdio_write(phy->bus, phy->addr, reg, val);
	ephy_reg_read(phy, reg);
}


/* MMD operation: call this function, then read/write MAADR (Reg. 14) */
static void ephy_mmd_io(eth_phy_state_t *phy, uint16_t devad, uint16_t addr)
{
	ephy_reg_write(phy, EPHY_0D_MACR, devad);
	ephy_reg_write(phy, EPHY_0E_MAADR, addr); /* EEEAR */
	ephy_reg_write(phy, EPHY_0D_MACR, (1 << 14) | devad);
}


static void ephy_reset(eth_phy_state_t *phy)
{
	if (gpio_valid(&phy->reset)) {
		ephy_debug_printf(phy, "ephy_reset: start hardware reset...");
		// TODO: prepare bootstrap pins
		gpio_set(&phy->reset, 1);
		usleep(phy->reset_hold_time_us);
		mdio_lock_bus(phy->bus);
		gpio_set(&phy->reset, 0);
		usleep(phy->reset_release_time_us);
		if (phy->model == ephy_rtl8201fi) {
			gpio_set(&phy->reset, 1);
			usleep(phy->reset_hold_time_us);
		}
		mdio_unlock_bus(phy->bus);
		ephy_debug_printf(phy, "ephy_reset: hardware reset complete.");
	}
	else {
		int res = 0, retries = 10;

		ephy_debug_printf(phy, "ephy_reset: start software reset...");

		ephy_reg_write(phy, EPHY_00_BMCR, 1 << 15);
		usleep(phy->reset_release_time_us);

		while (retries-- > 0) {
			res = ephy_reg_read(phy, EPHY_00_BMCR);
			if ((~res & (1 << 15)) != 0) {
				ephy_debug_printf(phy, "ephy_reset: software reset complete.");
				break;
			}
		}

		if ((res & (1 << 15)) != 0) {
			ephy_printf(phy, "soft-reset timed out");
		}
	}
}


static uint32_t ephy_readPhyId(eth_phy_state_t *phy)
{
	uint32_t oui = 0;
	uint32_t phyid = 0;
	uint16_t ret;

	ret = ephy_reg_read(phy, EPHY_02_PHYID1);
	phyid = ret << 16;
	oui |= ret << 2;

	ret = ephy_reg_read(phy, EPHY_03_PHYID2);
	phyid |= ret;
	oui |= (ret & 0xFC00) << (18 - 10);

	/*
		ephy_printf(phy, "id 0x%08x (vendor 0x%06x model 0x%02x rev %u)",
			phyid, oui, (ret >> 4) & 0x3F, ret & 0x0F);
	*/

	if (phy->model <= ephy_ksz8081rnd) {
		oui = ephy_reg_read(phy, EPHY_10_DRCR);
		ret = ephy_reg_read(phy, EPHY_11_AFECR1);
	}

	/*
		ephy_printf(phy, "DigCtl 0x%04x AFECtl1 0x%04x", oui, ret);
	*/

	return phyid;
}


static void ephy_setLinkState(eth_phy_state_t *phy)
{
	uint16_t bctl, bstat, adv, lpa, pc1, pc2;
	int speed, full_duplex;

	bctl = ephy_reg_read(phy, EPHY_00_BMCR);
	bstat = ephy_reg_read(phy, EPHY_01_BMSR);
	bstat = ephy_reg_read(phy, EPHY_01_BMSR);
	adv = ephy_reg_read(phy, EPHY_04_ANAR);
	lpa = ephy_reg_read(phy, EPHY_05_ANLPAR);

	speed = ephy_linkSpeed(phy, &full_duplex);

	int linkup = (bstat & (1 << 2)) != 0;

	if (phy->link_state_callback != NULL) {
		phy->link_state_callback(phy->link_state_callback_arg, linkup);
	}

	switch (phy->model) {
		case ephy_ksz8081rnab:
		case ephy_ksz8081rnd:
			pc1 = ephy_reg_read(phy, EPHY_1E_PHYCR1);
			pc2 = ephy_reg_read(phy, EPHY_1F_PHYCR2);
			ephy_printf(phy, "link is %s %uMbps/%s (ctl %04x, status %04x, adv %04x, lpa %04x, pctl %04x,%04x)",
					linkup ? "UP  " : "DOWN", speed, full_duplex ? "Full" : "Half", bctl, bstat, adv, lpa, pc1, pc2);
			break;
		case ephy_rtl8201fi:
			ephy_printf(phy, "link is %s %uMbps/%s (ctl %04x, status %04x, adv %04x, lpa %04x)",
					linkup ? "UP  " : "DOWN", speed, full_duplex ? "Full" : "Half", bctl, bstat, adv, lpa);
			break;
		case ephy_rtl8211fdi:
			pc1 = ephy_reg_read(phy, EPHY_18_PHYCR1);
			pc2 = ephy_reg_read(phy, EPHY_19_PHYCR2);
			ephy_printf(phy, "link is %s %uMbps/%s (ctl %04x, status %04x, adv %04x, lpa %04x, pctl %04x,%04x)",
					linkup ? "UP  " : "DOWN", speed, full_duplex ? "Full" : "Half", bctl, bstat, adv, lpa, pc1, pc2);
			break;
		default:
			/* unreachable */
			break;
	}
}


static inline int ephy_ksz8081rnx_linkSpeed(eth_phy_state_t *phy, int *full_duplex)
{
	uint16_t pc1 = ephy_reg_read(phy, EPHY_1E_PHYCR1);

	if ((pc1 & 7) == 0) { /* PHY still in auto-negotiation */
		return 0;
	}

	if (full_duplex != NULL) {
		*full_duplex = pc1 & (1 << 2); /* full-duplex mode (KSZ8081MNX/RNB manual, p. 50) */
	}

	return ((pc1 & 1) != 0) ? 10 : 100;
}


static inline int ephy_rtl8201fi_linkSpeed(eth_phy_state_t *phy, int *full_duplex)
{
	uint16_t bmcr = ephy_reg_read(phy, EPHY_00_BMCR);

	if (full_duplex != NULL) {
		*full_duplex = bmcr & (1 << 8); /* full-duplex mode */
	}

	return ((bmcr & (1 << 13)) == 0) ? 10 : 100;
}


static inline int ephy_rtl8211fdi_linkSpeed(eth_phy_state_t *phy, int *full_duplex)
{
	uint16_t physr = ephy_reg_read(phy, EPHY_1A_PHYSR);
	uint16_t speed;

	if (full_duplex != NULL) {
		*full_duplex = physr & (1 << 3); /* full-duplex mode */
	}

	speed = (physr >> 4) & 0x3;

	switch (speed) {
		case 0x0:
			return 10;
		case 0x1:
			return 100;
		case 0x2:
			return 1000;
		default:
			return 0;
	}
}


int ephy_linkSpeed(eth_phy_state_t *phy, int *full_duplex)
{
	switch (phy->model) {
		case ephy_ksz8081rnab:
		case ephy_ksz8081rnd:
			return ephy_ksz8081rnx_linkSpeed(phy, full_duplex);
		case ephy_rtl8201fi:
			return ephy_rtl8201fi_linkSpeed(phy, full_duplex);
		case ephy_rtl8211fdi:
			return ephy_rtl8211fdi_linkSpeed(phy, full_duplex);
		default:
			/* unreachable */
			return 0;
	}
}


static void ephy_restart_an(eth_phy_state_t *phy)
{
	/* 100M-FD, AN, restart-AN */
	uint16_t bmcr = (1 << 13) | (1 << 12) | (1 << 9) | (1 << 8);
	if (phy->model == ephy_rtl8211fdi) {
		/* adv: 1000M-FD */
		bmcr = (bmcr & ~(1 << 13)) | (1 << 6);
		ephy_reg_write(phy, EPHY_09_GBCR, (1 << 9));
		/* don't adv: 1000Base-T EEE (MMD write) */
		ephy_mmd_io(phy, 0x7, 0x3c); /* EEEAR */
		ephy_reg_write(phy, EPHY_0E_MAADR, 0);
	}
	/* adv: no-next-page, no-rem-fault, no-pause, no-T4, 100M/10M-FD & 10M-HD, 802.3 */
	ephy_reg_write(phy, EPHY_04_ANAR, (1 << 8) | (1 << 6) | (1 << 5) | 1);
	ephy_reg_write(phy, EPHY_00_BMCR, bmcr);
}


/* link-detect thread */
static void ephy_link_thread(void *arg)
{
	eth_phy_state_t *phy = arg;
	uint16_t stat, irq_reg, irq_mask;
	int err;

	switch (phy->model) {
		case ephy_ksz8081rnab:
		case ephy_ksz8081rnd:
			irq_reg = EPHY_1B_ICSR;
			irq_mask = 0xFF;
			break;
		case ephy_rtl8201fi:
			irq_reg = EPHY_1E_IISDR;
			irq_mask = 0xE800;
			break;
		case ephy_rtl8211fdi:
			irq_reg = EPHY_1D_INSR;
			irq_mask = 0x06BD;
			break;
		default:
			/* unreachable */
			endthread();
			return;
	}

	for (;;) {
		err = gpio_wait(&phy->irq_gpio, 1, 0);
		// FIXME: thread exit

		if (err == 0) {
			stat = ephy_reg_read(phy, irq_reg);
			if ((stat & irq_mask) != 0) {
				ephy_setLinkState(phy);
			}
		}
	}

	ephy_printf(phy, "thread finished.");
	endthread();
}


/* ARGS: pfx[-]n:/dev/gpioX[:...] */
static char *parse_pin_arg(char *cfg, const char *pfx, size_t pfx_len, gpio_info_t *gp, unsigned flags)
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
		printf("lwip: ephy: %s bad pin info: %s (%d)\n", pfx, strerror(err), err);
		return cfg - pfx_len;
	}

	return p;
}


/* printf("This is an Ethernet PHY driver. use: %s model id mdio-bus phy-addr [irq=[-]n,/dev/gpio/X] [reset=[-]n,/dev/gpio/X]\n", argv[0]); */
/* ARGS: model:[bus.]id[:reset:[-]n:/dev/gpioX][:irq:[-]n:/dev/gpioX] */
static int ephy_config(eth_phy_state_t *phy, char *cfg)
{
	char *p;

	if (*cfg == '\0') {
		return -EINVAL;
	}

	phy->addr = strtoul(cfg, &p, 0);
	if (cfg != p) {
		return -EINVAL;
	}

	if (strncmp(p, "ksz8081rn", 9) == 0) {
		if (p[9] == 'a' || p[9] == 'b') {
			phy->model = ephy_ksz8081rnab;
		}
		else if (p[9] == 'd') {
			phy->model = ephy_ksz8081rnd;
		}
		else {
			printf("lwip: ephy: unsupported PHY model: `ksz8081rn%c`\n", p[9]);
			return -EINVAL;
		}
	}
	else if (strncmp(p, "rtl8201fi", 9) == 0) {
		phy->model = ephy_rtl8201fi;
	}
	else if (strncmp(p, "rtl8211fdi", 10) == 0) {
		phy->model = ephy_rtl8211fdi;
	}
	else {
		p = strchr(cfg, ':');
		if (p == NULL) {
			return -EINVAL;
		}
		*p = '\0';
		printf("lwip: ephy: unsupported PHY model: `%s`\n", cfg);
		return -EINVAL;
	}

	p = strchr(cfg, ':');
	if (p == NULL) {
		return -EINVAL;
	}
	*p = '\0';
#if EPHY_DEBUG
	printf("lwip: ephy: model=`%s`\n", cfg);
#endif
	cfg = ++p;

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
#if EPHY_DEBUG
		printf("lwip: ephy: WARN: setting default bus 0\n");
#endif
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

		p = parse_pin_arg(p, "irq:", 4, &phy->irq_gpio, GPIO_INPUT);
		if (p == cfg) {
			p = parse_pin_arg(p, "reset:", 6, &phy->reset, GPIO_OUTPUT | GPIO_ACTIVE);
		}
		if (p == cfg) {
			printf("lwip: ephy: unparsed args: %s\n", cfg);
			return -EINVAL;
		}
	}

	return 0;
}


static inline int ephy_ksz8081rnx_enableLoopback(eth_phy_state_t *phy, bool enable)
{
	uint16_t bmcr = ephy_reg_read(phy, EPHY_00_BMCR);
	uint16_t phy_ctrl2 = ephy_reg_read(phy, EPHY_1F_PHYCR2);

	if (enable) {
		/* disable auto-negotiation, enable: full-duplex, 100Mbps, loopback mode */
		bmcr = (bmcr & ~(1 << 12)) | (1 << 8) | (1 << 13) | (1 << 14);
		/* force link up, disable transmitter */
		phy_ctrl2 |= (1 << 11) | (1 << 3);
	}
	else {
		bmcr = (bmcr & ~((1 << 8) | (1 << 13) | (1 << 14))) | (1 << 12);
		phy_ctrl2 &= ~((1 << 11) | (1 << 3));
	}

	ephy_reg_write(phy, EPHY_00_BMCR, bmcr);
	ephy_reg_write(phy, EPHY_1F_PHYCR2, phy_ctrl2);

	if (ephy_reg_read(phy, EPHY_00_BMCR) != bmcr) {
		ephy_printf(phy, "failed to set loopback mode");
		return -1;
	}

	if (ephy_reg_read(phy, EPHY_1F_PHYCR2) != phy_ctrl2) {
		ephy_printf(phy, "failed to force link up");
		return -1;
	}

	ephy_debug_printf(phy, "loopback %s", enable ? "enabled" : "disabled");

	return 0;
}


static inline int ephy_rtl8201fi_enableLoopback(eth_phy_state_t *phy, bool enable)
{
	uint16_t bmcr = ephy_reg_read(phy, EPHY_00_BMCR);

	if (enable) {
		/* disable auto-negotiation, enable: full-duplex, 100Mbps, loopback mode */
		bmcr = (bmcr & ~(1 << 12)) | (1 << 8) | (1 << 13) | (1 << 14);
	}
	else {
		bmcr = (bmcr & ~((1 << 8) | (1 << 13) | (1 << 14))) | (1 << 12);
	}

	ephy_reg_write(phy, EPHY_00_BMCR, bmcr);
	bmcr = ephy_reg_read(phy, EPHY_00_BMCR);

	bool loopback_fail = (enable) ?
			!(ALL_SET(bmcr, (1 << 8) | (1 << 13) | (1 << 14)) && ALL_RESET(bmcr, (1 << 12))) :
			!(ALL_SET(bmcr, (1 << 12)) && ALL_RESET(bmcr, (1 << 14)));

	if (loopback_fail) {
		ephy_printf(phy, "failed to set loopback mode");
		return -1;
	}

	usleep(phy->reset_release_time_us);

	return 0;
}


static inline int ephy_rtl8211fdi_enableLoopback(eth_phy_state_t *phy, bool enable)
{
	uint16_t bmcr = ephy_reg_read(phy, EPHY_00_BMCR);

	ephy_reg_write(phy, EPHY_00_BMCR, (1 << 15));
	while ((ephy_reg_read(phy, EPHY_00_BMCR) & (1 << 15)) != 0) {
		usleep(100);
	}

	if (enable) {
		/* disable auto-negotiation, enable: full-duplex, 1000Mbps, loopback mode, transmit without link-ok */
		bmcr = (bmcr & ~((1 << 12) | (1 << 13))) | (1 << 14) | (1 << 8) | (1 << 6) | (1 << 5);
	}
	else {
		bmcr = (bmcr & ~((1 << 5) | (1 << 6) | (1 << 8) | (1 << 14))) | (1 << 13) | (1 << 12);
	}

	ephy_reg_write(phy, EPHY_00_BMCR, bmcr);
	bmcr = ephy_reg_read(phy, EPHY_00_BMCR);

	bool loopback_fail = (enable) ?
			!(ALL_SET(bmcr, (1 << 5) | (1 << 6) | (1 << 8) | (1 << 14)) && ALL_RESET(bmcr, (1 << 12) | (1 << 13))) :
			!(ALL_SET(bmcr, (1 << 12)) && ALL_RESET(bmcr, (1 << 5) | (1 << 14)));

	if (loopback_fail) {
		ephy_printf(phy, "failed to set loopback mode");
		return -1;
	}

	usleep(phy->reset_release_time_us);

	return 0;
}


/* toggle MACPHY internal loopback for test mode */
int ephy_enableLoopback(eth_phy_state_t *phy, bool enable)
{
	switch (phy->model) {
		case ephy_ksz8081rnab:
		case ephy_ksz8081rnd:
			return ephy_ksz8081rnx_enableLoopback(phy, enable);
		case ephy_rtl8201fi:
			return ephy_rtl8201fi_enableLoopback(phy, enable);
		case ephy_rtl8211fdi:
			return ephy_rtl8211fdi_enableLoopback(phy, enable);
		default:
			/* unreachable */
			return -1;
	}
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
	uint16_t phy_ctrl2 = ephy_reg_read(phy, EPHY_1F_PHYCR2);

	if (cfg_id == 0) {
		phy_ctrl2 &= ~(1 << 7);
	}
	else if (cfg_id == 1) {
		phy_ctrl2 |= (1 << 7);
	}
	else {
		return 0; /* unknown config ID */
	}

	ephy_reg_write(phy, EPHY_1F_PHYCR2, phy_ctrl2);
	if (ephy_reg_read(phy, EPHY_1F_PHYCR2) != phy_ctrl2) {
		ephy_printf(phy, "failed to set clock");
		return -1;
	}

	return 1;
}


static inline int ephy_ksz8081rnx_init(eth_phy_state_t *phy, uint8_t board_rev)
{
	/* make address 0 not broadcast, disable NAND-tree mode */
	ephy_reg_write(phy, EPHY_16_OMSOR, (1 << 1) | (1 << 9));

	int err = ephy_setAltConfig(phy, 0); /* KSZ8081 RND - default config */
	if (err <= 0) {
		ephy_printf(phy, "Couldn't set default config");
		return -ENODEV;
	}

#ifdef LWIP_EPHY_INIT_HOOK
	LWIP_EPHY_INIT_HOOK(phy, phyid, board_rev);
#else
	(void)board_rev;
#endif

	switch (phy->model) {
		case ephy_ksz8081rnab:
			ephy_setAltConfig(phy, 1);
			break;
		case ephy_ksz8081rnd:
			ephy_setAltConfig(phy, 0);
			break;
		default:
			/* unreachable */
			break;
	}

	return 0;
}


static inline void ephy_rtl8201fi_init(eth_phy_state_t *phy)
{
	/* RMII mode, TXC output, default tx/rx offset */
	ephy_reg_write(phy, EPHY_1F_PAGESEL, 7);
	ephy_reg_write(phy, EPHY_10_RMSR, (0xff << 4) | (1 << 3));
	ephy_reg_write(phy, EPHY_1F_PAGESEL, 0);
}


static inline void ephy_rtl8211fdi_init(eth_phy_state_t *phy)
{
	/* no addr 0 broadcast, auto-MDI, TX CRS assert, no PHYAD detect, check preamble, no jabber detection, no ALDPS/PLL-OFF  */
	ephy_reg_write(phy, EPHY_18_PHYCR1, (1 << 8) | (1 << 4));
	/* clkout 125MHz, no clkout SSC, no RXC SSC, no EEE, RXC out enabled, clkout out disabled */
	ephy_reg_write(phy, EPHY_19_PHYCR2, (1 << 6));

	/* Pin 31 INTB */
	ephy_reg_write(phy, EPHY_1F_PAGESEL, 0xd40);
	ephy_reg_write(phy, EPHY_16_INTBCR, 0);
	ephy_reg_write(phy, EPHY_1F_PAGESEL, 0xa42);
}


int ephy_init(eth_phy_state_t *phy, char *conf, uint8_t board_rev, link_state_cb_t cb, void *cb_arg)
{
	uint32_t phyid;
	int err;

	memset(phy, 0, sizeof(*phy));

	err = ephy_config(phy, conf);
	if (err != 0) {
		printf("lwip: ephy: Couldn't configure PHY: %s (%d)\n", strerror(err), err);
		return -EINVAL;
	}
	ephy_debug_printf(phy, "PHY configured");

	switch (phy->model) {
		case ephy_ksz8081rnab:
		case ephy_ksz8081rnd:
			phy->reset_hold_time_us = 500 /* us */;
			phy->reset_release_time_us = 100 /* us */;
			break;
		case ephy_rtl8201fi:
			phy->reset_hold_time_us = 150 * 1000 /* 150ms */;
			phy->reset_release_time_us = 10 * 1000 /* 10ms */;
			break;
		case ephy_rtl8211fdi:
			phy->reset_hold_time_us = 10 * 1000 /* 10ms */;
			phy->reset_release_time_us = 3 * 30 * 1000 /* 90ms */;
			break;
		default:
			/* unreachable */
			break;
	}

	/* for KSZ8081RNA/D, KSZ8081RNB:
	 * MDC max. 10MHz, std. 2.5MHz
	 * MDIO hold min. 10 ns
	 * preamble mandatory
	 */
	err = mdio_setup(phy->bus, 2500 /* kHz */, 10 /* ns */, 0 /* with-preamble */);
	if (err != 0) {
		ephy_printf(phy, "Couldn't init MDIO: %s (%d)", strerror(err), err);
		return err;
	}

	ephy_reset(phy);

	phyid = ephy_readPhyId(phy);
	if (phyid == 0u || phyid == ~0u) {
		ephy_printf(phy, "Couldn't read PHY ID");
		gpio_set(&phy->reset, 1);
		return -ENODEV;
	}

	// FIXME: check phyid

	switch (phy->model) {
		case ephy_ksz8081rnab:
		case ephy_ksz8081rnd:
			err = ephy_ksz8081rnx_init(phy, board_rev);
			if (err < 0) {
				return err;
			}
			break;
		case ephy_rtl8201fi:
			ephy_rtl8201fi_init(phy);
			break;
		case ephy_rtl8211fdi:
			ephy_rtl8211fdi_init(phy);
			break;
		default:
			/* unreachable */
			break;
	}

	phy->link_state_callback = cb;
	phy->link_state_callback_arg = cb_arg;
	ephy_setLinkState(phy);

	if (gpio_valid(&phy->irq_gpio)) {
		err = beginthread(ephy_link_thread, 0, phy->th_stack, sizeof(phy->th_stack), phy);
		if (err != 0) {
			gpio_set(&phy->reset, 1);
			return err;
		}

		/* enable link up/down IRQ signal */
		switch (phy->model) {
			case ephy_ksz8081rnab:
			case ephy_ksz8081rnd:
				ephy_reg_write(phy, EPHY_1B_ICSR, (1 << 8) | (1 << 10));
				break;
			case ephy_rtl8201fi:
				ephy_reg_write(phy, EPHY_1F_PAGESEL, 7);
				ephy_reg_write(phy, EPHY_13_IWELFR, ephy_reg_read(phy, EPHY_13_IWELFR) | (1 << 13));
				ephy_reg_write(phy, EPHY_1F_PAGESEL, 0);
				break;
			case ephy_rtl8211fdi:
				ephy_reg_write(phy, EPHY_12_INER, (1 << 4));
				break;
			default:
				/* unreachable */
				break;
		}
	}
	else {
		ephy_printf(phy, "WARN: irq_gpio not valid, could not start PHY IRQ thread");
		return -ENODEV;
	}

	ephy_restart_an(phy);

	ephy_debug_printf(phy, "Successfully initialized PHY");

	return 0;
}
