/*
 * Phoenix-RTOS --- networking stack
 *
 * Ethernet PHY common routines
 *
 * Copyright 2018, 2024, 2026 Phoenix Systems
 * Author: Michal Miroslaw, Julian Uziemblo
 *
 * %LICENSE%
 */
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/list.h>
#include <sys/threads.h>

#include "netif-driver.h"

#include "../mac.h"
#include "ephy-driver.h"


static ephy_driver_t *ephy_drivers = NULL;


void ephy_driverRegister(ephy_driver_t *driver)
{
	assert(driver->enable_irq != NULL);
	assert(driver->link_speed != NULL);
	LIST_ADD(&ephy_drivers, driver);
}


static inline size_t ephy_driverStrcmp(const char *drvName, const char *name)
{
	size_t i = 0;
	while (drvName[i] != '\0' && name[i] != '\0' && tolower((unsigned char)drvName[i]) == tolower((unsigned char)name[i])) {
		i++;
	}
	return drvName[i] == '\0' ? i : 0;
}


/* match longest prefix (case-insensitive) */
static ephy_driver_t *ephy_driverFind(const char *name)
{
	size_t match, bestMatch = 0;
	ephy_driver_t *bestDriver = NULL, *driver = ephy_drivers;

	if (driver != NULL) {
		do {
			match = ephy_driverStrcmp(driver->name, name);
			if (match > bestMatch) {
				bestMatch = match;
				bestDriver = driver;
			}
		} while ((driver = driver->next) != ephy_drivers);
	}

	return bestDriver;
}


uint16_t ephy_regRead(const eth_phy_state_t *phy, uint16_t reg)
{
	return mdio_read(phy->bus, phy->addr, reg);
}


void ephy_regWrite(const eth_phy_state_t *phy, uint16_t reg, uint16_t val)
{
	mdio_write(phy->bus, phy->addr, reg, val);
}


uint16_t ephy_mmdRead(const eth_phy_state_t *phy, uint16_t devad, uint16_t addr)
{
	ephy_regWrite(phy, EPHY_MMD_0D_MACR, devad);
	ephy_regWrite(phy, EPHY_MMD_0E_MAADR, addr);
	ephy_regWrite(phy, EPHY_MMD_0D_MACR, 1U << 14 | devad);
	return ephy_regRead(phy, EPHY_MMD_0E_MAADR);
}


void ephy_mmdWrite(const eth_phy_state_t *phy, uint16_t devad, uint16_t addr, uint16_t val)
{
	ephy_regWrite(phy, EPHY_MMD_0D_MACR, devad);
	ephy_regWrite(phy, EPHY_MMD_0E_MAADR, addr);
	ephy_regWrite(phy, EPHY_MMD_0D_MACR, 1U << 14 | devad);
	ephy_regWrite(phy, EPHY_MMD_0E_MAADR, val);
}


static void ephy_softReset(const eth_phy_state_t *phy)
{
	uint16_t res;
	int retries = 10;

	ephy_debug_printf(phy, "ephy_reset: start software reset...");

	ephy_regWrite(phy, EPHY_COMMON_00_BMCR, 1U << 15);
	usleep(phy->driver->properties.reset.releaseTimeUs);

	while (retries-- > 0) {
		res = ephy_regRead(phy, EPHY_COMMON_00_BMCR);
		if ((res & (1U << 15)) == 0) {
			return;
		}
	}

	ephy_printf(phy, "soft-reset timed out");
}


static void ephy_reset(const eth_phy_state_t *phy)
{
	if (gpio_valid(&phy->resetGpio)) {
		ephy_debug_printf(phy, "ephy_reset: start hardware reset...");
		// TODO: prepare bootstrap pins
		gpio_set(&phy->resetGpio, 1);
		usleep(phy->driver->properties.reset.holdTimeUs);
		mdio_lock_bus(phy->bus);
		gpio_set(&phy->resetGpio, 0);
		usleep(phy->driver->properties.reset.releaseTimeUs);
		mdio_unlock_bus(phy->bus);
		ephy_debug_printf(phy, "ephy_reset: hardware reset complete.");
	}
	else {
		ephy_softReset(phy);
	}
}


static uint32_t ephy_readPhyId(const eth_phy_state_t *phy)
{
	uint32_t phyid = 0;
	uint16_t ret;

	ret = ephy_regRead(phy, EPHY_COMMON_02_PHYID1);
	phyid = (uint32_t)ret << 16;

	ret = ephy_regRead(phy, EPHY_COMMON_03_PHYID2);
	phyid |= (uint32_t)ret;

	return phyid;
}


static void ephy_setLinkState(const eth_phy_state_t *phy)
{
	uint16_t bctl, bstat, adv, lpa;
	enum eth_linkSpeed speed;
	enum eth_duplex duplex;

	bctl = ephy_regRead(phy, EPHY_COMMON_00_BMCR);
	/*
	 * NOTE: "[Bit 2 of BMSR] indicates whether the link was
	 * lost since the last read. For the current link status,
	 * read this register twice." - RTL8201FI-VC-CG datasheet
	 */
	bstat = ephy_regRead(phy, EPHY_COMMON_01_BMSR);
	bstat = ephy_regRead(phy, EPHY_COMMON_01_BMSR);
	adv = ephy_regRead(phy, EPHY_COMMON_04_ANAR);
	lpa = ephy_regRead(phy, EPHY_COMMON_05_ANLPAR);

	if (phy->driver->link_speed(phy, &speed, &duplex) < 0) {
		speed = eth_linkSpeed_unknown;
		duplex = eth_duplexHalf;
	}

	bool linkup = (bstat & (1U << 2)) != 0;

	mac_setLinkState(phy->netif, linkup);

	ephy_printf(phy, "link is %s %uMbps/%s (ctl %04x, status %04x, adv %04x, lpa %04x)",
			linkup ? "UP  " : "DOWN", speed, (duplex == eth_duplexFull) ? "Full" : "Half",
			bctl, bstat, adv, lpa);
}


static inline uint16_t ephy_bmcrMaxSpeedMask(const eth_phy_state_t *phy)
{
	switch (phy->driver->properties.maxSpeed) {
		case eth_linkSpeed_100M:
			return 1U << 13;
		case eth_linkSpeed_1G:
			return 1U << 6;
		case eth_linkSpeed_10M:
		default:
			return 0U;
	}
}


static void ephy_restartAN(const eth_phy_state_t *phy)
{
	/* max speed, enable AN, restart AN, full-duplex */
	uint16_t bmcr = ephy_bmcrMaxSpeedMask(phy) | (1U << 12) | (1U << 9) | (1U << 8);

	/* standard adv: no-next-page, no-rem-fault, no-pause, no-T4, 100M/10M-FD & 10M-HD, 802.3 */
	ephy_regWrite(phy, EPHY_COMMON_04_ANAR, (1U << 8) | (1U << 6) | (1U << 5) | 1U);

	if (phy->driver->properties.maxSpeed >= eth_linkSpeed_1G) {
		/* gigabit adv: 1000M-FD */
		ephy_regWrite(phy, EPHY_COMMON_09_GBCR, (1U << 9));
	}

	if (phy->driver->config_adv != NULL) {
		(void)phy->driver->config_adv(phy);
	}

	ephy_regWrite(phy, EPHY_COMMON_00_BMCR, bmcr);
}


static void ephy_linkThread(void *arg)
{
	eth_phy_state_t *phy = arg;
	int err;

	for (;;) {
		err = gpio_wait(&phy->irqGpio, 1, 0);
		if (err < 0) {
			ephy_printf(phy, "IRQ GPIO wait failed: %s (%d)", strerror(-err), -err);
			break;
		}

		ephy_handleInterrupt(phy);
	}

	ephy_printf(phy, "thread finished.");
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
		*p = 0;
		p++;
	}

	err = gpio_init(gp, cfg, flags);
	if (err != 0) {
		printf("lwip: ephy: %s bad pin info: %s (%d)\n", pfx, strerror(-err), err);
		return cfg - pfx_len;
	}

	return p;
}


static int ephy_parseConfig(eth_phy_state_t *phy, char *cfg)
{
	char *name, *p;

	if (*cfg == '\0') {
		return -EINVAL;
	}

#if defined(EPHY_KSZ8081RNA)
	name = "ksz8081rna";
#elif defined(EPHY_KSZ8081RNB)
	name = "ksz8081rnb";
#elif defined(EPHY_KSZ8081RND)
	name = "ksz8081rnd";
#else
	p = strchr(cfg, ':');
	if (p == NULL) {
		return -EINVAL;
	}

	*p = '\0';
	name = cfg;
	cfg = p + 1;
#endif

	phy->driver = ephy_driverFind(name);
	if (phy->driver == NULL) {
		fprintf(stderr, "lwip: ephy: driver \"%s\" is not supported\n", name);
		return -ENOENT;
	}

	phy->addr = strtoul(cfg, &p, 0);

	if (*p == '.') {
		phy->bus = phy->addr;
		p++;
		cfg = p;

		if (*cfg == '\0') {
			return -EINVAL;
		}

		phy->addr = strtoul(cfg, &p, 0);
	}
	else {
		fprintf(stderr, "lwip: ephy: WARN: setting default bus 0\n");
		phy->bus = 0;
	}

	if ((phy->addr & ~NETDEV_MDIO_ADDR_MASK) != 0) {
		fprintf(stderr, "lwip: ephy: bad PHY address: 0x%x (valid bits: 0x%x)\n", phy->addr, NETDEV_MDIO_ADDR_MASK);
		return -EINVAL;
	}

	if (*p != ':') {
		return -EINVAL;
	}
	p++;

	phy->irqtype = ephy_irqGpio;

	while (p != NULL && *p != '\0') {
		cfg = p;

		if (strcmp(p, "irq:MAC") == 0) {
			phy->irqtype = ephy_irqMac;
			p = NULL;
			break;
		}
		else if (strncmp(p, "irq:MAC:", 8) == 0) {
			phy->irqtype = ephy_irqMac;
			p += 8;
			continue;
		}
		else {
			/* MISRA */
		}

		p = ephy_parsePinArg(p, "irq:", 4, &phy->irqGpio, GPIO_INPUT);
		if (p == cfg) {
			p = ephy_parsePinArg(p, "reset:", 6, &phy->resetGpio, GPIO_OUTPUT | GPIO_ACTIVE);
		}
		if (p == cfg) {
			fprintf(stderr, "lwip: ephy: unparsed args: %s\n", cfg);
			return -EINVAL;
		}
	}

	return 0;
}


void ephy_handleInterrupt(const eth_phy_state_t *phy)
{
	uint16_t stat;

	/* function should not be called before ePHY is successfully initialized */
	assert(phy != NULL && phy->driver != NULL);

	stat = ephy_regRead(phy, phy->driver->properties.irq.reg);
	if ((stat & phy->driver->properties.irq.mask) != 0) {
		ephy_setLinkState(phy);
	}
}


int ephy_linkSpeed(const eth_phy_state_t *phy, int *full_duplex)
{
	enum eth_linkSpeed speed;
	enum eth_duplex duplex;

	/* function should not be called before ePHY is successfully initialized */
	assert(phy != NULL && phy->driver != NULL);

	if (phy->driver->link_speed(phy, &speed, &duplex) < 0) {
		return 0;
	}

	if (full_duplex != NULL) {
		*full_duplex = duplex;
	}

	return speed;
}


int ephy_enableLoopback(const eth_phy_state_t *phy, bool enable)
{
	uint16_t bmcr = ephy_regRead(phy, EPHY_COMMON_00_BMCR);
	bool loopbackEnabled = (bmcr & (1U << 14)) != 0U;

	if (loopbackEnabled == enable) {
		return 0;
	}

	if (enable) {
		/* disable AN */
		bmcr &= ~(1U << 12);
		/* full-duplex */
		bmcr |= 1U << 8;
		bmcr |= ephy_bmcrMaxSpeedMask(phy);
	}

	/* loopback */
	bmcr = enable ?
			(bmcr | (1U << 14)) :
			(bmcr & ~(1U << 14));
	ephy_regWrite(phy, EPHY_COMMON_00_BMCR, bmcr);

	if (!enable) {
		ephy_restartAN(phy);
	}

	ephy_debug_printf(phy, "loopback %s", enable ? "enabled" : "disabled");
	return 0;
}


/* ARGS: [model:][bus.]addr[:reset:[-]n:/dev/gpioX][:irq:{MAC|[-]n:/dev/gpioX}] */
int ephy_init(eth_phy_state_t *phy, char *conf, uint8_t boardRev, struct netif *netif)
{
	memset(phy, 0, sizeof(*phy));

	phy->netif = netif;
	phy->boardRev = boardRev;

	int err = ephy_parseConfig(phy, conf);
	if (err < 0) {
		return err;
	}

	err = mdio_setup(phy->bus, 2500 /* kHz */, 10 /* ns */, 0 /* with-preamble */);
	if (err != 0) {
		ephy_printf(phy, "Couldn't init MDIO: %s (%d)", strerror(-err), err);
		return err;
	}

	ephy_reset(phy);

	phy->phyid = ephy_readPhyId(phy);
	if (phy->phyid == 0U || phy->phyid == ~0U) {
		ephy_printf(phy, "Couldn't read PHY ID");
		gpio_set(&phy->resetGpio, 1);
		return -ENODEV;
	}

	ephy_debug_printf(phy, "ID: 0x%x", phy->phyid);

	if (phy->driver->specific_setup != NULL) {
		err = phy->driver->specific_setup(phy);
		if (err < 0) {
			ephy_printf(phy, "init failed: %s (%d)", strerror(-err), -err);
			gpio_set(&phy->resetGpio, 1);
			return err;
		}
	}

	ephy_setLinkState(phy);

	if (phy->irqtype == ephy_irqGpio) {
		if (!gpio_valid(&phy->irqGpio)) {
			ephy_printf(phy, "Interrupt GPIO invalid, could not start PHY IRQ thread");
			return -ENODEV;
		}
		err = beginthread(ephy_linkThread, 0, phy->stack, sizeof(phy->stack), phy);
		if (err != 0) {
			gpio_set(&phy->resetGpio, 1);
			return err;
		}
	}

	(void)phy->driver->enable_irq(phy, true);

	ephy_restartAN(phy);

	ephy_debug_printf(phy, "Successfully initialized PHY");

	return 0;
}
