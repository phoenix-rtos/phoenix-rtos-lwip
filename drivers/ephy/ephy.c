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

#include "ephy-driver.h"
#include "netif-driver.h"

/* adv: no-next-page, no-rem-fault, no-pause, no-T4, 100M/10M-FD & 10M-HD, 802.3 (differs from the reset default) */
#define EPHY_ANAR_ADV  ((1U << 8) | (1U << 6) | (1U << 5) | 1U)
#define EPHY_ANAR_MASK 0x0fffU /* without NP/ACK/RF bits, which some PHYs manage themselves */

#define EPHY_CHECK_PERIOD_US (1000 * 1000)


static ephy_driver_t *ephy_drivers = NULL;


void ephy_driverRegister(ephy_driver_t *driver)
{
	assert(driver->enable_irq != NULL);
	assert(driver->link_speed != NULL);
	LIST_ADD(&ephy_drivers, driver);
}


/* match longest prefix (case-insensitive) */
static inline size_t ephy_drvcmp(const char *drvName, const char *name)
{
	size_t i = 0;
	while (drvName[i] != '\0' && name[i] != '\0' && tolower((unsigned char)drvName[i]) == tolower((unsigned char)name[i])) {
		i++;
	}
	return drvName[i] == '\0' ? i : 0;
}


static ephy_driver_t *ephy_drvFind(const char *name)
{
	size_t match, bestMatch = 0;
	ephy_driver_t *bestDriver = NULL, *driver = ephy_drivers;

	if (driver != NULL) {
		do {
			match = ephy_drvcmp(driver->name, name);
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
	if (net_gpioValid(&phy->resetGpio)) {
		ephy_debug_printf(phy, "ephy_reset: start hardware reset...");
		// TODO: prepare bootstrap pins
		net_gpioSet(&phy->resetGpio, 1);
		usleep(phy->driver->properties.reset.holdTimeUs);
		mdio_lock_bus(phy->bus);
		net_gpioSet(&phy->resetGpio, 0);
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
		speed = eth_linkSpeedUnknown;
		duplex = eth_duplexHalf;
	}

	bool linkup = !phy->absent && (bstat & (1U << 2)) != 0;

	if (phy->lsCb != NULL) {
		phy->lsCb(phy->lsCbArg, linkup);
	}

	ephy_printf(phy, "link is %s %uMbps/%s (ctl %04x, status %04x, adv %04x, lpa %04x)",
			linkup ? "UP  " : "DOWN", speed, (duplex == eth_duplexFull) ? "Full" : "Half",
			bctl, bstat, adv, lpa);
}


static inline uint16_t ephy_bmcrMaxSpeedMask(const eth_phy_state_t *phy)
{
	switch (phy->driver->properties.maxSpeed) {
		case eth_linkSpeed100M:
			return 1U << 13;
		case eth_linkSpeed1G:
			return 1U << 6;
		case eth_linkSpeed10M:
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

	if (phy->driver->properties.maxSpeed >= eth_linkSpeed1G) {
		/* gigabit adv: 1000M-FD */
		ephy_regWrite(phy, EPHY_COMMON_09_GBCR, (1U << 9));
	}

	if (phy->driver->config_adv != NULL) {
		(void)phy->driver->config_adv(phy);
	}

	ephy_regWrite(phy, EPHY_COMMON_00_BMCR, bmcr);
}


/* Writes the PHY config (lost on PHY reset), reports the link state and restarts autonegotiation */
static int ephy_configure(const eth_phy_state_t *phy)
{
	int err;

	if (phy->driver->specific_setup != NULL) {
		err = phy->driver->specific_setup(phy);
		if (err < 0) {
			ephy_printf(phy, "init failed: %s (%d)", strerror(-err), -err);
			return err;
		}
	}

	ephy_setLinkState(phy);

	if (phy->driver->enable_irq(phy, true) < 0) {
		/* should we error here? */
		ephy_printf(phy, "WARN: could not enable link status IRQ");
	}

	ephy_restartAN(phy);

	return 0;
}


/* Returns true if the PHY answers on MDIO */
static bool ephy_isResponding(const eth_phy_state_t *phy)
{
	uint16_t id = ephy_regRead(phy, EPHY_COMMON_02_PHYID1);

	return (id != 0U) && (id != 0xffffU);
}


/* Returns false if the PHY is back at its reset defaults (e.g. after a power loss) */
static bool ephy_isConfigured(const eth_phy_state_t *phy)
{
	return (ephy_regRead(phy, EPHY_COMMON_04_ANAR) & EPHY_ANAR_MASK) == EPHY_ANAR_ADV;
}


/* Detects PHY power loss (it raises no IRQ) and restores the PHY config once it's back */
static void ephy_checkPower(eth_phy_state_t *phy)
{
	if (!ephy_isResponding(phy)) {
		if (!phy->absent) {
			phy->absent = true;
			ephy_printf(phy, "PHY not responding");
			ephy_setLinkState(phy);
		}
	}
	else if (!ephy_isConfigured(phy)) {
		ephy_printf(phy, "%s, reconfiguring", phy->absent ? "PHY is back" : "PHY reset detected");
		phy->absent = false;
		ephy_reset(phy);
		/* on failure ANAR stays at the reset default, so it's retried on the next check */
		(void)ephy_configure(phy);
	}
	else if (phy->absent) {
		/* MDIO dropout without a PHY reset: only the link reported as down needs restoring */
		ephy_printf(phy, "PHY is back");
		phy->absent = false;
		ephy_setLinkState(phy);
	}
}


static void ephy_linkThread(void *arg)
{
	eth_phy_state_t *phy = arg;
	int err;

	for (;;) {
		err = net_gpioWait(&phy->irqGpio, 1, EPHY_CHECK_PERIOD_US);
		// FIXME: thread exit

		if (err == 0) {
			ephy_handleInterrupt(phy);
		}
		else if (err == -ETIME) {
			ephy_checkPower(phy);
		}
		else {
			/* don't spin at the highest priority - it would starve everything, the watchdog daemon included */
			ephy_printf(phy, "IRQ GPIO wait failed: %s (%d)", strerror(-err), err);
			usleep(EPHY_CHECK_PERIOD_US);
		}
	}

	ephy_printf(phy, "thread finished.");
	endthread();
}


/* ARGS: pfx[-]n:/dev/gpioX[:...] */
static char *ephy_parsePinArg(char *cfg, const char *pfx, size_t pfx_len, net_gpioInfo_t *gp, unsigned flags)
{
	char *p;
	int err;

	if (strncmp(pfx, cfg, pfx_len) != 0) {
		return cfg;
	}

	cfg += pfx_len;

	p = strchr(cfg, ':');
	if (p == NULL) {
		fprintf(stderr, "lwip: ephy: %s missing pin GPIO node\n", pfx);
		return cfg - pfx_len;
	}
	p = strchr(p + 1, ':');
	if (p != NULL) {
		*p = 0;
		p++;
	}

	err = net_gpioInit(gp, cfg, flags);
	if (err != 0) {
		fprintf(stderr, "lwip: ephy: %s bad pin info: %s (%d)\n", pfx, strerror(-err), err);
		return cfg - pfx_len;
	}

	return p;
}


static int ephy_parseConfig(eth_phy_state_t *phy, char *cfg)
{
	unsigned long parsed;
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

	phy->driver = ephy_drvFind(name);
	if (phy->driver == NULL) {
		fprintf(stderr, "lwip: ephy: driver \"%s\" is not supported\n", name);
		return -ENOENT;
	}

	errno = 0;
	parsed = strtoul(cfg, &p, 0);
	if (errno != 0 || p == cfg || parsed > UINT_MAX) {
		return -EINVAL;
	}
	phy->addr = parsed;

	if (*p == '.') {
		phy->bus = phy->addr;
		p++;
		cfg = p;

		if (*cfg == '\0') {
			return -EINVAL;
		}

		errno = 0;
		parsed = strtoul(cfg, &p, 0);
		if (errno != 0 || p == cfg || parsed > UINT_MAX) {
			return -EINVAL;
		}
		phy->addr = parsed;
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

	const char *irqMacStr = "irq:MAC";
	size_t irqMacLen = sizeof("irq:MAC") - 1;

	phy->irqtype = ephy_irqGpio;
	while (p != NULL && *p != '\0') {
		cfg = p;
		if (strncmp(p, irqMacStr, irqMacLen) == 0) {
			if ((p[irqMacLen] == '\0') || (p[irqMacLen] == ':')) {
				phy->irqtype = ephy_irqMac;
				p += irqMacLen;
				if (p[0] == ':') {
					p++;
				}
			}
		}

		if ((p == cfg) && (phy->irqtype == ephy_irqGpio)) {
			p = ephy_parsePinArg(p, "irq:", 4, &phy->irqGpio, GPIO_INPUT);
		}

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


enum eth_linkSpeed ephy_linkSpeed(const eth_phy_state_t *phy, enum eth_duplex *duplex)
{
	enum eth_linkSpeed s;
	enum eth_duplex d;

	/* function should not be called before ePHY is successfully initialized */
	assert(phy != NULL && phy->driver != NULL);

	if (phy->driver->link_speed(phy, &s, &d) < 0) {
		return eth_linkSpeedUnknown;
	}

	if (duplex != NULL) {
		*duplex = d;
	}

	return s;
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
int ephy_init(eth_phy_state_t *phy, char *conf, uint8_t boardRev, linkStateCb_t lsCb, void *lsCbArg)
{
	memset(phy, 0, sizeof(*phy));

	phy->lsCb = lsCb;
	phy->lsCbArg = lsCbArg;
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
		net_gpioSet(&phy->resetGpio, 1);
		return -ENODEV;
	}

	ephy_debug_printf(phy, "ID: 0x%x", phy->phyid);

	err = ephy_configure(phy);
	if (err < 0) {
		net_gpioSet(&phy->resetGpio, 1);
		return err;
	}

	if (phy->irqtype == ephy_irqGpio) {
		if (!net_gpioValid(&phy->irqGpio)) {
			ephy_printf(phy, "Interrupt GPIO invalid, could not start PHY IRQ thread");
			return -ENODEV;
		}

		err = beginthread(ephy_linkThread, 0, phy->stack, sizeof(phy->stack), phy);
		if (err != 0) {
			net_gpioSet(&phy->resetGpio, 1);
			return err;
		}
	}

	ephy_debug_printf(phy, "Successfully initialized PHY");

	return 0;
}
