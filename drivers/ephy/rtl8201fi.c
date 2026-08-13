/*
 * Phoenix-RTOS --- networking stack
 *
 * Ethernet PHY 88e1111 driver
 *
 * Copyright 2025, 2026 Phoenix Systems
 * Author: Julian Uziemblo
 *
 * %LICENSE%
 */
#include "ephy-driver.h"


/* RTL common registers */
enum {
	EPHY_RTL_1F_PAGESEL = 0x1F /* Page Select */
};

/* RTL8201-specific registers */
enum {
	/* Page 0 (default) */
	EPHY_RTL8201_18_PSMR = 0x18,  /* Power Saving Mode */
	EPHY_RTL8201_1C_FMLR = 0x1C,  /* Fiber Mode and Loopback */
	EPHY_RTL8201_1E_IISDR = 0x1E, /* Interrupt Indicators and SNR Display */

	/* Page 4 */
	EPHY_RTL8201_PAGE04_10_ECER = 0x10, /* EEE Capability Enable */
	EPHY_RTL8201_PAGE04_15_EECR = 0x15, /* EEE Capability */

	/* Page 7 */
	EPHY_RTL8201_PAGE07_10_RMSR = 0x10, /* RMII Mode Setting */
	EPHY_RTL8201_PAGE07_11_CLSR,        /* Customised LEDs Setting */
	EPHY_RTL8201_PAGE07_12_ELER,        /* EEE LEDs Enable */
	EPHY_RTL8201_PAGE07_13_IWELFR,      /* Interrupt, WOL Enable and LEDs Function */
	EPHY_RTL8201_PAGE07_14_MTIR,        /* MII TX Isolate */
	EPHY_RTL8201_PAGE07_18_SSCR = 0x18  /* Spread Spectrum Clock Register */
};


static int rtl8201fi_setup(const eth_phy_state_t *phy)
{
	/* RMII mode, TXC input, default tx/rx offset */
	ephy_regWrite(phy, EPHY_RTL_1F_PAGESEL, 7);
	ephy_regWrite(phy, EPHY_RTL8201_PAGE07_10_RMSR, (1U << 12) | (0xffU << 4) | (1U << 3));
	ephy_regWrite(phy, EPHY_RTL_1F_PAGESEL, 0);
	return 0;
}


static int rtl8201fi_enableIrq(const eth_phy_state_t *phy, bool enable)
{
	ephy_regWrite(phy, EPHY_RTL_1F_PAGESEL, 7);

	uint16_t iwelfr = ephy_regRead(phy, EPHY_RTL8201_PAGE07_13_IWELFR);
	if (enable) {
		iwelfr |= (1U << 13);
	}
	else {
		iwelfr &= ~(1U << 13);
	}
	ephy_regWrite(phy, EPHY_RTL8201_PAGE07_13_IWELFR, iwelfr);

	ephy_regWrite(phy, EPHY_RTL_1F_PAGESEL, 0);
	return 0;
}


static int rtl8201fi_linkSpeed(const eth_phy_state_t *phy, enum eth_linkSpeed *speed, enum eth_duplex *duplex)
{
	uint16_t bmcr = ephy_regRead(phy, EPHY_COMMON_00_BMCR);
	*speed = ((bmcr & (1U << 13)) == 0) ? eth_linkSpeed_10M : eth_linkSpeed_100M;
	*duplex = ((bmcr & (1U << 8)) != 0) ? eth_duplexFull : eth_duplexHalf;
	return 0;
}


static ephy_driver_t rtl8201fi_driver = {
	.name = "rtl8201fi",
	.specific_setup = rtl8201fi_setup,
	.enable_irq = rtl8201fi_enableIrq,
	.link_speed = rtl8201fi_linkSpeed,
	.properties = {
		.irq = {
			.mask = 0xE800,
			.reg = EPHY_RTL8201_1E_IISDR,
		},
		.reset = {
			.holdTimeUs = 10 * 1000,
			.releaseTimeUs = 150 * 1000,
		},
		.maxSpeed = eth_linkSpeed_100M,
	},
};


__attribute__((constructor)) static void rtl8201fi_driverRegister(void)
{
	ephy_driverRegister(&rtl8201fi_driver);
}
