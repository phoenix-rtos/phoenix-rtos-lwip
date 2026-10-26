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
#include <errno.h>

#include "ephy-driver.h"


/* RTL common registers */
enum {
	EPHY_RTL_1F_PAGESEL = 0x1F /* Page Select */
};


/* RTL8211-specific registers */
enum {
	/* Page 0/0xa42 (default) */
	EPHY_RTL8211_12_INER = 0x12,   /* Interrupt Enable */
	EPHY_RTL8211_18_PHYCR1 = 0x18, /* PHY Specific Control 1 */
	EPHY_RTL8211_19_PHYCR2,        /* PHY Specific Control 2 */
	EPHY_RTL8211_1A_PHYSR,         /* PHY Specific Status */
	EPHY_RTL8211_1D_INSR = 0x1D,   /* Interrupt Status */
	EPHY_RTL8211_1E_EXTPAGESEL,    /* (hidden) Ext Page Select */

	/* Page 0xd04 */
	EPHY_RTL8211_PAGE0D04_10_LCR = 0x10, /* LED Control */
	EPHY_RTL8211_PAGE0D04_11_EEELCR,     /* EEE LEd Control */

	/* Page 0xa46 */
	EPHY_RTL8211_PAGE0A46_14_PHYSCR = 0x14, /* PHY Special Config */

	/* Page 0xd08 */
	EPHY_RTL8211_PAGE0D08_15_MIICR, /* MII Control */

	/* Page 0xd40 */
	EPHY_RTL8211_PAGE0D40_16_INTBCR, /* INTB Pin Control */
};


static int rtl8211fdi_setup(const eth_phy_state_t *phy)
{
	/* no addr 0 broadcast, auto-MDI, TX CRS assert, no PHYAD detect, check preamble, no jabber detection, no ALDPS/PLL-OFF  */
	ephy_regWrite(phy, EPHY_RTL8211_18_PHYCR1, (1U << 8) | (1U << 4));
	/* clkout 125MHz, no clkout SSC, no RXC SSC, no EEE, RXC out enabled, clkout out disabled */
	ephy_regWrite(phy, EPHY_RTL8211_19_PHYCR2, (1U << 6));

	/* Pin 31 INTB */
	ephy_regWrite(phy, EPHY_RTL_1F_PAGESEL, 0xd40);
	ephy_regWrite(phy, EPHY_RTL8211_PAGE0D40_16_INTBCR, 0);
	ephy_regWrite(phy, EPHY_RTL_1F_PAGESEL, 0xa42);

	return 0;
}


static int rtl8211fdi_enableIrq(const eth_phy_state_t *phy, bool enable)
{
	uint16_t val = enable ? (1U << 4) : 0U;
	ephy_regWrite(phy, EPHY_RTL8211_12_INER, val);
	return 0;
}


static int rtl8211fdi_linkSpeed(const eth_phy_state_t *phy, enum eth_linkSpeed *speed, enum eth_duplex *duplex)
{
	uint16_t physr = ephy_regRead(phy, EPHY_RTL8211_1A_PHYSR);
	uint16_t speedVal;

	*duplex = ((physr & (1U << 3)) != 0) ? eth_duplexFull : eth_duplexHalf;

	speedVal = (physr >> 4) & 0x3;

	switch (speedVal) {
		case 0x0:
			*speed = eth_linkSpeed_10M;
			break;
		case 0x1:
			*speed = eth_linkSpeed_100M;
			break;
		case 0x2:
			*speed = eth_linkSpeed_1G;
			break;
		default:
			*speed = eth_linkSpeed_unknown;
			break;
	}

	return 0;
}


static int rtl8211fdi_configAdv(const eth_phy_state_t *phy)
{
	/* don't adv: 1000Base-T EEE (MMD write) */
	ephy_mmdWrite(phy, 0x7, 0x3c /* EEEAR */, 0);

	return 0;
}


static ephy_driver_t rtl8211fdi_driver = {
	.name = "rtl8211fdi",
	.specific_setup = rtl8211fdi_setup,
	.enable_irq = rtl8211fdi_enableIrq,
	.link_speed = rtl8211fdi_linkSpeed,
	.config_adv = rtl8211fdi_configAdv,
	.properties = {
		.irq = {
			.mask = 0x06BD,
			.reg = EPHY_RTL8211_1D_INSR,
		},
		.reset = {
			.holdTimeUs = 10 * 1000,
			.releaseTimeUs = 3 * 30 * 1000,
		},
		.maxSpeed = eth_linkSpeed_1G,
	},
};


__attribute__((constructor)) static void rtl8211fdi_driverRegister(void)
{
	ephy_driverRegister(&rtl8211fdi_driver);
}
