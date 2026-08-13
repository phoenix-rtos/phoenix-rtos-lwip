/*
 * Phoenix-RTOS --- networking stack
 *
 * Ethernet PHY 88e1111 driver
 *
 * Copyright 2025, 2026 Phoenix Systems
 * Author: Andrzej Tlomak, Julian Uziemblo
 *
 * %LICENSE%
 */
#include "ephy-driver.h"


/* DP83867IS-specific registers*/
enum {
	EPHY_DP83867IS_10_PHYCR = 0x10,    /* PHY Control */
	EPHY_DP83867IS_11_PHYSTS,          /* PHY Status */
	EPHY_DP83867IS_12_MICR,            /* MII Interrupt Control */
	EPHY_DP83867IS_13_ISR,             /* MII Interrupt Status */
	EPHY_DP83867IS_14_SGMIICR,         /* SGMII Control */
	EPHY_DP83867IS_1E_CFG3 = 0x1E,     /* Configuration 3 */
	EPHY_DP83867IS_1F_CFG4,            /* Configuration 4 */
	EPHY_DP83867IS_31_CFG4 = 0x31,     /* CFG4 (SGMII Auto-Neg Timer) */
	EPHY_DP83867IS_32_RGMIICTL,        /* RGMII Control */
	EPHY_DP83867IS_D3_SGMIICTL1 = 0xD3 /* SGMIICTL1 (via MMD access) */
};


static int dp83867is_setup(const eth_phy_state_t *phy)
{
	const uint16_t devad = 0x1FU;
	/* Enable differential SGMII clock to MAC */
	ephy_mmdWrite(phy, devad, EPHY_DP83867IS_D3_SGMIICTL1, 0x4000);

	/* Enable SGMII autonegotiation and speed optimization */
	ephy_regWrite(phy, EPHY_COMMON_00_BMCR, 0x1000U);
	ephy_regWrite(phy, EPHY_DP83867IS_14_SGMIICR, 0x2BC0U);

	/* Set SGMII Auto-Negotiation Timer Duration to 11 ms */
	ephy_mmdWrite(phy, devad, EPHY_DP83867IS_31_CFG4, 0x0070);

	/* Disable RGMII */
	ephy_mmdWrite(phy, devad, EPHY_DP83867IS_32_RGMIICTL, 0x0);

#if EPHY_DEBUG
	uint16_t reg;
	reg = ephy_mmdRead(phy, devad, 0xD3);
	ephy_debug_printf(phy, "extended reg 0xD3: %04x", reg);
	reg = ephy_mmdRead(phy, devad, 0x31);
	ephy_debug_printf(phy, "extended reg 0x31: %04x", reg);
	reg = ephy_mmdRead(phy, devad, 0x32);
	ephy_debug_printf(phy, "extended reg 0x32: %04x", reg);
#endif
	return 0;
}


static int dp83867is_enableIrq(const eth_phy_state_t *phy, bool enable)
{
	uint16_t cfg3 = enable ? ((1U << 7) | (1U << 1)) : 0U;
	uint16_t micr = enable ? (1U << 10) : 0U;

	ephy_regWrite(phy, EPHY_DP83867IS_1E_CFG3, cfg3);
	ephy_regWrite(phy, EPHY_DP83867IS_12_MICR, micr);

	return 0;
}


static int dp83867is_linkSpeed(const eth_phy_state_t *phy, enum eth_linkSpeed *speed, enum eth_duplex *duplex)
{
	uint16_t st = ephy_regRead(phy, EPHY_COMMON_01_BMSR);
	uint16_t sts = ephy_regRead(phy, EPHY_DP83867IS_11_PHYSTS);
	uint16_t speedVal;

	/* PHY still in auto-negotiation */
	if ((st & (1U << 5)) == 0) {
		return -1;
	}

	*duplex = ((sts & (1U << 13)) != 0) ? eth_duplexFull : eth_duplexHalf;

	speedVal = (sts >> 14) & 0x3;
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


static ephy_driver_t dp83867is_driver = {
	.name = "dp83867is",
	.specific_setup = dp83867is_setup,
	.enable_irq = dp83867is_enableIrq,
	.link_speed = dp83867is_linkSpeed,
	.properties = {
		.irq = {
			.mask = 0x00FF,
			.reg = EPHY_DP83867IS_13_ISR,
		},
		.reset = {
			.holdTimeUs = 1,
			.releaseTimeUs = 200,
		},
		.maxSpeed = eth_linkSpeed_1G,
	},
};


__attribute__((constructor)) static void dp83867is_driverRegister(void)
{
	ephy_driverRegister(&dp83867is_driver);
}
