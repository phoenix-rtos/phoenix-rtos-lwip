/*
 * Phoenix-RTOS --- networking stack
 *
 * Ethernet PHY VSC8541-05 driver
 *
 * Copyright 2026 Phoenix Systems
 * Author: Andrzej Tlomak
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */


#include "ephy-driver.h"
#include <board_config.h>


#ifndef PHY_RX_SKEW
#define PHY_RX_SKEW 0
#endif


#ifndef PHY_TX_SKEW
#define PHY_TX_SKEW 0
#endif


/* VSC8541-05 registers */
enum {
	EPHY_VSC854105_17_PHYCTL1 = 0x17,         /* Extended PHY Control 1*/
	EPHY_VSC854105_19_IMR = 0x19,             /* Interrupt mask */
	EPHY_VSC854105_1A_ISR = 0x1A,             /* Interrupt status */
	EPHY_VSC854105_1C_AXCS = 0x1C,            /* Auxiliary Control and Status */
	EPHY_VSC854105_1F_PAGESEL = 0x1F,         /* Extended page select */
	EPHY_VSC854105_PAGE02_14_RGMIICTL = 0x14, /* Page 2, RGMII control */
};


static int vsc854105_setup(const eth_phy_state_t *phy)
{
	ephy_regWrite(phy, EPHY_VSC854105_1F_PAGESEL, 0x2U);

	/* set rx_clk and tx_clk delays */
	uint16_t rgmiiCtl = ephy_regRead(phy, EPHY_VSC854105_PAGE02_14_RGMIICTL);
	rgmiiCtl = rgmiiCtl & ~0x77U;
	rgmiiCtl |= ((PHY_RX_SKEW & 0x7U) << 4) | (PHY_TX_SKEW & 0x7U);
	ephy_regWrite(phy, EPHY_VSC854105_PAGE02_14_RGMIICTL, rgmiiCtl);

	ephy_regWrite(phy, EPHY_VSC854105_1F_PAGESEL, 0U);

	return 0;
}


static int vsc854105_enableIrq(const eth_phy_state_t *phy, bool enable)
{
	uint16_t imr = enable ? 0xFF00U : 0U;
	ephy_regWrite(phy, EPHY_VSC854105_19_IMR, imr);
	return 0;
}


static int vsc854105_linkSpeed(const eth_phy_state_t *phy, enum eth_linkSpeed *speed, enum eth_duplex *duplex)
{
	uint16_t ctl = ephy_regRead(phy, EPHY_COMMON_00_BMCR);
	uint16_t status = ephy_regRead(phy, EPHY_COMMON_01_BMSR);
	uint16_t axcs = ephy_regRead(phy, EPHY_VSC854105_1C_AXCS);
	uint16_t speedVal;

	/* auto-negotiation enabled and PHY still in auto-negotiation */
	if (((ctl & (1U << 12)) != 0) && ((status & (1U << 5)) == 0)) {
		return -1;
	}

	*duplex = ((axcs & (1U << 5)) != 0) ? eth_duplexFull : eth_duplexHalf;

	speedVal = (axcs >> 3) & 0x3U;

	switch (speedVal) {
		case 0x2:
			*speed = eth_linkSpeed1G;
			break;
		case 0x1:
			*speed = eth_linkSpeed100M;
			break;
		case 0x0:
			*speed = eth_linkSpeed10M;
			break;
		default:
			*speed = eth_linkSpeedUnknown;
			break;
	}
	return 0;
}


static ephy_driver_t vsc854105_driver = {
	.name = "vsc854105",
	.specific_setup = vsc854105_setup,
	.enable_irq = vsc854105_enableIrq,
	.link_speed = vsc854105_linkSpeed,
	.properties = {
		.irq = {
			.mask = 0xFF00U,
			.reg = EPHY_VSC854105_1A_ISR,
		},
		.reset = {
			.holdTimeUs = 2 * 1000,
			.releaseTimeUs = 15 * 1000,
		},
		.maxSpeed = eth_linkSpeed1G,
	},
};


__attribute__((constructor)) static void vsc854105_driverRegister(void)
{
	ephy_driverRegister(&vsc854105_driver);
}
