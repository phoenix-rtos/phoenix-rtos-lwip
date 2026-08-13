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


/* KSZ9031MNX-specific registers*/
enum {
	EPHY_KSZ9031_1B_ICSR = 0x1B,  /* PHY Control */
	EPHY_KSZ9031_1F_PHYCR = 0x1F, /* PHY Control */
};


static int ksz9031mnx_enableIrq(const eth_phy_state_t *phy, bool enable)
{
	uint16_t icsr = enable ? ((1U << 8) | (1U << 10)) : 0U;
	ephy_regWrite(phy, EPHY_KSZ9031_1B_ICSR, icsr);
	return 0;
}


static int ksz9031mnx_linkSpeed(const eth_phy_state_t *phy, enum eth_linkSpeed *speed, enum eth_duplex *duplex)
{
	uint16_t st = ephy_regRead(phy, EPHY_COMMON_01_BMSR);
	uint16_t pc, speedVal;

	/* PHY still in auto-negotiation */
	if ((st & (1U << 5)) == 0) {
		return -1;
	}

	pc = ephy_regRead(phy, EPHY_KSZ9031_1F_PHYCR);

	*duplex = ((pc & (1U << 3)) != 0) ? eth_duplexFull : eth_duplexHalf;

	speedVal = ((pc >> 4) & 0x7);

	switch (speedVal) {
		case 0x1:
			*speed = eth_linkSpeed_10M;
			break;
		case 0x2:
			*speed = eth_linkSpeed_100M;
			break;
		case 0x4:
			*speed = eth_linkSpeed_1G;
			break;
		default:
			*speed = eth_linkSpeed_unknown;
			break;
	}

	return 0;
}


static ephy_driver_t ksz9031mnx_driver = {
	.name = "ksz9031mnx",
	.enable_irq = ksz9031mnx_enableIrq,
	.link_speed = ksz9031mnx_linkSpeed,
	.properties = {
		.irq = {
			.mask = 0x00FF,
			.reg = EPHY_KSZ9031_1B_ICSR,
		},
		.reset = {
			.holdTimeUs = 500,
			.releaseTimeUs = 10 * 1000,
		},
		.maxSpeed = eth_linkSpeed_1G,
	},
};


__attribute__((constructor)) static void ksz9031mnx_driverRegister(void)
{
	ephy_driverRegister(&ksz9031mnx_driver);
}
