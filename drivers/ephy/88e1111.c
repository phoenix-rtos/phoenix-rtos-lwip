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


/* 88E1111-specific registers*/
enum {
	EPHY_88E1111_11_PHYSR = 0x11, /* PHY Specific Status */
	EPHY_88E1111_12_IER,          /* Interrupt Enable */
	EPHY_88E1111_13_ISR,          /* Interrupt Status */
};


static int ephy88e1111_enableIrq(const eth_phy_state_t *phy, bool enable)
{
	uint16_t ier = enable ? (1U << 10) : 0U;
	ephy_regWrite(phy, EPHY_88E1111_12_IER, ier);
	return 0;
}


static int ephy88e1111_linkSpeed(const eth_phy_state_t *phy, enum eth_linkSpeed *speed, enum eth_duplex *duplex)
{
	uint16_t physr = ephy_regRead(phy, EPHY_88E1111_11_PHYSR);
	uint16_t speedVal;

	*duplex = ((physr & (1U << 13)) != 0) ? eth_duplexFull : eth_duplexHalf;

	speedVal = (physr >> 14) & 0x3U;

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


static ephy_driver_t ephy88e1111_driver = {
	.name = "88e1111",
	.enable_irq = ephy88e1111_enableIrq,
	.link_speed = ephy88e1111_linkSpeed,
	.properties = {
		.irq = {
			.mask = 0x0400,
			.reg = EPHY_88E1111_13_ISR,
		},
		.reset = {
			.holdTimeUs = 10 * 1000,
			.releaseTimeUs = 5 * 1000,
		},
		.maxSpeed = eth_linkSpeed_1G,
	},
};


__attribute__((constructor)) static void ephy88e1111_driverRegister(void)
{
	ephy_driverRegister(&ephy88e1111_driver);
}
