/*
 * Phoenix-RTOS --- networking stack
 *
 * Ethernet PHY 88e1111 driver
 *
 * Copyright 2018, 2026 Phoenix Systems
 * Author: Michal Miroslaw, Julian Uziemblo
 *
 * %LICENSE%
 */
#include <errno.h>

#include "ephy-driver.h"

#include "lwipopts.h"
#include LWIP_HOOK_FILENAME


/* KSZ8081 registers */
enum {
	EPHY_KSZ8081_10_DRCR = 0x10,      /* Digital Reserved Control */
	EPHY_KSZ8081_11_AFECR1,           /* AFE Control 1 */
	EPHY_KSZ8081_15_RXER_CNTR = 0x15, /* RXER Counter */
	EPHY_KSZ8081_16_OMSOR,            /* Operation Mode Strap Override */
	EPHY_KSZ8081_17_OMSSR,            /* Operation Mode Strap Status*/
	EPHY_KSZ8081_18_EXCR,             /* Expanded Control */
	EPHY_KSZ8081_1B_ICSR = 0x1B,      /* Interrupt Control/Status */
	EPHY_KSZ8081_1D_LMDCSR = 0x1D,    /* LinkMD Control/Status */
	EPHY_KSZ8081_1E_PHYCR1,           /* PHY Control 1 */
	EPHY_KSZ8081_1F_PHYCR2            /* PHY Control 2 */
};


/* Try to set alternative MAC PHY config (alternative configurations within the same PHY ID).
 * returns:
 *   > 0 if alternative config has been set
 *     0 if no alternative config with this ID
 *   < 0 if alternative config setting has failed
 */
static int ksz8081rnx_setAltConfig(const eth_phy_state_t *phy, int cfgId)
{
	/* CFG id:
	 * 0: KSZ8081 RND with 50 MHz RMII input clock (PHY_CTRL2[7] = 0)
	 * 1: KSZ8081 RNA/RNB with 50 MHz RMII input clock (PHY_CTRL2[7] = 1)
	 */

	/* try to set alternative MII clock frequency */
	uint16_t phy_ctrl2 = ephy_regRead(phy, EPHY_KSZ8081_1F_PHYCR2);

	switch (cfgId) {
		case 0:
			phy_ctrl2 &= ~(1U << 7);
			break;
		case 1:
			phy_ctrl2 |= (1U << 7);
			break;
		default:
			return 0; /* unknown config ID */
	}

	ephy_regWrite(phy, EPHY_KSZ8081_1F_PHYCR2, phy_ctrl2);
	if (ephy_regRead(phy, EPHY_KSZ8081_1F_PHYCR2) != phy_ctrl2) {
		ephy_printf(phy, "failed to set clock");
		return -1;
	}

	return 1;
}


static int ksz8081rnx_commonSetup(const eth_phy_state_t *phy, int cfgId)
{
	/* disable: addr 0 broadcast, NAND-tree mode */
	ephy_regWrite(phy, EPHY_KSZ8081_16_OMSOR, (1U << 1) | (1U << 9));

	if (ksz8081rnx_setAltConfig(phy, cfgId) < 0) {
		ephy_printf(phy, "Couldn't set clock config");
		return -ENODEV;
	}

#ifdef LWIP_EPHY_INIT_HOOK
/* keep the hook API intact */
#define ephy_setAltConfig ksz8081rnx_setAltConfig
	LWIP_EPHY_INIT_HOOK(phy, phy->phyid, phy->boardRev);
#endif

	return 0;
}


static int ksz8081rnab_setup(const eth_phy_state_t *phy)
{
	return ksz8081rnx_commonSetup(phy, 1);
}


static int ksz8081rnd_setup(const eth_phy_state_t *phy)
{
	return ksz8081rnx_commonSetup(phy, 0);
}


static int ksz8081rnx_enableIrq(const eth_phy_state_t *phy, bool enable)
{
	uint16_t val = enable ? ((1U << 8) | (1U << 10)) : 0U;
	ephy_regWrite(phy, EPHY_KSZ8081_1B_ICSR, val);
	return 0;
}


static int ksz8081rnx_linkSpeed(const eth_phy_state_t *phy, enum eth_linkSpeed *speed, enum eth_duplex *duplex)
{
	uint16_t pc1 = ephy_regRead(phy, EPHY_KSZ8081_1E_PHYCR1);

	if ((pc1 & 0x7) == 0) { /* PHY still in auto-negotiation */
		return -1;
	}

	*speed = ((pc1 & 0x1) != 0) ? eth_linkSpeed_10M : eth_linkSpeed_100M;
	*duplex = ((pc1 & (1U << 2)) != 0) ? eth_duplexFull : eth_duplexHalf;

	return 0;
}


static ephy_driver_t ksz8081rna_driver = {
	.name = "ksz8081rna",
	.specific_setup = ksz8081rnab_setup,
	.enable_irq = ksz8081rnx_enableIrq,
	.link_speed = ksz8081rnx_linkSpeed,
	.properties = {
		.irq = {
			.mask = 0x00FF,
			.reg = EPHY_KSZ8081_1B_ICSR,
		},
		.reset = {
			.holdTimeUs = 500,
			.releaseTimeUs = 10 * 1000,
		},
		.maxSpeed = eth_linkSpeed_100M,
	},
};


static ephy_driver_t ksz8081rnb_driver = {
	.name = "ksz8081rnb",
	.specific_setup = ksz8081rnab_setup,
	.enable_irq = ksz8081rnx_enableIrq,
	.link_speed = ksz8081rnx_linkSpeed,
	.properties = {
		.irq = {
			.mask = 0x00FF,
			.reg = EPHY_KSZ8081_1B_ICSR,
		},
		.reset = {
			.holdTimeUs = 500,
			.releaseTimeUs = 10 * 1000,
		},
		.maxSpeed = eth_linkSpeed_100M,
	},
};


static ephy_driver_t ksz8081rnd_driver = {
	.name = "ksz8081rnd",
	.specific_setup = ksz8081rnd_setup,
	.enable_irq = ksz8081rnx_enableIrq,
	.link_speed = ksz8081rnx_linkSpeed,
	.properties = {
		.irq = {
			.mask = 0x00FF,
			.reg = EPHY_KSZ8081_1B_ICSR,
		},
		.reset = {
			.holdTimeUs = 500,
			.releaseTimeUs = 10 * 1000,
		},
		.maxSpeed = eth_linkSpeed_100M,
	},
};


__attribute__((constructor)) static void ksz808rnx_driverRegister(void)
{
	ephy_driverRegister(&ksz8081rna_driver);
	ephy_driverRegister(&ksz8081rnb_driver);
	ephy_driverRegister(&ksz8081rnd_driver);
}
