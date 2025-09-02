#include "tda4vm-ephy.h"
#include "netif-driver.h"
#include "res-create.h"

#include <sys/threads.h>
#include <sys/interrupt.h>
#include <stdio.h>
#include <string.h>

#define EPHY_DBG     1

#if EPHY_DBG
#define ephy_debug(fmt, ...) printf("ephy: "fmt"\n", ##__VA_ARGS__)
#else 
#define ephy_debug(fmt, ...)
#endif 

enum {
	EPHY_00_BMCR = 0x00,      /* Basic Mode Control */
	EPHY_01_BMSR,             /* Basic Mode Status */
	EPHY_02_PHYID1,           /* PHY Identifier 1 */
	EPHY_03_PHYID2,           /* PHY Identifier 2 */
	EPHY_04_ANAR,             /* Auto-Negotiation Advertisement */
	EPHY_05_ANLPAR,           /* Auto-Negotiation Link Partner Ability */
	EPHY_06_ANER,             /* Auto-Negotiation Expansion */
	EPHY_07_ANPR,             /* Auto-Negotiation Next Page Transmit */
	EPHY_08_ANNPRR,			  /* Auto-Negotiation Next Page Receive */
	EPHY_09_CFG1,			  /* 1000BASE-T Configuration Register */
	EPHY_0A_STS1,			  /* Status Register 1 */
	EPHY_0F_1KSCR = 0x0F,	  /* 1000BASE-T Status Register */
	EPHY_10_PHYCR,			  /* PHY Control Register */
	EPHY_11_PHYSTS,		      /* PHY Status Register */
	EPHY_12_MICR,             /* MII Interrupt Control Register */
	EPHY_13_ISR,			  /* Interrupt Status Register */
	EPHY_14_CFG2,			  /* Configuration Register 2 */
	EPHY_15_RECR,			  /* Receiver Error Counter Register */
	EPHY_16_BIST,			  /* BIST Control Register */
	EPHY_17_STS2			  /* Status Register 2 */
};

#define EPHY_00_BMCR_AUTONEG_EN			(1 << 12)


static uint16_t ephy_regRead(eth_phy_state_t *phy, uint16_t reg)
{
	return mdio_read(phy->bus, phy->addr, reg);
}

static void ephy_regWrite(eth_phy_state_t *phy, uint16_t reg, uint16_t val)
{
	mdio_write(phy->bus, phy->addr, reg, val);
}

static void ephy_config(eth_phy_state_t *phy) 
{
	uint16_t val;

	/* enable Auto Negotiation */
	val = ephy_regRead(phy, EPHY_00_BMCR);
	val |= EPHY_00_BMCR_AUTONEG_EN;
	ephy_regWrite(phy, EPHY_00_BMCR, val);	
}

static void ephy_setLinkState(eth_phy_state_t *phy)
{
	linkstate_t phy_status;
	uint16_t link_speed;

	phy_status.phystatus = ephy_regRead(phy, EPHY_11_PHYSTS);
    
	switch(phy_status.SPEED_SEL) {
		case(0b00) :
			link_speed = 10;
      		break;
		case(0b01) :
			link_speed = 100;
    		break;
		case(0b10) :
			link_speed = 1000;
      		break;
		default:
			link_speed = 0;
      		break;			
	}
	phy->linkstatus(phy->linkstatus_arg, phy_status, link_speed);
}

/**
 *  MDIO link state change thread 
 */
static void ephy_irqThread(void *arg)
{
	eth_phy_state_t *phy = arg;

	mutexLock(phy->mdio_irq_lock);
	for(;;) {
		ephy_setLinkState(phy);
		condWait(phy->mdio_cond, phy->mdio_irq_lock, 0);
	}
	mutexUnlock(phy->mdio_irq_lock);

	endthread();
}

/**
 *  basic PHY/MDIO setup
 */
int ephy_init(eth_phy_state_t *phy, linkstatus linkstatus, void *linkstatus_arg, clear_MDIO_irq mdio_clear, void *mdio_clear_arg)
{
	int err;
	uint32_t phy_id;

	/* configure phy parameters first */
	phy->addr = PHY_ADDRESS;
	phy->bus = PHY_BUS;	
	phy->linkstatus = linkstatus;
	phy->linkstatus_arg = linkstatus_arg;
	phy->mdio_clear = mdio_clear;
	phy->mdio_clear_arg = mdio_clear_arg;

	/* init MDIO */
	err = mdio_setup(phy->bus, 0, 0, 0);

	/* read PHYID to confirm connection */
	phy_id = (ephy_regRead(phy, EPHY_02_PHYID1) << 16);
	phy_id |= (ephy_regRead(phy, EPHY_03_PHYID2));

	if (phy_id == PHY_ID)
		ephy_debug("PHY ID read correctly: 0x%08x", phy_id);
	else 
		return -EIO;	

	/* create IRQ & thread handlers */
	err = create_mutexcond_bulk(&phy->mdio_irq_lock, 2, ~0x01);
	if (err < 0) {
		ephy_debug("mutexcond creation fail");
		return err;
	}

	/* register IRQ and thread */
	err = interrupt((int)MDIO_IRQ, phy->mdio_clear, phy->mdio_clear_arg, phy->mdio_cond, &phy->mdio_irq_handle);
	if (err < 0) {
		ephy_debug("Couldn't register MDIO IRQ handler : %s", strerror(err));
		return err;
	}

	err = beginthread(ephy_irqThread, 1, phy->th_stack, sizeof(phy->th_stack), phy);
	if (err < 0) {
		ephy_debug("Couldn't register MDIO IRQ thread : %s", strerror(err));
		return err;
	}

	/* set link state */
	ephy_config(phy);
	ephy_setLinkState(phy);

	/* register ephy thread */
	return err;
}

/**
 *  PHY restart (reset + config), after enabling MAC interrupts
 */
int ephy_restart(eth_phy_state_t);
