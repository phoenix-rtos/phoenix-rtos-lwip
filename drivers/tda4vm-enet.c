
/*
 * Phoenix-RTOS --- networking stack
 *
 * J721 ENET network module driver
 *
 * Copyright 2025 Phoenix Systems
 * Author: Rafał Mikielis
 *
 * %LICENSE%
 */

#include "netif-driver.h"
#include "tda4vm-ephy.h"
#include "bdring.h"
#include "tda4vm-enet-regs.h"
#include "physmmap.h"

#include <stdatomic.h>
#include <stdio.h>
#include <phoenix/errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/platform.h>
#include <phoenix/arch/armv7r/tda4vm/tda4vm.h>
#include <phoenix/arch/armv7r/tda4vm/tisci_pm_clock.h>
#include <unistd.h>

#define ENET_DBG		0
#define SELF_CHECK		0

#if ENET_DBG == 1
#define enet_debug(fmt, ...) printf("lwip: "fmt"\n", ##__VA_ARGS__)
#else 
#define enet_debug(fmt, ...)
#endif 

#define enet_info(fmt, ...) printf("lwip: "fmt"\n", ##__VA_ARGS__)

typedef struct {
	struct netif *netif;
	volatile struct MCU_CTRL_MMR0 *mmr0_ctrl;
 	volatile struct MCU_CPSW0_NUSS_CONTROL *cpsw_ctrl;
	volatile struct MCU_CPSW0_NUSS_ALE *ale_ctrl;
    volatile struct MCU_CPSW0_NUSS_MDIO *mdio_ctrl;
 
	eth_phy_state_t phy_state;

} enet_state_t;


static err_t netif_sendPacket(struct netif *netif, struct pbuf *data)
{

}

static void enet_readMAC(enet_state_t *state)
{
	uint8_t *mac;
	uint32_t buff[2];

	mac = (uint8_t *)state->netif->hwaddr;

	buff[0] = (uint32_t)state->mmr0_ctrl->CTRLMMR_MCU_MAC_ID0;
	buff[1] = (uint32_t)state->mmr0_ctrl->CTRLMMR_MCU_MAC_ID1;

	/* saving MAC address in little-endian */
	mac[0] = (buff[1] >> 8)  & 0xff;
	mac[1] = (buff[1] >> 0)  & 0xff;
	mac[2] = (buff[0] >> 24) & 0xff;
	mac[3] = (buff[0] >> 16) & 0xff;
	mac[4] = (buff[0] >> 8)  & 0xff;
	mac[5] = (buff[0] >> 0)  & 0xff;

}

static void enet_readPins(void)
{
	uint8_t pins[] = {29, 23, 28, 22, 33, 32, 31};
	platformctl_t pctl;
	size_t size = sizeof(pins)/sizeof(uint8_t);

	pctl.type = pctl_pinconfig;
	pctl.action = pctl_get;

	for(int i=0; i < size; i++) {
		pctl.pin_config.pin_num = pins[i];
		platformctl(&pctl);
		enet_debug("pin mux = %d", pctl.pin_config.mux);
	}
}

static int enet_configPins(void)
{
	size_t pin_count;
	int err;
    
	platformctl_t enet_pins[] = { {pctl_set, pctl_pinconfig, .pin_config = { .flags = TDA4VM_GPIO_PULL_DISABLE | TDA4VM_GPIO_RX_EN | TDA4VM_GPIO_RX_EN | TDA4VM_GPIO_TX_DIS, 
																			 .mux = 0, 
																			 .pin_num = 29 } }, 					 /* RGMII Receive Clock    */
								  {pctl_set, pctl_pinconfig, .pin_config = { .flags = TDA4VM_GPIO_PULL_DISABLE | TDA4VM_GPIO_RX_EN | TDA4VM_GPIO_RX_EN | TDA4VM_GPIO_TX_DIS, 
																			 .mux = 0, 
																			 .pin_num = 23} }, 						 /* RGMII Receive Control  */
								  {pctl_set, pctl_pinconfig, .pin_config = { .flags = TDA4VM_GPIO_PULL_DISABLE | TDA4VM_GPIO_RX_EN, 
																			 .mux = 0, 
																			 .pin_num = 28} },  					/* RGMII Transmit Clock   */																	 
								  {pctl_set, pctl_pinconfig, .pin_config = { .flags = TDA4VM_GPIO_PULL_DISABLE, 
																			 .mux = 0, 
																			 .pin_num = 22} },   					/* RGMII Transmit Control */
								  {pctl_set, pctl_pinconfig, .pin_config = { .flags = TDA4VM_GPIO_PULL_DISABLE | TDA4VM_GPIO_RX_EN | TDA4VM_GPIO_TX_DIS, 
																			 .mux = 0, 
																			 .pin_num = 33} },					    /* RGMII Receive Data 0   */
								  {pctl_set, pctl_pinconfig, .pin_config = { .flags = TDA4VM_GPIO_PULL_DISABLE | TDA4VM_GPIO_RX_EN | TDA4VM_GPIO_TX_DIS, 
																			 .mux = 0, 
																			 .pin_num = 32} }, 						 /* RGMII Receive Data 1   */
								  {pctl_set, pctl_pinconfig, .pin_config = { .flags = TDA4VM_GPIO_PULL_DISABLE | TDA4VM_GPIO_RX_EN | TDA4VM_GPIO_TX_DIS, 
																			 .mux = 0, 
																			 .pin_num = 31} },  					/* RGMII Receive Data 2   */
								  {pctl_set, pctl_pinconfig, .pin_config = { .flags = TDA4VM_GPIO_PULL_DISABLE | TDA4VM_GPIO_RX_EN | TDA4VM_GPIO_TX_DIS, 
																			 .mux = 0, 
																			 .pin_num = 30} },  					/* RGMII Receive Data 3   */ 
								  {pctl_set, pctl_pinconfig, .pin_config = { .flags = TDA4VM_GPIO_PULL_DISABLE,
																			 .mux = 0, 
																			 .pin_num = 27} }, 						/* RGMII Transmit Data 0   */
								  {pctl_set, pctl_pinconfig, .pin_config = { .flags = TDA4VM_GPIO_PULL_DISABLE,
																			 .mux = 0, 
																			 .pin_num = 26} },  					/* RGMII Transmit Data 1   */
								  {pctl_set, pctl_pinconfig, .pin_config = { .flags = TDA4VM_GPIO_PULL_DISABLE,
																			 .mux = 0, 
																			 .pin_num = 25} }, 					   /* RGMII Transmit Data 2   */
								  {pctl_set, pctl_pinconfig, .pin_config = { .flags = TDA4VM_GPIO_PULL_DISABLE,
																			 .mux = 0, 
																			 .pin_num = 24} }, 					   /* RGMII Transmit Data 3   */																			 
								  {pctl_set, pctl_pinconfig, .pin_config = { .flags = TDA4VM_GPIO_PULL_UP_NDOWN,
																			 .mux = 0, 
																			 .pin_num = 35} }, 					  /* MDIO Clock   */ 
								  {pctl_set, pctl_pinconfig, .pin_config = { .flags = TDA4VM_GPIO_PULL_UP_NDOWN | TDA4VM_GPIO_RX_EN,   
																			 .mux = 0, 
																			 .pin_num = 34} }  }; 				  /* MDIO Data  */ 
	pin_count = sizeof(enet_pins) / sizeof(platformctl_t);

	for(int i = 0; i < pin_count; i++) {
		if((err = platformctl(&enet_pins[i])) != 0 ) {
			return err;
		}
	}
	
	/* MDIO pinmuxing */
	*(uint32_t *)(CTRLMMR_WKUP_BASE_ADDR + 0x1C088) &= ~(0xF);  
	*(uint32_t *)(CTRLMMR_WKUP_BASE_ADDR + 0x1C08C) &= ~(0xF);
	
	enet_debug("MDIO MDC PAD config: 0x%08x", *(uint32_t *)(CTRLMMR_WKUP_BASE_ADDR + 0x1C088));
	enet_debug("MDIO DATA PAD config: 0x%08x", *(uint32_t *)(CTRLMMR_WKUP_BASE_ADDR + 0x1C08C));
}

/**
 * 3 clocks must be delivered to CPSW.
 * 
 *  MCU_SYSCLK0 (1GHz) 				 -> CPPI_ICLK
 *  MCU_PLL2_HSDIV1_CLKOUT (500MHz)  -> MCU_CPTS_RFT_CLK -> CPTS_RFT_CLK
 * 	MCU_PLL2_HSDIV0_CLKOUT (250 MHz) -> GMII_RFT CLK/RGMII_MHz_*
 * 
 */
static int enet_initClocks(enet_state_t *state)
{
	platformctl_t enetClocks[] = { { .action = pctl_set, .type = pctl_tisci_clk_freq, .pctl_tisci_clk_freq = { .device = J721E_DEV_MCU_CPSW0,
																											   .clk = TISCI_DEV_MCU_CPSW0_CPPI_CLK_CLK,
																											   .target_freq_hz = 333333333,
																											   .min_freq_hz = 333333333,
																											   .max_freq_hz = 333333333} },
								   { .action = pctl_set, .type = pctl_tisci_clk_freq, .pctl_tisci_clk_freq = { .device = J721E_DEV_MCU_CPSW0,
																											   .clk = TISCI_DEV_MCU_CPSW0_CPTS_RFT_CLK,
																											   .target_freq_hz = 500000000,
																											   .min_freq_hz = 500000000,
																											   .max_freq_hz = 500000000 }},
								   { .action = pctl_set, .type = pctl_tisci_clk_freq, .pctl_tisci_clk_freq = { .device = J721E_DEV_MCU_CPSW0,
																											   .clk = TISCI_DEV_MCU_CPSW0_RGMII_MHZ_250_CLK,
																											   .target_freq_hz = 250000000,
																											   .min_freq_hz = 250000000,
																											   .max_freq_hz = 250000000 }} };

    for (int i = 0; i < sizeof(enetClocks) / sizeof(platformctl_t); i++) {

		int resp = platformctl(&enetClocks[i]);

		if (resp != EOK) {
			enet_debug("initClocks: setting frequency for clock %u failed", enetClocks[i].pctl_tisci_clk_freq.device);
			return -EINVAL;
		}
	}
	
	return EOK;
}

static int enet_reset(enet_state_t *state)
{
	uint8_t sleep_cnt;

	/* set CMD_IDLE bit */
	state->cpsw_ctrl->CPSW_PN_MAC_CONTROL_REG |= CPSW_PN_MAC_CONTROL_CMD_IDLE;

	/* wait for CMD_IDLE to take effect */
	sleep_cnt = 0;
	while (!(state->cpsw_ctrl->CPSW_PN_MAC_STATUS_REG & CPSW_PN_MAC_STATUS_IDLE)) {
		enet_debug("waiting for MAC idle mode");
		usleep(100);
		sleep_cnt += 1;
		if (sleep_cnt == 10)
			return -EBUSY;
	}

	/* set soft reset bit */
	state->cpsw_ctrl->CPSW_PN_MAC_SOFT_RESET_REG |= CPSW_PN_MAC_SOFT_RESET_RES;

	/* poll reset bit to check if reset is finished */
	sleep_cnt = 0;
	while((state->cpsw_ctrl->CPSW_PN_MAC_SOFT_RESET_REG & CPSW_PN_MAC_SOFT_RESET_RES)) {
		enet_debug("waiting for CPSW reset to finalize");
		usleep(100);
		sleep_cnt += 1;
		if (sleep_cnt == 10)
			return -EBUSY;
	}
	
	/* Ensure that at least 2000 CPPI_ICLK periods are run after reset is de-asserted */
	usleep(10);

	return EOK;
}


/**
 * TODO: take into account max_khz, min_hold_ns and opt_preamble during MDIO setup. So far these values
 * are hard-typed.
 */

static int enet_initMDIO(void *arg, unsigned max_khz, unsigned min_hold_ns, unsigned opt_preamble)
{
	uint8_t cnt;
	enet_state_t *state = arg;

	/* Assuming CPPI_ICLK (333MHz) is main clock for MDIO module, setting CLKDIV to 32 for 10MHz MDC */
	state->mdio_ctrl->CPSW_MDIO_CONTROL_REG &= ~CPSW_MDIO_CONTROL_REG_CLK_DIV(0xFFFF);
	state->mdio_ctrl->CPSW_MDIO_CONTROL_REG |= CPSW_MDIO_CONTROL_REG_CLK_DIV(0x20);
	
	/* enable MDIO module */
	state->mdio_ctrl->CPSW_MDIO_CONTROL_REG |= CPSW_MDIO_CONTROL_REG_EN;

	/* enable only PHY addr 0 for polling */
	state->mdio_ctrl->CPSW_MDIO_POLL_EN_REG = 0x1;

	/* check if PHY at addr 0x0 is alive */
	cnt = 0;
	while (!(state->mdio_ctrl->CPSW_MDIO_ALIVE_REG & 0x1)) {
		enet_debug("ENET PHY not active");
		usleep(100);
		cnt++;

		if (cnt == 10)
			return -EBUSY;
	}

	enet_debug("ENET PHY active");

	/* extend IPG value. For 10MHz clk, IPG will be 25us. */
	state->mdio_ctrl->CPSW_MDIO_POLL_REG |= 0xFF;
	
	/* enable linkint for PHY Addr 0x0 */
	state->mdio_ctrl->CPSW_MDIO_USER_PHY_SEL_REG_0 |= CPSW_MDIO_USER_PHY_SEL_REG_LINKINT;

	return EOK;
}

static uint16_t enet_mdioIO(enet_state_t *state, unsigned addr, unsigned reg, unsigned val, unsigned op)
{
	uint8_t count;

	state->mdio_ctrl->CPSW_MDIO_USER_ACCESS_REG_0 &= ~(0xFFFFFFFF);
	/* check if GO bit is cleared*/
	count = 0;
	while ((state->mdio_ctrl->CPSW_MDIO_USER_ACCESS_REG_0 & CPSW_MDIO_USER_ACCESS_REG_GO)) {
		
		enet_debug("MDIO IF busy");
		usleep(100);
		count++;

		if (count == 10)
			return -EBUSY;
	}

	/* write data to ACCESS_REG */
	state->mdio_ctrl->CPSW_MDIO_USER_ACCESS_REG_0 |= CPSW_MDIO_USER_ACCESS_REG_PHY_ADDR(addr);
	state->mdio_ctrl->CPSW_MDIO_USER_ACCESS_REG_0 |= CPSW_MDIO_USER_ACCESS_REG_REG_ADDR(reg);
	if (op == CPSW_MDIO_REG_WRITE) {
		state->mdio_ctrl->CPSW_MDIO_USER_ACCESS_REG_0 |= CPSW_MDIO_USER_ACCESS_REG_WRITE;
		state->mdio_ctrl->CPSW_MDIO_USER_ACCESS_REG_0 |= CPSW_MDIO_USER_ACCESS_REG_DATA(val); 
	}
	state->mdio_ctrl->CPSW_MDIO_USER_ACCESS_REG_0 |= CPSW_MDIO_USER_ACCESS_REG_GO;

	/* poll GO and ACK bits */

	count = 0;
	while( !(state->mdio_ctrl->CPSW_MDIO_USER_ACCESS_REG_0 & CPSW_MDIO_USER_ACCESS_REG_ACK) ||
		    (state->mdio_ctrl->CPSW_MDIO_USER_ACCESS_REG_0 & CPSW_MDIO_USER_ACCESS_REG_GO) ) {

		enet_debug("MDIO IO not completed");
		usleep(10000);
		count++;

		if (count == 10)
			return -EIO;
	}

	/* save MDIO data */
	val = state->mdio_ctrl->CPSW_MDIO_USER_ACCESS_REG_0 & 0xFFFF;

	return val;
}


static uint16_t enet_mdioRead(void *arg, unsigned addr, uint16_t reg) 
{
	enet_state_t *state = arg;
	return enet_mdioIO(state, addr, reg, 0, CPSW_MDIO_REG_READ);
}

static void enet_mdioWrite(void *arg, unsigned addr, uint16_t reg, uint16_t val)
{
	enet_state_t *state = arg;
	(void)enet_mdioIO(state, addr, reg, val, CPSW_MDIO_REG_WRITE);
}

static const mdio_bus_ops_t enet_mdio_ops = {
	enet_initMDIO,
	enet_mdioRead,
	enet_mdioWrite,
};

/* set CPSW_PN_MAC_CONTROL_REG due to PHY link state change */
static void enet_setLinkState(void *arg, linkstate_t status, uint16_t link_speed)
{
	struct netif *net = arg;
	enet_state_t *state = net->state;
	cpsw_mac_ctrl_t mac;

	mac.reg = 0;

	switch (status.LINK_STATUS) {
		case 1:							 // linkup
			if (link_speed == 1000) {
				mac.fullduplex = 1;
				mac.gig = 1;
			} else {
				if (status.DUPLEX_MODE)
					mac.fullduplex = 1;
				else 
					mac.fullduplex = 0;

				mac.gig = 0;	
			}
		break;
		case 0:							// linkdown
			mac.cmd_idle = 1;
		break;
		default:
			mac.cmd_idle = 1;
		break;
	}
	state->cpsw_ctrl->CPSW_PN_MAC_CONTROL_REG &= ~0xFFFFFFFF;
	state->cpsw_ctrl->CPSW_PN_MAC_CONTROL_REG |= mac.reg;

	enet_info("link is %s, %uMbps in %s duplex", status.LINK_STATUS? "UP" : "DOWN", link_speed, 
				status.DUPLEX_RES? (status.DUPLEX_MODE? "FULL" : "HALF") : "NONE");
}

static int enet_MDIOirq(unsigned int irq, void *arg)
{
	enet_state_t *state;
	state = arg;
	
	/* if set, clear LINKINT interrupt */
	if (state->mdio_ctrl->CPSW_MDIO_LINK_INT_MASKED_REG & CPSW_MDIO_LINK_INT_MASKED_INT0) {
		state->mdio_ctrl->CPSW_MDIO_LINK_INT_MASKED_REG |= CPSW_MDIO_LINK_INT_MASKED_INT0;
		state->mdio_ctrl->CPSW_MDIO_LINK_INT_RAW_REG |= 0x1;
		return 0;
	}
	return 1;
}

static int enet_netifInit(struct netif *netif, char *cfg)
{
	enet_state_t *state;
	int err;

	state = netif->state;
	state->netif = netif;

	state->cpsw_ctrl = (struct MCU_CPSW0_NUSS_CONTROL *)physmmap(MCU_CPSW0_NUSS_CONTROL_ADDR, sizeof(struct MCU_CPSW0_NUSS_CONTROL));
	state->mmr0_ctrl = (struct MCU_CTRL_MMR0 *)physmmap(MCU_CTRL_MMR0_BASE, sizeof(struct MCU_CTRL_MMR0));
	state->ale_ctrl = (struct MCU_CPSW0_NUSS_ALE *)physmmap(MCU_CPSW0_NUSS_ALE_ADDR, sizeof(struct MCU_CPSW0_NUSS_ALE));
	state->mdio_ctrl = (struct MCU_CPSW0_NUSS_MDIO *)physmmap(MCU_CPSW0_NUSS_MDIO_ADDR, sizeof(struct MCU_CPSW0_NUSS_MDIO));
	
	if( state->cpsw_ctrl == MAP_FAILED || state->mmr0_ctrl == MAP_FAILED || 
		state->ale_ctrl == MAP_FAILED || state->mdio_ctrl == MAP_FAILED) {
		enet_debug("physmmap failed, no memory");
		return -ENOMEM;
	}
	
	/* select interface (RMII/RGMII) */
	state->mmr0_ctrl->CTRLMMR_MCU_ENET_CTRL = CTRLMMR_MCU_ENET_CTRL_RGMII;

	/* configure pads (pin muxing) -- (signal descriptions for ethernet are at p.96 in Datasheet, pad - signal mapping are t p.146 in Datasheet) */
	err = enet_configPins();
	if(err < 0) {
		enet_debug("pin config failed");
		return err;
	}
	enet_debug("pins configured");

	/* initialize CPSW sybsystem clocks p.1622 in TRM */
	err = enet_initClocks(state);
	if(err < 0) {
		enet_debug("clock config failed");
		return err;
	}
	enet_debug("clock configured");

	/* soft reset CPSW */
	err = enet_reset(state);
	if(err < 0) {
		enet_debug("enet reset failed");
		return err;
	}
	enet_debug("enet reset done");

	/* configure CPSW_CONTROL_REG */
	state->cpsw_ctrl->CPSW_CONTROL_REG = (CPSW_CPTS_CONTROL_P0_ENABLE | CPSW_CPTS_CONTROL_P0_TX_CRC_REMOVE);
	state->cpsw_ctrl->CPSW_CONTROL_REG &= ~(CPSW_CPTS_CONTROL_VLAN_AWARE | CPSW_CPTS_CONTROL_P0_RX_PAD |
										   CPSW_CPTS_CONTROL_P0_RX_PASS_CRC_ERR | CPSW_CPTS_CONTROL_ECC_CRC_MODE);										 

	/* TODO: configure FIFO depths (p. 1649) */

	/* configure the Ethernet Port Source Address registers (CPSW_PN_SA_L_REG and CPSW_PN_SA_H_REG) */
	enet_readMAC(state);

	state->cpsw_ctrl->CPSW_PN_SA_L_REG |= (state->netif->hwaddr[0] << 8);
	state->cpsw_ctrl->CPSW_PN_SA_L_REG |= (state->netif->hwaddr[1] << 0);
	state->cpsw_ctrl->CPSW_PN_SA_H_REG |= (state->netif->hwaddr[2] << 24);
	state->cpsw_ctrl->CPSW_PN_SA_H_REG |= (state->netif->hwaddr[3] << 16);
	state->cpsw_ctrl->CPSW_PN_SA_H_REG |= (state->netif->hwaddr[4] << 8);
	state->cpsw_ctrl->CPSW_PN_SA_H_REG |= (state->netif->hwaddr[5] << 0);

#if SELF_CHECK
	uint64_t mac = (uint64_t)(state->cpsw_ctrl->CPSW_PN_SA_L_REG & 0xFFFF) << 32;
	mac |= ((uint64_t)(state->cpsw_ctrl->CPSW_PN_SA_H_REG & 0xFFFFFFFF));
	
	uint8_t mac_arr[6];
	for (int i=0; i <6; i++) {
		mac_arr[i] = (mac >> (i*8)) & 0xFF;
	}

	enet_debug("configured MAC address: 0x%02x:%02x:%02x:%02x:%02x:%02x", mac_arr[5], mac_arr[4], mac_arr[3], mac_arr[2], mac_arr[1], mac_arr[0]);
#endif	

	/* configure ALE engine */
	state->ale_ctrl->CPSW_ALE_CONTROL |= (CPSW_ALE_CONTROL_EN_BYPASS | CPSW_ALE_CONTROL_UNI_HOST_FLOOD | 
										  CPSW_ALE_CONTROL_CLEAR_TABLE | CPSW_ALE_CONTROL_ENABLE_ALE);
	state->ale_ctrl->CPSW_ALE_CONTROL &= ~CPSW_ALE_CONTROL_OUI_DENY; 		
	state->ale_ctrl->CPSW_ALE_CTRL2 |= CPSW_ALE_CTRL2_DROP_BADLEN;							

	/* configure priority handling */
	state->cpsw_ctrl->CPSW_P0_CONTROL_REG |= (CPSW_P0_CONTROL_REG_DSCP_IPV4_EN | CPSW_P0_CONTROL_REG_DSCP_IPV6_EN); 
	state->cpsw_ctrl->CPSW_PN_CONTROL_REG |= (CPSW_P0_CONTROL_REG_DSCP_IPV4_EN | CPSW_P0_CONTROL_REG_DSCP_IPV6_EN); 

	/* TODO: rate limiting */

	/* TODO: statistic interrupts and handling */
	/* state->cpsw_ctrl->CPSW_STAT_PORT_EN_REG = (CPSW_STAT_PORT_EN_REG_P0 | CPSW_STAT_PORT_EN_REG_P1); */

	/* register MDIO bus device */
	err = register_mdio_bus(&enet_mdio_ops, state);
	if (err < 0) {
		enet_debug("Can't register MDIO bus:  %s (%d)", strerror(-err), err);
		return err;
	}
	enet_debug("MDIO bus registered");

	err = ephy_init(&(state->phy_state), enet_setLinkState, (void *)state->netif, enet_MDIOirq, state);
	if (err < 0) {
		enet_debug("PHY device not connected");
		return err;
	}
	enet_debug("PHY device connected");

	for(;;) {
		
		/* endless for loop for debugging purpose, otherwise process will terminate at this point.  */
		usleep(3000000);
	}

	/* TODO: assign linkoutput function */

	/* TODO: initialize RA */

	/* TODO: rx irq interrupt */

	/* TODO: rx irq handler */

	return -ENOMEM;
}

static netif_driver_t enet_drv = {
	.init = enet_netifInit,
	.state_sz = sizeof(enet_state_t),
	.state_align = _Alignof(enet_state_t),
	.name = "enet",
	//.media = enet_media,
};


void register_driver_enet(void)
{
    register_netif_driver(&enet_drv);
}
