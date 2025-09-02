/*
 * Phoenix-RTOS --- networking stack
 *
 * Ethernet MDIO routines
 *
 * Copyright 2025 Phoenix Systems
 * Author: Rafał Mikielis
 *
 * %LICENSE%
 */

#ifndef NET_TDA4VM_EPHY
#define NET_TDA4VM_EPHY

#include "lwip/err.h"

#include <stdint.h>
#include <phoenix/errno.h>
#include <stdbool.h>

#define PHY_ADDRESS			0x00
#define PHY_BUS				0x00
#define PHY_ID				0x2000A231
#define MDIO_IRQ			35

typedef union {
	uint16_t phystatus;
	struct {
		uint16_t RES1  : 6;  		// bits 0-5
		uint16_t SLEEP : 1;	 		// bit 6
		uint16_t RES2  : 3;  		// bits 7-9
		uint16_t LINK_STATUS : 1;   // bit 10
		uint16_t DUPLEX_RES  : 1;   // bit 11
		uint16_t PAGE_RXED   : 1;   // bit 12
		uint16_t DUPLEX_MODE : 1;   // bit 13
		uint16_t SPEED_SEL   : 2;   // bit 14-15
	};
} linkstate_t;

typedef void (* linkstatus)(void *arg, linkstate_t status, uint16_t link_speed);
typedef int (* clear_MDIO_irq)(unsigned int irq, void *arg);

typedef struct {
	unsigned bus;
	unsigned addr;
	linkstatus linkstatus;
	void *linkstatus_arg;

	clear_MDIO_irq mdio_clear;
	void *mdio_clear_arg;

	handle_t mdio_irq_lock, mdio_cond;
	handle_t mdio_irq_handle;

	uint32_t th_stack[128] __attribute__((aligned(8)));
} eth_phy_state_t;


typedef struct {
	uint16_t data;
	uint8_t phy_addr;
	uint8_t reg_addr;
	bool write;
} mdio_access_t;


int ephy_init(eth_phy_state_t *phy, linkstatus linkstatus, void *linkstatus_arg, clear_MDIO_irq mdio_clear, void *mdio_clear_arg);

#endif /* NET_TDA4VM_EPHY */