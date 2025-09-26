/*
 * Phoenix-RTOS --- networking stack
 *
 * Ethernet PHY common routines
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * %LICENSE%
 */
#ifndef NET_EPHY_H_
#define NET_EPHY_H_

#include "gpio.h"

#include <phoenix/ethtool.h>
#include <stdint.h>
#include <stdbool.h>


#define EPHY_ADVERTISED_SPEEDS     (ADVERTISED_10baseT_Half | ADVERTISED_10baseT_Full | ADVERTISED_100baseT_Half | ADVERTISED_100baseT_Full)
#define EPHY_ADVERTISED_INTERFACES (ADVERTISED_Autoneg)
#define EPHY_ADVERTISED_FEATURES   (ADVERTISED_MII)
#define EPHY_ADVERTISED            (EPHY_ADVERTISED_SPEEDS | EPHY_ADVERTISED_INTERFACES | EPHY_ADVERTISED_FEATURES)

typedef void (*link_state_cb_t)(void *arg, int state);

typedef struct {
	enum { ephy_ksz8081rna,
		ephy_ksz8081rnb,
		ephy_ksz8081rnd,
		ephy_rtl8201fi,
		ephy_rtl8211fdi } model;
	unsigned bus;
	unsigned addr;
	unsigned reset_hold_time_us;
	unsigned reset_release_time_us;
	gpio_info_t reset, irq_gpio;

	link_state_cb_t link_state_callback;
	void *link_state_callback_arg;

	uint32_t th_stack[512] __attribute__((aligned(16)));
} eth_phy_state_t;


int ephy_init(eth_phy_state_t *phy, char *conf, uint8_t board_rev, link_state_cb_t cb, void *cb_arg);
int ephy_linkSpeed(const eth_phy_state_t *phy, int *duplex);

/* toggle MACPHY internal loopback for test mode */
int ephy_enableLoopback(const eth_phy_state_t *phy, bool enable);

/* ethtool interface */
int ephy_getAN(const eth_phy_state_t *phy);

#endif /* NET_EPHY_H_ */
