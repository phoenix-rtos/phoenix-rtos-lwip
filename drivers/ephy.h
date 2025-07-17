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

#include <stdint.h>
#include <stdbool.h>

typedef void (*link_state_cb_t)(void *arg, int state);

typedef struct {
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
int ephy_linkSpeed(const eth_phy_state_t *phy, int *full_duplex);

/* toggle MACPHY internal loopback for test mode */
int ephy_enableLoopback(const eth_phy_state_t *phy, bool enable);

#endif /* NET_EPHY_H_ */
