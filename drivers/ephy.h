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

#include <sys/types.h>


typedef struct {
	unsigned bus;
	unsigned addr;
	unsigned reset_hold_time_us;
	unsigned reset_release_time_us;
	gpio_info_t reset, irq_gpio;

	/* FIXME: link state callback */

	u32 th_stack[512] __attribute__((aligned(16)));
} eth_phy_state_t;


int ephy_init(eth_phy_state_t *phy, char *conf);


#endif /* NET_EPHY_H_ */
