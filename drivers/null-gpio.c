/*
 * Phoenix-RTOS --- networking stack
 *
 * GPIO stubs
 *
 * Copyright 2025 Phoenix Systems
 * Author: Andrzej Tlomak
 *
 * %LICENSE%
 */

#include "gpio.h"
#include <errno.h>


int gpio_set(const gpio_info_t *gp, int active)
{
	return -ENOSYS;
}


int gpio_get(const gpio_info_t *gp)
{
	return -ENOSYS;
}


int gpio_wait(const gpio_info_t *gp, int active, time_t timeout)
{
	return -ENOSYS;
}


int gpio_init(gpio_info_t *gp, const char *arg, unsigned flags)
{
	return -ENOSYS;
}
