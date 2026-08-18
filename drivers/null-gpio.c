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


int net_gpioSet(const net_gpioInfo_t *gp, int active)
{
	return -ENOSYS;
}


int net_gpioGet(const net_gpioInfo_t *gp)
{
	return -ENOSYS;
}


int net_gpioWait(const net_gpioInfo_t *gp, int active, time_t timeout)
{
	return -ENOSYS;
}


int net_gpioInit(net_gpioInfo_t *gp, const char *arg, unsigned flags)
{
	return -ENOSYS;
}
