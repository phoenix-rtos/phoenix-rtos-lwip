/*
 * Phoenix-RTOS --- networking stack
 *
 * GPIO wrapper
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * %LICENSE%
 */
#ifndef NET_GPIO_H_
#define NET_GPIO_H_

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

enum {
	GPIO_INVERTED = 1 << 0,
	GPIO_ACTIVE = 1 << 1,
	GPIO_INPUT = 0 << 2,
	GPIO_OUTPUT = 1 << 2,
	GPIO_PULL_UP = 1 << 3,
	GPIO_PULL_DOWN = 1 << 4,
	GPIO_INITIALIZED = 1 << 7,
};


typedef struct {
	unsigned flags;
	union {
		int fd;
		int id;
	};
	uint32_t pin;
#if defined(__CPU_IMXRT106X) || defined(__CPU_IMXRT117X) || defined(__CPU_STM32N6)
	oid_t multidrv;
#endif
} net_gpioInfo_t;


int net_gpioSet(const net_gpioInfo_t *gp, int active);
int net_gpioGet(const net_gpioInfo_t *gp);
int net_gpioWait(const net_gpioInfo_t *gp, int active, time_t timeout);
int net_gpioInit(net_gpioInfo_t *gp, const char *arg, unsigned flags);


static inline bool net_gpioValid(const net_gpioInfo_t *gp)
{
	return !!(gp->flags & GPIO_INITIALIZED);
}

#endif /* NET_GPIO_H_ */
