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

enum {
	GPIO_INVERTED = 1 << 0,
	GPIO_ACTIVE = 1 << 1,
	GPIO_INPUT = 0 << 2,
	GPIO_OUTPUT = 1 << 2,
	GPIO_PULL_UP = 1 << 3,
	GPIO_PULL_DOWN = 1 << 4,
	GPIO_INITIALIZED = 1 << 7,
};


typedef struct gpio_info_ {
	unsigned flags;
	int fd;
	uint32_t pin;
} gpio_info_t;


int gpio_set(const gpio_info_t *gp, int active);
int gpio_get(const gpio_info_t *gp);
int gpio_wait(const gpio_info_t *gp, int active, time_t timeout);
int gpio_init(gpio_info_t *gp, const char *arg, unsigned flags);


static inline bool gpio_valid(const gpio_info_t *gp)
{
	return !!(gp->flags & GPIO_INITIALIZED);
}

#endif /* NET_GPIO_H_ */
