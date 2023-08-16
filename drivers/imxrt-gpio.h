/*
 * Phoenix-RTOS --- networking stack
 *
 * GPIO wrapper
 *
 * Copyright 2018 Phoenix Systems
 * Author: Phoenix Systems
 *
 * %LICENSE%
 */
#ifndef NET_GPIO_H_
#define NET_GPIO_H_

#include <sys/types.h>
#include <stdint.h>

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
	int gpio;
	int pin;
} imxrt_gpio_info_t;


int gpio_set(imxrt_gpio_info_t *gp, int active);
uint32_t gpio_get(imxrt_gpio_info_t *gp);
int gpio_wait(imxrt_gpio_info_t *gp, int active, time_t timeout);
int gpio_init(imxrt_gpio_info_t *gp, const char *arg, unsigned flags);

int gpio_getPin(int gpio, int pin, uint32_t *res);
int gpio_setPin(int gpio, int pin, int state);
int gpio_setDir(int gpio, int pin, int dir);

static inline int gpio_valid(imxrt_gpio_info_t *gp)
{
	return !!(gp->flags & GPIO_INITIALIZED);
}

#endif /* NET_GPIO_H_ */
