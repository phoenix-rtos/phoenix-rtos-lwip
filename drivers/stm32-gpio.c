/*
 * Phoenix-RTOS --- networking stack
 *
 * STM32 GPIO interface for PHY driver
 *
 * Copyright 2024, 2026 Phoenix Systems
 * Author: Julian Uziembło, Jacek Maksymowicz
 *
 * %LICENSE%
 */

#if defined(__CPU_STM32N6)
#include <phoenix/arch/armv8m/stm32/n6/stm32n6.h>
#else
#error "Unsupported TARGET"
#endif
#include <phoenix/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/msg.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <limits.h>
#include <stm32l4-multi.h>
#include <ctype.h>

#include "gpio.h"
#include "stm32-gpio.h"

#define GPIO_DEBUG 0

#define gpio_printf(gp, fmt, ...) printf("lwip: gpio P%c%u: " fmt "\n", (gp->id - gpioa + 'A'), gp->pin, ##__VA_ARGS__)

#if GPIO_DEBUG
#define gpio_debug_printf(gp, fmt, ...) gpio_printf(gp, fmt, ##__VA_ARGS__)
#else
#define gpio_debug_printf(...)
#endif

#define GPIO_MAX_PIN (15)
#define GPIO_PORT_PREFIX     "/dev/gpio"
#define GPIO_PORT_PREFIX_LEN (sizeof(GPIO_PORT_PREFIX) - 1)


int stm32_pinConfig(const oid_t *dev, int port, uint8_t pin, int afMode)
{
	char mode, af;
	msg_t msg = {
		.type = mtDevCtl,
		.oid = *dev
	};

	multi_i_t *i = (multi_i_t *)msg.i.raw;
	i->type = gpio_def;
	if (afMode == STM32_PIN_CONFIG_OUTPUT) {
		mode = gpio_mode_gpo;
		af = 0;
	}
	else if (afMode == STM32_PIN_CONFIG_INPUT) {
		mode = gpio_mode_gpi;
		af = 0;
	}
	else if (afMode < 0) {
		return -EINVAL;
	}
	else {
		mode = gpio_mode_af;
		af = afMode;
	}

	i->type = gpio_def;
	i->gpio_def = (gpiodef_t) {
		.port = port,
		.pin = pin,
		.mode = mode,
		.af = af,
		.otype = gpio_otype_pp,
		.ospeed = gpio_ospeed_hi,
		.pupd = gpio_pupd_nopull,
	};

	int ret = msgSend(dev->port, &msg);
	if (ret < 0) {
		return ret;
	}

	return msg.o.err;
}


int stm32_pinSet(const oid_t *dev, int port, uint8_t pin, uint8_t state)
{
	msg_t msg = {
		.type = mtDevCtl,
		.oid = *dev
	};

	multi_i_t *i = (multi_i_t *)msg.i.raw;
	i->type = gpio_set;
	i->gpio_set = (gpioset_t) {
		.port = port,
		.mask = (1UL << pin),
		.state = (state != 0) ? (1UL << pin) : 0UL,
	};

	int ret = msgSend(dev->port, &msg);
	if (ret < 0) {
		return ret;
	}

	return msg.o.err;
}


int stm32_pinGet(const oid_t *dev, int port, uint8_t pin, uint8_t *state)
{
	msg_t msg = {
		.type = mtDevCtl,
		.oid = *dev
	};

	multi_i_t *i = (multi_i_t *)msg.i.raw;
	multi_o_t *o = (multi_o_t *)msg.o.raw;
	i->type = gpio_get;
	i->gpio_get = (gpioget_t) {
		.port = port,
	};

	int ret = msgSend(dev->port, &msg);
	if (ret < 0) {
		return ret;
	}

	if (msg.o.err >= 0) {
		*state = (o->gpio_get >> pin) & 1u;
	}

	return msg.o.err;
}


int net_gpioSet(const net_gpioInfo_t *gp, int active)
{
	if (!net_gpioValid(gp)) {
		return -EINVAL;
	}

	if ((gp->flags & GPIO_INVERTED) != 0) {
		active = !active;
	}

	return stm32_pinSet(&gp->multidrv, gp->id, gp->pin, active != 0 ? 1 : 0);
}


int net_gpioGet(const net_gpioInfo_t *gp)
{
	if (!net_gpioValid(gp)) {
		return -EINVAL;
	}

	uint8_t ret = 0;

	int err = stm32_pinGet(&gp->multidrv, gp->id, gp->pin, &ret);
	if (err < 0) {
		return err;
	}

	if ((gp->flags & GPIO_INVERTED) != 0) {
		ret = ~ret;
	}

	return ret != 0 ? 1 : 0;
}


int net_gpioWait(const net_gpioInfo_t *gp, int active, time_t timeout)
{
	time_t when, now;
	int val;

	if (!net_gpioValid(gp)) {
		return -EINVAL;
	}

	if (timeout != 0) {
		gettime(&now, NULL);
		when = now + timeout;
	}

	for (;;) {
		val = net_gpioGet(gp);
		if (val < 0) {
			return val;
		}

		if (!!val == !!active) {
			gpio_debug_printf(gp, "net_gpioWait: finished waiting");
			return EOK;
		}

		if (timeout != 0) {
			gettime(&now, NULL);
			if (now >= when) {
				gpio_debug_printf(gp, "net_gpioWait: timeout");
				return -ETIME;
			}
		}
		usleep(100 * 1000);  // 100ms
	}
}


int net_gpioInit(net_gpioInfo_t *gp, const char *arg, unsigned flags)
{
	char *endp;
	int err;

	if (arg == NULL || strlen(arg) == 0) {
		return -EINVAL;
	}

	if (*arg == '-') {
		++arg;
		flags |= GPIO_INVERTED;
	}

	gp->flags = flags & ~(GPIO_ACTIVE | GPIO_INITIALIZED);

	errno = 0;
	unsigned long int pin = strtoul(arg, &endp, 0);
	if (errno != 0 || endp == arg || pin == ULONG_MAX) {
		return -EINVAL;
	}

	if (*endp != ':' || pin > GPIO_MAX_PIN) {
		return -EINVAL;
	}

	arg = endp + 1;
	if (strncmp(GPIO_PORT_PREFIX, arg, GPIO_PORT_PREFIX_LEN) != 0) {
		return -EINVAL;
	}

	arg += GPIO_PORT_PREFIX_LEN;
	char portLetter = tolower(*arg);
	if ((portLetter < 'a') || (portLetter > 'z')) {
		return -EINVAL;
	}

	/*
	 * We assume that gpio* enum values are aligned with increasing letter numbers.
	 * Because actual hardware ports may be discontinuous, we rely on multidriver to do final verification.
	 */
	int port = gpioa + (int)(portLetter - 'a');

	gp->id = port;
	gp->pin = pin;
	if (gp->multidrv.port == 0) {
		while (lookup(STM32_MULTI_PATH, NULL, &gp->multidrv) < 0) {
			usleep(100 * 1000);
		}
	}

	gpio_debug_printf(gp, "oid=%u, port=%d", gp->multidrv.id, gp->multidrv.port);
	gpio_debug_printf(gp, "gp->flags=0x%08x", gp->flags);

	if ((flags & GPIO_OUTPUT) != 0) {
		err = stm32_pinSet(&gp->multidrv, gp->id, gp->pin, !!(flags & GPIO_ACTIVE) ^ !!(flags & GPIO_INVERTED));
		if (err != 0) {
			gpio_printf(gp, "WARN: can't pre-set pin: %s (%d)", strerror(-err), err);
			return err;
		}
	}

	int mode = ((flags & GPIO_OUTPUT) != 0) ? STM32_PIN_CONFIG_OUTPUT : STM32_PIN_CONFIG_INPUT;
	err = stm32_pinConfig(&gp->multidrv, gp->id, gp->pin, mode);
	if (err != 0) {
		gpio_printf(gp, "WARN: can't configure pin direction: %s (%d)", strerror(-err), err);
		return err;
	}

	gp->flags |= GPIO_INITIALIZED;
	return 0;
}
