/*
 * Phoenix-RTOS --- networking stack
 *
 * GPIO wrapper for iMX RT106x/RT117x
 *
 * Copyright 2024 Phoenix Systems
 * Author: Julian Uziembło
 *
 * %LICENSE%
 */
#if defined(__CPU_IMXRT106X)
#include <phoenix/arch/armv7m/imxrt/10xx/imxrt10xx.h>
#elif defined(__CPU_IMXRT117X)
#include <phoenix/arch/armv7m/imxrt/11xx/imxrt1170.h>
#else
#error "Unsupported TARGET"
#endif
#include <phoenix/types.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/msg.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <limits.h>

#include "gpio.h"
#include "imxrt-multi.h"

#define GPIO_DEBUG 0


#define gpio_printf(gp, fmt, ...) printf("lwip: gpio%02u_io%02u: " fmt "\n", gp->id - id_gpio1 + 1, gp->pin, ##__VA_ARGS__)

#if GPIO_DEBUG
#define gpio_debug_printf(gp, fmt, ...) gpio_printf(gp, fmt, ##__VA_ARGS__)
#else
#define gpio_debug_printf(...)
#endif

#define GPIO_MAX_PIN         (31)
#define GPIO_PORT_PREFIX     "/dev/gpio"
#define GPIO_PORT_PREFIX_LEN (sizeof(GPIO_PORT_PREFIX) - 1)


static int gpio_getPin(const gpio_info_t *gp, uint32_t *res)
{
	int err;
	msg_t msg = {
		.type = mtDevCtl,
		.oid = {
			.id = gp->id,
			.port = gp->multidrv.port,
		},
	};
	multi_i_t *imsg = (multi_i_t *)msg.i.raw;

	imsg->gpio.type = gpio_get_port;

	err = msgSend(gp->multidrv.port, &msg);
	if (err < 0) {
		return err;
	}
	if (msg.o.err < 0) {
		return msg.o.err;
	}

	*res = ((multi_o_t *)msg.o.raw)->val;

	return 0;
}


static int gpio_setPin(const gpio_info_t *gp, int state)
{
	int err;
	msg_t msg = {
		.type = mtDevCtl,
		.oid = {
			.id = gp->id,
			.port = gp->multidrv.port,
		},
	};
	multi_i_t *imsg = (multi_i_t *)msg.i.raw;

	imsg->gpio.type = gpio_set_port;
	imsg->gpio.port.val = state << gp->pin;
	imsg->gpio.port.mask = 1 << gp->pin;

	err = msgSend(gp->multidrv.port, &msg);
	if (err < 0) {
		return err;
	}
	if (msg.o.err < 0) {
		return msg.o.err;
	}

	return 0;
}


static int gpio_setDir(const gpio_info_t *gp, int dir)
{
	int err;
	msg_t msg = {
		.type = mtDevCtl,
		.oid = {
			.id = gp->id,
			.port = gp->multidrv.port,
		},
	};
	multi_i_t *imsg = (multi_i_t *)msg.i.raw;

	imsg->gpio.type = gpio_set_dir;
	imsg->gpio.dir.val = dir << gp->pin;
	imsg->gpio.dir.mask = 1 << gp->pin;

	err = msgSend(gp->multidrv.port, &msg);
	if (err < 0) {
		return err;
	}
	if (msg.o.err < 0) {
		return msg.o.err;
	}

	return 0;
}

int gpio_set(const gpio_info_t *gp, int active)
{
	if (!gpio_valid(gp)) {
		return -EINVAL;
	}

	if ((gp->flags & GPIO_INVERTED) != 0) {
		active = !active;
	}

	return gpio_setPin(gp, active);
}


int gpio_get(const gpio_info_t *gp)
{
	if (!gpio_valid(gp)) {
		return -EINVAL;
	}

	uint32_t ret = 0;
	int err = gpio_getPin(gp, &ret);
	if (err < 0) {
		return err;
	}

	if ((gp->flags & GPIO_INVERTED) != 0) {
		ret = ~ret;
	}

	return !!(ret & (1u << gp->pin));
}

int gpio_wait(const gpio_info_t *gp, int active, time_t timeout)
{
	time_t when, now;
	int val;

	if (!gpio_valid(gp)) {
		return -EINVAL;
	}

	if (timeout != 0) {
		gettime(&now, NULL);
		when = now + timeout;
	}

	for (;;) {
		val = gpio_get(gp);
		if (val < 0) {
			return val;
		}

		if (!!val == !!active) {
			gpio_debug_printf(gp, "gpio_wait: finished waiting");
			return EOK;
		}

		if (timeout != 0) {
			gettime(&now, NULL);
			if (now >= when) {
				gpio_debug_printf(gp, "gpio_wait: timeout");
				return -ETIME;
			}
		}
		usleep(100 * 1000);  // 100ms
	}
}

/* arg like: `X:/dev/gpioY`, where:
 * X = GPIO pin
 * Y = GPIO port
 */
int gpio_init(gpio_info_t *gp, const char *arg, unsigned flags)
{
	char *endp;
	const char *gpio_prefix;
	int err;
	unsigned long res;

	if (arg == NULL || strlen(arg) == 0) {
		return -EINVAL;
	}

	if (*arg == '-') {
		++arg;
		flags |= GPIO_INVERTED;
	}

	gp->flags = flags & ~(GPIO_ACTIVE | GPIO_INITIALIZED);

	errno = 0;
	gp->pin = strtoul(arg, &endp, 0);
	if (errno != 0 || endp == arg || gp->pin == ULONG_MAX) {
		return -EINVAL;
	}
	if (*endp != ':' || gp->pin > GPIO_MAX_PIN) {
		return -EINVAL;
	}

	arg = endp + 1;
	if (strncmp(arg, GPIO_PORT_PREFIX, GPIO_PORT_PREFIX_LEN) != 0) {
		return -EINVAL;
	}
	gpio_prefix = arg;
	arg += GPIO_PORT_PREFIX_LEN;

	errno = 0;
	res = strtoul(arg, &endp, 10);
	if (errno != 0 || endp == arg || res == ULONG_MAX) {
		return -EINVAL;
	}

	gp->id = id_gpio1 - 1 + res;
	if (gp->id < id_gpio1 || gp->id > id_gpio13) {
		return -EINVAL;
	}

	if (gp->multidrv.port == 0) {
		while (lookup(gpio_prefix, NULL, &gp->multidrv) < 0) {
			usleep(100 * 1000);
		}
	}

	gpio_debug_printf(gp, "oid=%u, port=%d", multidrv.id, multidrv.port);
	gpio_debug_printf(gp, "gp->flags=0x%08x", gp->flags);

	err = gpio_setDir(gp, !!(flags & GPIO_OUTPUT));
	if (err != 0) {
		gpio_printf(gp, "WARN: can't configure pin direction: %s (%d)", strerror(-err), err);
		return err;
	}

	err = gpio_setPin(gp, !!(flags & GPIO_ACTIVE) ^ !!(flags & GPIO_INVERTED));
	if (err != 0) {
		gpio_printf(gp, "WARN: can't pre-set pin: %s (%d)", strerror(-err), err);
		return err;
	}

	gp->flags |= GPIO_INITIALIZED;
	return 0;
}
