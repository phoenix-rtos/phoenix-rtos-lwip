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

#include "gpio.h"
#include "imxrt-multi.h"

#define GPIO_DEBUG 0


#if GPIO_DEBUG
#define gpio_debug_printf(gp, fmt, ...) printf("lwip: gpio%02u_io%02u: " fmt "\n", gp->id - id_gpio1 + 1, gp->pin, ##__VA_ARGS__)
#else
#define gpio_debug_printf(...)
#endif

#define ID_GPIO(n) (id_gpio1 + n - 1)


static int gpio_getPin(gpio_info_t *gp, uint32_t *res)
{
	msg_t msg = { 0 };
	multi_i_t *imsg = NULL;
	int err = 0;

	msg.type = mtDevCtl;
	msg.oid.id = gp->id;
	msg.oid.port = gp->multidrv.port;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	imsg = (multi_i_t *)msg.i.raw;
	imsg->gpio.type = gpio_get_port;

	err = msgSend(gp->multidrv.port, &msg);
	if (err < 0) {
		return err;
	}

	*res = ((multi_o_t *)(msg.o.raw))->val;

	return err;
}


static int gpio_setPin(gpio_info_t *gp, int state)
{
	msg_t msg = { 0 };
	multi_i_t *imsg = NULL;

	msg.type = mtDevCtl;
	msg.oid.id = gp->id;
	msg.oid.port = gp->multidrv.port;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	imsg = (multi_i_t *)msg.i.raw;

	imsg->gpio.type = gpio_set_port;
	imsg->gpio.port.val = state << gp->pin;
	imsg->gpio.port.mask = 1 << gp->pin;

	return msgSend(gp->multidrv.port, &msg);
}


static int gpio_setDir(gpio_info_t *gp, int dir)
{
	msg_t msg = { 0 };
	multi_i_t *imsg = NULL;

	msg.type = mtDevCtl;
	msg.oid.id = gp->id;
	msg.oid.port = gp->multidrv.port;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	imsg = (multi_i_t *)msg.i.raw;

	imsg->gpio.type = gpio_set_dir;
	imsg->gpio.dir.val = dir << gp->pin;
	imsg->gpio.dir.mask = 1 << gp->pin;

	return msgSend(gp->multidrv.port, &msg);
}

int gpio_set(gpio_info_t *gp, int active)
{
	if (!gpio_valid(gp)) {
		return -EINVAL;
	}

	if ((gp->flags & GPIO_INVERTED) != 0) {
		active = !active;
	}

	return gpio_setPin(gp, active);
}


uint32_t gpio_get(gpio_info_t *gp)
{
	if (!gpio_valid(gp)) {
		return 0;
	}

	uint32_t ret = 0;
	gpio_getPin(gp, &ret);

	if ((gp->flags & GPIO_INVERTED) != 0) {
		ret = ~ret;
	}

	return ret;
}

int gpio_wait(gpio_info_t *gp, int active, time_t timeout)
{
	time_t when, now;
	uint32_t val;

	if (!gpio_valid(gp)) {
		return -EINVAL;
	}

	gettime(&now, NULL);
	when = now + timeout;

	for (;;) {
		val = gpio_get(gp);

		if (!!((1 << gp->pin) & val) == !!(active)) {
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

int gpio_init(gpio_info_t *gp, const char *arg, unsigned flags)
{
	char *endp;
	int err;

	if (*arg == '-') {
		++arg;
		flags |= GPIO_INVERTED;
	}

	gp->pin = strtoul(arg, &endp, 0);

	if ((*endp != ',' && *endp != ':') || gp->pin >= (sizeof(gp->pin) * 8)) {
		return -EINVAL;
	}

	arg = endp + 1;

	if (*arg == '\0') {
		return -EINVAL;
	}

	gp->flags = flags & ~(GPIO_ACTIVE | GPIO_INITIALIZED);

	if (strlen(arg) < 10) {
		return -EINVAL;
	}

	gp->id = ID_GPIO(strtoul(arg + 9, NULL, 10));
	if (gp->id < id_gpio1 || gp->id > id_gpio13) {
		return -EINVAL;
	}

	if (gp->multidrv.port == 0) {
		while (lookup(arg, NULL, &gp->multidrv) < 0) {
			usleep(100 * 1000);
		}
	}

	gpio_debug_printf(gp, "oid=%u, port=%d", multidrv.id, multidrv.port);
	gpio_debug_printf(gp, "gp->flags=0x%08x", gp->flags);

	err = gpio_setDir(gp, !!(flags & GPIO_OUTPUT));
	if (err != 0) {
		gpio_debug_printf(gp, "WARN: can't configure pin direction: %s (%d)", strerror(err), err);
		return err;
	}

	err = gpio_setPin(gp, !!(flags & GPIO_ACTIVE) ^ !!(flags & GPIO_INVERTED));
	if (err != 0) {
		gpio_debug_printf(gp, "WARN: can't pre-set pin: %s (%d)", strerror(err), err);
		return err;
	}

	gp->flags |= GPIO_INITIALIZED;
	return 0;
}
