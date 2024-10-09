/*
 * Phoenix-RTOS --- networking stack
 *
 * GPIO wrapper for iMX RT106x
 *
 * Copyright 2024 Phoenix Systems
 * Author: Julian Uziembło
 *
 * %LICENSE%
 */
#include <phoenix/arch/armv7m/imxrt/10xx/imxrt10xx.h>
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
#include "lwipopts.h"


static oid_t multidrv;

#if GPIO_DEBUG
static inline void gpio_debug_printf(const char *format, ...)
{
	char buf[192];
	va_list arg;

	va_start(arg, format);
	vsnprintf(buf, sizeof(buf), format, arg);
	va_end(arg);
	printf("lwip: gpio: %s\n", buf);
}
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
	msg.oid.id = gp->num;
	msg.oid.port = multidrv.port;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	imsg = (multi_i_t *)msg.i.raw;
	imsg->gpio.type = gpio_get_port;

	err = msgSend(multidrv.port, &msg);
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
	msg.oid.id = gp->num;
	msg.oid.port = multidrv.port;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	imsg = (multi_i_t *)msg.i.raw;

	imsg->gpio.type = gpio_set_port;
	imsg->gpio.port.val = state << gp->pin;
	imsg->gpio.port.mask = 1 << gp->pin;

	return msgSend(multidrv.port, &msg);
}


static int gpio_setDir(gpio_info_t *gp, int dir)
{
	msg_t msg = { 0 };
	multi_i_t *imsg = NULL;

	msg.type = mtDevCtl;
	msg.oid.id = gp->num;
	msg.oid.port = multidrv.port;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	imsg = (multi_i_t *)msg.i.raw;

	imsg->gpio.type = gpio_set_dir;
	imsg->gpio.dir.val = dir << gp->pin;
	imsg->gpio.dir.mask = 1 << gp->pin;

	return msgSend(multidrv.port, &msg);
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
			gpio_debug_printf("gpio_wait: finished waiting");
			return EOK;
		}

		if (timeout != 0) {
			gettime(&now, NULL);
			if (now >= when) {
				gpio_debug_printf("gpio_wait: timeout");
				return -ETIME;
			}
		}
		usleep(100 * 1000);  // 100ms
	}
}

int gpio_init(gpio_info_t *gp, const char *arg, unsigned flags)
{
	gpio_debug_printf("init started, args: `%s`, flags: 0x%08x", arg, flags);

	char buf[64];
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

	if (strlen(arg) > sizeof(buf) - 6) {
		return -EINVAL;
	}

	gp->flags = flags & ~(GPIO_ACTIVE | GPIO_INITIALIZED);

	if (multidrv.port == 0) {
		while (lookup(arg, NULL, &multidrv) < 0) {
			usleep(100 * 1000);  // 100ms
		}
	}

	if (strlen(arg) < 10) {
		return -EINVAL;
	}
	gp->num = ID_GPIO(strtoul(arg + 9, NULL, 10));
	if (gp->num < id_gpio1 || gp->num > id_gpio13) {
		return -EINVAL;
	}

	gpio_debug_printf("got multidrv, oid=%u (0x%08x), port=%d (0x%08x)",
			multidrv.id, multidrv.id, multidrv.port, multidrv.port);
	gpio_debug_printf("before sending messages, gp={.num=%u, .pin=%u, .flags=0x%08x}",
			gp->num, gp->pin, gp->flags);

	err = gpio_setDir(gp, !!(flags & GPIO_OUTPUT));
	if (err != 0) {
		gpio_debug_printf("WARN: can't configure pin direction: %s (%d)", strerror(err), err);
		return err;
	}

	err = gpio_setPin(gp, !!(flags & GPIO_ACTIVE) ^ !!(flags & GPIO_INVERTED));
	if (err != 0) {
		gpio_debug_printf("WARN: can't pre-set pin: %s (%d)", strerror(err), err);
		return err;
	}

	gp->flags |= GPIO_INITIALIZED;
	return 0;
}
