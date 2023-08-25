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
#include "imxrt-gpio.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#include <sys/msg.h>
#include <sys/threads.h>

#include <imxrt-multi.h>


static struct {
	oid_t multidrv;
} gpio_common;

int gpio_set(imxrt_gpio_info_t *gp, int active)
{
	if (!gpio_valid(gp))
		return -EINVAL;

	if (gp->flags & GPIO_INVERTED)
		active = !active;

	return gpio_setPin(gp->gpio, gp->pin, active);
}


uint32_t gpio_get(imxrt_gpio_info_t *gp)
{
	uint32_t data[1];
	int err;

	if (!gpio_valid(gp))
		return 0;

	uint32_t buf = 0;
	gpio_getPin(gp->gpio, gp->pin, &buf);

	return buf;
}


int gpio_wait(imxrt_gpio_info_t *gp, int active, time_t timeout)
{
	time_t when, now;
	uint32_t val;

	if (!gpio_valid(gp))
		return -EINVAL;

	gettime(&now, NULL);
	when = now + timeout;

	for (;;) {
		val = gpio_get(gp);

		if (!active ^ !val)
			return 0;

		if (timeout) {
			gettime(&now, NULL);
			if (now >= when)
				return -ETIME;
			now = when - now;
			if (now > 100000)
				now = 100000;
		} else
			now = 100000;

		usleep(now);
	}
}


int gpio_init(imxrt_gpio_info_t *gp, const char *arg, unsigned flags)
{
	char buf[64];
	char *endp;
	int err, fd = -1;

	if (gpio_common.multidrv.port == 0) {
		while (lookup("/dev/gpio1", NULL, &gpio_common.multidrv) < 0)
			usleep(100 * 1000);
	}

	if (*arg == '-') {
		++arg;
		flags |= GPIO_INVERTED;
	}

	gp->pin = strtoul(arg, &endp, 0);

	if ((*endp != ',' && *endp != ':') || gp->pin >= sizeof(gp->pin) * 8) {
		return -EINVAL;
	}
	
	arg = endp + 1;

	if (!*arg) {
		return -EINVAL;
	}

	if (strlen(arg) > sizeof(buf) - 6) {
		return -EINVAL;
	}

	gp->flags = flags & ~(GPIO_ACTIVE | GPIO_INITIALIZED);

	printf("\tgpio_init: arg=%s flags=%d gpio_pin=%d dir=%d port=%d\n", arg, flags, gp->pin, !!(flags & GPIO_OUTPUT), !!(flags & GPIO_ACTIVE) ^ !!(flags & GPIO_INVERTED));

	gpio_setDir(id_gpio1, gp->pin, !!(flags & GPIO_OUTPUT));
	if (err) {
		printf("gpio: can't configure pin direction: %s (%d)\n", strerror(err), err);
		return err;
	}

	err = gpio_setPin(id_gpio1, gp->pin, !!(flags & GPIO_ACTIVE) ^ !!(flags & GPIO_INVERTED));
	if (err) {
		printf("gpio: WARN: can't pre-set pin: %s (%d)\n", strerror(err), err);
		return err;
	}

	gp->flags |= GPIO_INITIALIZED;
	return 0;
}

int gpio_getPin(int gpio, int pin, uint32_t *res)
{
	msg_t msg;
	multi_i_t *imsg = NULL;
	multi_o_t *omsg = NULL;
	int err;

	msg.type = mtDevCtl;
	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	imsg = (multi_i_t *)msg.i.raw;
	omsg = (multi_i_t *)msg.o.raw;

	imsg->id = gpio;
	imsg->gpio.type = gpio_get_port;

	*res = omsg->val;

	err = msgSend(gpio_common.multidrv.port, &msg);
	if (err < 0) {
		return err;
	}
	*res = omsg->val;

	return omsg->err;
}


int gpio_setPin(int gpio, int pin, int state)
{
	msg_t msg;
	multi_i_t *imsg = NULL;

	msg.type = mtDevCtl;
	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	imsg = (multi_i_t *)msg.i.raw;

	imsg->id = gpio;
	imsg->gpio.type = gpio_set_port;
	imsg->gpio.port.val = !!state << pin;
	imsg->gpio.port.mask = 1 << pin;

	return msgSend(gpio_common.multidrv.port, &msg);
}


int gpio_setDir(int gpio, int pin, int dir)
{
	msg_t msg;
	multi_i_t *imsg = NULL;   

	msg.type = mtDevCtl;
	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	imsg = (multi_i_t *)msg.i.raw;

	imsg->id = gpio;
	imsg->gpio.type = gpio_set_dir;
	imsg->gpio.dir.val = !!dir << pin;
	imsg->gpio.dir.mask = 1 << pin;

	return msgSend(gpio_common.multidrv.port, &msg);
}
