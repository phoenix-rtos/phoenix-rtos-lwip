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
#include "gpio.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>


#define GPIO_IMX6_ULL


static int gpio_do_set(gpio_info_t *gp, int val)
{
	uint32_t data[2];

	data[0] = val ? gp->gpio_pin : 0;
	data[1] = gp->gpio_pin;

	val = write(gp->fd, data, sizeof(data));
	if (val == sizeof(data))
		return 0;
	if (val >= 0)
		return -EIO;
	return -errno;
}


int gpio_set(gpio_info_t *gp, int active)
{
	if (!gpio_valid(gp))
		return -EINVAL;

	if (gp->flags & GPIO_INVERTED)
		active = !active;

	return gpio_do_set(gp, active);
}


uint32_t gpio_get(gpio_info_t *gp)
{
	uint32_t data[1];
	int err;

	if (!gpio_valid(gp))
		return 0;

	err = read(gp->fd, data, sizeof(data));
	if (err != sizeof(data))
		return 0;

	if (gp->flags & GPIO_INVERTED)
		data[0] = ~data[0];

	return data[0] & gp->gpio_pin;
}


int gpio_wait(gpio_info_t *gp, int active, time_t timeout)
{
	time_t when, now;
	uint32_t val;

	if (!gpio_valid(gp))
		return -EINVAL;

	if (gp->flags & GPIO_INVERTED)
		active = !active;

	gettime(&now, NULL);
	when = now + timeout;

	for (;;) {
		val = gpio_get(gp);	// FIXME: in gpiosrv
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


int gpio_init(gpio_info_t *gp, const char *arg, unsigned flags)
{
	char buf[64];
	char *endp;
	int err, fd = -1;

	if (*arg == '-') {
		++arg;
		flags ^= GPIO_INVERTED;
	}

	gpio_close(gp);

	gp->gpio_pin = strtoul(arg, &endp, 0);
	if ((*endp != ',' && *endp != ':') || gp->gpio_pin >= sizeof(gp->gpio_pin) * 8)
		return -EINVAL;
	gp->gpio_pin = 1u << gp->gpio_pin;
	arg = endp + 1;
	if (!*arg)
		return -EINVAL;
	if (strlen(arg) > sizeof(buf) - 6)
		return -EINVAL;

	gp->flags = flags & ~(GPIO_ACTIVE | GPIO_INITIALIZED);

#ifdef GPIO_IMX6_ULL
	imx6ull_gpio_config(arg, gp->gpio_pin, gp->flags);
#endif

	snprintf(buf, sizeof(buf), "%s/port", arg);
	gp->fd = open(buf, O_RDWR);
	if (gp->fd < 0)
		goto open_error;

	if (flags & GPIO_OUTPUT) {
		err = gpio_do_set(gp, !!(flags & GPIO_ACTIVE) ^ !!(flags & GPIO_INVERTED));
		if (err)
			printf("gpio: WARN: can't pre-set pin: %s (%d; fd = %d)\n", strerror(err), err, gp->fd);
	}

	fd = gp->fd;

	snprintf(buf, sizeof(buf), "%s/dir", arg);
	gp->fd = open(buf, O_RDWR);
	if (gp->fd < 0)
		goto open_error;

	err = gpio_do_set(gp, flags & GPIO_OUTPUT);
	if (err)
		printf("gpio: can't configure pin direction: %s (%d; fd = %d)\n", strerror(err), err, gp->fd);

	close(gp->fd);

	if (err)
		goto init_error;

	gp->fd = fd;
	gp->flags |= GPIO_INITIALIZED;

	return 0;

open_error:
	err = -errno;
	printf("gpio: can't open '%s': %s (%d)\n", buf, strerror(err), err);

init_error:
	if (fd >= 0)
		close(fd);
	return err;
}


int gpio_close(gpio_info_t *gp)
{
	int err;

	if (!gpio_valid(gp))
		return -EINVAL;

	err = close(gp->fd);
	gp->flags = 0;

	return err;
}
