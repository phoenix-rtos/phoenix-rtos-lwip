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
#include <limits.h>

#define GPIO_MAX_PIN (31)


static int gpio_doSet(const gpio_info_t *gp, int val)
{
	uint32_t data[2];

	data[0] = val ? gp->pin : 0;
	data[1] = gp->pin;

	val = write(gp->fd, data, sizeof(data));
	if (val == sizeof(data)) {
		return 0;
	}
	if (val >= 0) {
		return -EIO;
	}
	return -errno;
}


int gpio_set(const gpio_info_t *gp, int active)
{
	if (!gpio_valid(gp)) {
		return -EINVAL;
	}

	if ((gp->flags & GPIO_INVERTED) != 0) {
		active = !active;
	}

	return gpio_doSet(gp, active);
}


int gpio_get(const gpio_info_t *gp)
{
	uint32_t data[1];
	int err;

	if (!gpio_valid(gp)) {
		return -EINVAL;
	}

	err = read(gp->fd, data, sizeof(data));
	if (err < 0) {
		return -errno;
	}
	if (err != sizeof(data)) {
		return -EIO;
	}

	if ((gp->flags & GPIO_INVERTED) != 0) {
		data[0] = ~data[0];
	}

	return !!(data[0] & gp->pin);
}


int gpio_wait(const gpio_info_t *gp, int active, time_t timeout)
{
	time_t when, now;
	int val;

	if (!gpio_valid(gp)) {
		return -EINVAL;
	}

	if ((gp->flags & GPIO_INVERTED) != 0) {
		active = !active;
	}

	if (timeout != 0) {
		gettime(&now, NULL);
		when = now + timeout;
	}

	for (;;) {
		val = gpio_get(gp);  // FIXME: in gpiosrv
		if (val < 0) {
			return val;
		}
		if (!!active == !!val) {
			return 0;
		}

		if (timeout != 0) {
			gettime(&now, NULL);
			if (now >= when) {
				return -ETIME;
			}
			now = when - now;
			if (now > 100000) {
				now = 100000;
			}
		}
		else {
			now = 100000;
		}

		usleep(now);
	}
}


int gpio_init(gpio_info_t *gp, const char *arg, unsigned flags)
{
	char buf[64];
	char *endp;
	int err, port_fd;

	if (arg == NULL || strlen(arg) == 0) {
		return -EINVAL;
	}

	if (*arg == '-') {
		++arg;
		flags |= GPIO_INVERTED;
	}

	gpio_close(gp);

	gp->flags = flags & ~(GPIO_ACTIVE | GPIO_INITIALIZED);

	errno = 0;
	gp->pin = strtoul(arg, &endp, 0);
	if (errno != 0 || endp == arg || gp->pin == ULONG_MAX) {
		return -EINVAL;
	}
	if ((*endp != ',' && *endp != ':') || gp->pin > GPIO_MAX_PIN) {
		return -EINVAL;
	}

	gp->pin = 1u << gp->pin;
	arg = endp + 1;
	if (*arg == '\0') {
		return -EINVAL;
	}
	if (strlen(arg) > sizeof(buf) - 6) {
		return -EINVAL;
	}

	err = imx6ull_gpio_config(arg, gp->pin, gp->flags);
	if (err < 0) {
		return err;
	}

	snprintf(buf, sizeof(buf), "%s/port", arg);
	gp->fd = open(buf, O_RDWR);
	if (gp->fd < 0) {
		err = -errno;
		printf("gpio: can't open '%s': %s (%d)\n", buf, strerror(errno), -errno);
		return err;
	}

	if ((flags & GPIO_OUTPUT) != 0) {
		err = gpio_doSet(gp, !!(flags & GPIO_ACTIVE) ^ !!(flags & GPIO_INVERTED));
		if (err != 0) {
			printf("gpio: WARN: can't pre-set pin: %s (%d; fd = %d)\n", strerror(-err), err, gp->fd);
		}
	}

	port_fd = gp->fd; /* save gpio port file descriptor */

	snprintf(buf, sizeof(buf), "%s/dir", arg);
	gp->fd = open(buf, O_RDWR);
	if (gp->fd < 0) {
		err = -errno;
		printf("gpio: can't open '%s': %s (%d)\n", buf, strerror(-err), err);
		close(port_fd);
		return err;
	}

	err = gpio_doSet(gp, flags & GPIO_OUTPUT);
	if (err != 0) {
		printf("gpio: can't configure pin direction: %s (%d; fd = %d)\n", strerror(-err), err, gp->fd);
		close(gp->fd);
		close(port_fd);
		return err;
	}

	gp->fd = port_fd; /* restore gpio port file descriptor */
	gp->flags |= GPIO_INITIALIZED;

	return 0;
}


int gpio_close(gpio_info_t *gp)
{
	int err;

	if (!gpio_valid(gp)) {
		return -EINVAL;
	}

	err = close(gp->fd);
	gp->flags = 0;

	return err;
}
