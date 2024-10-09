/*
 * Phoenix-RTOS --- networking stack
 *
 * GPIO wrapper for iMX 6ULL
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
#include <sys/platform.h>
#include <limits.h>
#include <phoenix/arch/armv7a/imx6ull/imx6ull.h>
#include <string.h>
#include <errno.h>

#define GPIO_MAX_PIN (31)

struct pin_conf {
	uint32_t mask;
	uint32_t mux0;
	uint32_t pad0;
};

static const struct pin_conf pin_conf0[] = {
	{ 0 }
};

static const struct pin_conf pin_conf1[] = {
	{ 0x000003ff, pctl_mux_gpio1_00, pctl_pad_gpio1_00 },
	{ 0x0000fc00, pctl_mux_jtag_mod - 10, pctl_pad_jtag_mod - 10 },
	{ 0xffff0000, pctl_mux_uart1_tx - 16, pctl_pad_uart1_tx - 16 },
	{ 0 }
};

static const struct pin_conf pin_conf5[] = {
	{ 0x000003ff, pctl_mux_tamper0, pctl_pad_tamper0 },
	{ 0x00000c00, pctl_mux_boot_mode0 - 10, pctl_pad_boot0 - 10 },
	{ 0 }
};

static const struct pin_conf *const imx_gpio_pin[5] = { pin_conf1, pin_conf0, pin_conf0, pin_conf0, pin_conf5 };


static int gpio_setPinConf(unsigned mux, unsigned pad, unsigned flags)
{
	platformctl_t pmux;
	int err;

	pmux.action = pctl_set;
	pmux.type = pctl_iomux;
	pmux.iomux.mux = mux;
	pmux.iomux.sion = 0;
	pmux.iomux.mode = 5;

	err = platformctl(&pmux);
	if (err != 0) {
		return err;
	}

	pmux.action = pctl_set;
	pmux.type = pctl_iopad;
	pmux.iopad.pad = pad;
	pmux.iopad.hys = 0;
	pmux.iopad.pus = ((flags & GPIO_PULL_UP) != 0) ? 2 : 0;
	pmux.iopad.pue = !!(flags & (GPIO_PULL_DOWN | GPIO_PULL_UP));
	pmux.iopad.pke = !!(flags & (GPIO_PULL_DOWN | GPIO_PULL_UP));
	pmux.iopad.ode = 0;
	pmux.iopad.speed = 2;
	pmux.iopad.dse = 1;
	pmux.iopad.sre = 0;

	return platformctl(&pmux);
}


static int gpio_config(const char *name, uint32_t mask, unsigned flags)
{
	const struct pin_conf *pinc;
	unsigned instance;
	uint32_t v, ov;
	int err = 0;

	if (strncmp("/dev/gpio", name, 9) != 0) {
		return -EINVAL;
	}
	if (name[9] < '1' || name[9] > '5' || name[10] != '\0') {
		return -EINVAL;
	}
	instance = name[9] - '1';

	for (pinc = imx_gpio_pin[instance]; pinc->mask; ++pinc) {
		v = mask & pinc->mask;
		while (v) {
			ov = __builtin_ctz(v);
			v &= ~(1 << ov);
			err = gpio_setPinConf(pinc->mux0 + ov, pinc->pad0 + ov, flags);
		}
	}

	return err;
}


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


static int gpio_close(gpio_info_t *gp)
{
	int err;

	if (!gpio_valid(gp)) {
		return -EINVAL;
	}

	err = close(gp->fd);
	gp->flags = 0;

	return err;
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

	err = gpio_config(arg, gp->pin, gp->flags);
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
