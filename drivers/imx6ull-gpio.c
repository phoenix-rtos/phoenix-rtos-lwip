/*
 * Phoenix-RTOS --- networking stack
 *
 * iMX6ULL GPIO hack (mask missing functionality in gpiosrv)
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * %LICENSE%
 */
#include "gpio.h"

#include <sys/platform.h>
#include <phoenix/arch/imx6ull.h>
#include <string.h>


struct pin_conf {
	uint32_t mask;
	uint32_t mux0;
	uint32_t pad0;
};

static const struct pin_conf pin_conf0[] = {
	{ 0, }
};

static const struct pin_conf pin_conf1[] = {
	{ 0x000003ff, pctl_mux_gpio1_00, pctl_pad_gpio1_00 },
	{ 0x0000fc00, pctl_mux_jtag_mod - 10, pctl_pad_jtag_mod - 10 },
	{ 0xffff0000, pctl_mux_uart1_tx - 16, pctl_pad_uart1_tx - 16 },
	{ 0, }
};

static const struct pin_conf pin_conf5[] = {
	{ 0x000003ff, pctl_mux_tamper0, pctl_pad_tamper0 },
	{ 0x00000c00, pctl_mux_boot_mode0 - 10, pctl_pad_boot0 - 10 },
	{ 0, }
};

static const struct pin_conf *const imx_gpio_pin[5] = {  pin_conf1,  pin_conf0,  pin_conf0,  pin_conf0,  pin_conf5 };


static int imx6ull_set_pin_conf(unsigned mux, unsigned pad, unsigned flags)
{
	platformctl_t pmux;
	int err;

	pmux.action = pctl_set;
	pmux.type = pctl_iomux;
	pmux.iomux.mux = mux;
	pmux.iomux.sion = 0;
	pmux.iomux.mode = 5;

	if ((err = platformctl(&pmux)))
		return err;

	pmux.action = pctl_set;
	pmux.type = pctl_iopad;
	pmux.iopad.pad = pad;
	pmux.iopad.hys = 0;
	pmux.iopad.pus = flags & GPIO_PULL_UP ? 2 : 0;
	pmux.iopad.pue = !!(flags & (GPIO_PULL_DOWN | GPIO_PULL_UP));
	pmux.iopad.pke = !!(flags & (GPIO_PULL_DOWN | GPIO_PULL_UP));
	pmux.iopad.ode = 0;
	pmux.iopad.speed = 2;
	pmux.iopad.dse = 1;
	pmux.iopad.sre = 0;

	return platformctl(&pmux);
}


int imx6ull_gpio_config(const char *name, uint32_t mask, unsigned flags)
{
	const struct pin_conf *pinc;
	unsigned instance;
	uint32_t v, ov;
	int err = 0;

	if (strncmp("/dev/gpio", name, 9))
		return 0;
	if (name[9] < '1' || name[9] > '5' || name[10])
		return 0;
	instance = name[9] - '1';

	for (pinc = imx_gpio_pin[instance]; pinc->mask; ++pinc) {
		v = mask & pinc->mask;
		while (v) {
			ov = __builtin_ctz(v);
			v &= ~(1 << ov);
			err = imx6ull_set_pin_conf(pinc->mux0 + ov, pinc->pad0 + ov, flags);
		}
	}

	return err;
}
