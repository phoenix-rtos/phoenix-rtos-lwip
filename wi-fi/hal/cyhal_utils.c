/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP Wi-Fi
 *
 * Copyright 2021 Phoenix Systems
 * Author: Ziemowit Leszczynski
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cyhal_utils.h"


int cyhal_utils_set_iomux(int mux, char mode)
{
	platformctl_t ctl;

	ctl.action = pctl_set;
	ctl.type = pctl_iomux;
	ctl.iomux.mux = mux;
	ctl.iomux.sion = 0;
	ctl.iomux.mode = mode;

	return platformctl(&ctl);
}


int cyhal_utils_set_iosel(int isel, char daisy)
{
	platformctl_t ctl;

	ctl.action = pctl_set;
	ctl.type = pctl_ioisel;
	ctl.ioisel.isel = isel;
	ctl.ioisel.daisy = daisy;

	return platformctl(&ctl);
}


int cyhal_utils_set_iopad(int pad, char hys, char pus, char pue, char pke, char ode, char speed, char dse, char sre)
{
	platformctl_t ctl;

	ctl.action = pctl_set;
	ctl.type = pctl_iopad;
	ctl.iopad.pad = pad;
	ctl.iopad.hys = hys;
	ctl.iopad.pus = pus;
	ctl.iopad.pue = pue;
	ctl.iopad.pke = pke;
	ctl.iopad.ode = ode;
	ctl.iopad.speed = speed;
	ctl.iopad.dse = dse;
	ctl.iopad.sre = sre;

	return platformctl(&ctl);
}


int cyhal_utils_set_devclk(int dev, unsigned int state)
{
	platformctl_t ctl;

	ctl.action = pctl_set;
	ctl.type = pctl_devclock;
	ctl.devclock.dev = dev;
	ctl.devclock.state = state;

	return platformctl(&ctl);
}
