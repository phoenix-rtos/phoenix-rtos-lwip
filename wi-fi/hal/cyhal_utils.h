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

#ifndef PHOENIX_CYHAL_UTILS_H_
#define PHOENIX_CYHAL_UTILS_H_

#include <sys/platform.h>
#include <phoenix/arch/imx6ull.h>


int cyhal_utils_set_iomux(int mux, char mode);


int cyhal_utils_set_iosel(int isel, char daisy);


int cyhal_utils_set_iopad(int pad, char hys, char pus, char pue, char pke, char ode, char speed, char dse, char sre);


int cyhal_utils_set_devclk(int dev, unsigned int state);


#endif /* PHOENIX_CYHAL_UTILS_H_ */
