/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP Wi-Fi
 *
 * Default pin definitions
 *
 * Copyright 2025 Phoenix Systems
 * Author: Jacek Maksymowicz
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _CYHAL_SDIO_DEF_H_
#define _CYHAL_SDIO_DEF_H_

#ifndef CONFIG_USDHC2_CLK_MUX_PAD
#define CONFIG_USDHC2_CLK_MUX_PAD mux_csi_vsync
#endif

#ifndef CONFIG_USDHC2_CLK_PAD
#define CONFIG_USDHC2_CLK_PAD pad_csi_vsync
#endif

#ifndef CONFIG_USDHC2_CLK_MUX_VAL
#define CONFIG_USDHC2_CLK_MUX_VAL 1
#endif

#ifndef CONFIG_USDHC2_CLK_ISEL
#define CONFIG_USDHC2_CLK_ISEL 0
#endif


#ifndef CONFIG_USDHC2_CMD_MUX_PAD
#define CONFIG_USDHC2_CMD_MUX_PAD mux_csi_hsync
#endif

#ifndef CONFIG_USDHC2_CMD_PAD
#define CONFIG_USDHC2_CMD_PAD pad_csi_hsync
#endif

#ifndef CONFIG_USDHC2_CMD_MUX_VAL
#define CONFIG_USDHC2_CMD_MUX_VAL 1
#endif

#ifndef CONFIG_USDHC2_CMD_ISEL
#define CONFIG_USDHC2_CMD_ISEL 0
#endif


#ifndef CONFIG_USDHC2_D0_MUX_PAD
#define CONFIG_USDHC2_D0_MUX_PAD mux_csi_d0
#endif

#ifndef CONFIG_USDHC2_D0_PAD
#define CONFIG_USDHC2_D0_PAD pad_csi_d0
#endif

#ifndef CONFIG_USDHC2_D0_MUX_VAL
#define CONFIG_USDHC2_D0_MUX_VAL 1
#endif

#ifndef CONFIG_USDHC2_D0_ISEL
#define CONFIG_USDHC2_D0_ISEL 0
#endif


#ifndef CONFIG_USDHC2_D1_MUX_PAD
#define CONFIG_USDHC2_D1_MUX_PAD mux_csi_d1
#endif

#ifndef CONFIG_USDHC2_D1_PAD
#define CONFIG_USDHC2_D1_PAD pad_csi_d1
#endif

#ifndef CONFIG_USDHC2_D1_MUX_VAL
#define CONFIG_USDHC2_D1_MUX_VAL 1
#endif

#ifndef CONFIG_USDHC2_D1_ISEL
#define CONFIG_USDHC2_D1_ISEL 0
#endif


#ifndef CONFIG_USDHC2_D2_MUX_PAD
#define CONFIG_USDHC2_D2_MUX_PAD mux_csi_d2
#endif

#ifndef CONFIG_USDHC2_D2_PAD
#define CONFIG_USDHC2_D2_PAD pad_csi_d2
#endif

#ifndef CONFIG_USDHC2_D2_MUX_VAL
#define CONFIG_USDHC2_D2_MUX_VAL 1
#endif

#ifndef CONFIG_USDHC2_D2_ISEL
#define CONFIG_USDHC2_D2_ISEL 2
#endif


#ifndef CONFIG_USDHC2_D3_MUX_PAD
#define CONFIG_USDHC2_D3_MUX_PAD mux_csi_d3
#endif

#ifndef CONFIG_USDHC2_D3_PAD
#define CONFIG_USDHC2_D3_PAD pad_csi_d3
#endif

#ifndef CONFIG_USDHC2_D3_MUX_VAL
#define CONFIG_USDHC2_D3_MUX_VAL 1
#endif

#ifndef CONFIG_USDHC2_D3_ISEL
#define CONFIG_USDHC2_D3_ISEL 0
#endif


#endif /* _CYHAL_SDIO_DEF_H_ */
