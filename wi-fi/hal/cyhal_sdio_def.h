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

/* uSDHC controller of the Wi-Fi module (default: USDHC2), IRQ and clock follow from its address */
#ifndef CONFIG_WIFI_USDHC_ADDR
#define CONFIG_WIFI_USDHC_ADDR 0x2194000
#endif

#if CONFIG_WIFI_USDHC_ADDR == 0x2190000
#ifndef CONFIG_WIFI_USDHC_IRQ
#define CONFIG_WIFI_USDHC_IRQ (32 + 22)
#endif
#ifndef CONFIG_WIFI_USDHC_CLK
#define CONFIG_WIFI_USDHC_CLK clk_usdhc1
#endif
#elif CONFIG_WIFI_USDHC_ADDR == 0x2194000
#ifndef CONFIG_WIFI_USDHC_IRQ
#define CONFIG_WIFI_USDHC_IRQ (32 + 23)
#endif
#ifndef CONFIG_WIFI_USDHC_CLK
#define CONFIG_WIFI_USDHC_CLK clk_usdhc2
#endif
#else
#error "unknown CONFIG_WIFI_USDHC_ADDR"
#endif

/* Pads of the Wi-Fi uSDHC; set *_ISEL to -1 for pads without input select (e.g. USDHC1 on SD1 pads) */

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
