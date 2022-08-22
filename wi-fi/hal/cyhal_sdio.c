/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP Wi-Fi
 *
 * Copyright 2021 Phoenix Systems
 * Author: Ziemowit Leszczynski, Artur Miller
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cyhal_sdio.h"
#include "cyhal_gpio.h"
#include <stdio.h>
#include <unistd.h>

#include <sdio.h>


typedef union {
	struct {
		uint8_t data;                /* 0 - 7 */
		unsigned int _stuff2 : 1;    /* 8     */
		unsigned int address : 17;   /* 9-25  */
		unsigned int _stuff : 1;     /* 26    */
		unsigned int checkWrite : 1; /* 27    */
		unsigned int areaIndex : 3;  /* 28-30 */
		unsigned int dir : 1;        /* 31    */
	} cmd52;
	struct {
		unsigned int count : 9;     /* 0-8   */
		unsigned int address : 17;  /* 9-25  */
		unsigned int opCode : 1;    /* 26    */
		unsigned int blockMode : 1; /* 27    */
		unsigned int areaIndex : 3; /* 28-30 */
		unsigned int dir : 1;       /* 31    */
	} cmd53;
	uint32_t uint;
} sdio_cmd_arg_t;


cyhal_sdio_irq_handler_t conv;


/* NOTE: obj is ignored, state instance is held by the SDIO API*/
cy_rslt_t cyhal_sdio_init(cyhal_sdio_t *obj)
{
	cyhal_gpio_init(0, 0, 0, 0); /* all args are ignored          */
	usleep(10000);               /* 10 ms for regulator discharge */
	cyhal_gpio_write(0, 1);      /* only second arg is used       */
	usleep(250000);              /* 250 ms for WLAN power up      */
	return sdio_init();
}


/* NOTE: obj is ignored, state instance is held by the SDIO API*/
void cyhal_sdio_free(cyhal_sdio_t *obj)
{
	sdio_free();
}


/* NOTE: obj is ignored, state instance is held by the SDIO API*/
cy_rslt_t cyhal_sdio_configure(cyhal_sdio_t *obj, const cyhal_sdio_cfg_t *config)
{
	/* block size is 0 for some reason, hardcode instead */
	return sdio_config(config->frequencyhal_hz, 64);
}


/* NOTE: obj is ignored, state instance is held by the SDIO API*/
cy_rslt_t cyhal_sdio_send_cmd(const cyhal_sdio_t *obj, cyhal_transfer_t direction,
	cyhal_sdio_command_t command, uint32_t argument, uint32_t *response)
{
	int rslt;
	uint8_t data;

	sdio_cmd_arg_t arg;
	arg.uint = argument;

	/* WHD only uses send cmd api call for
	 * transfers after init commands which are
	 * issued by sdio_init function, hence
	 * just indicate success and exit */
	if (command != CYHAL_SDIO_CMD_IO_RW_DIRECT) {
		*response = 0;
		return 0;
	}

	data = arg.cmd52.data;
	rslt = sdio_transferDirect(arg.cmd52.dir, arg.cmd52.address, arg.cmd52.areaIndex, &data);
	*response = data;

	return rslt;
}


/* NOTE: obj is ignored, state instance is held by the SDIO API*/
cy_rslt_t cyhal_sdio_bulk_transfer(cyhal_sdio_t *obj, cyhal_transfer_t direction, uint32_t argument,
	uint32_t *data, uint16_t length, uint32_t *response)
{
	size_t len;
	sdio_cmd_arg_t arg;
	arg.uint = argument;
	len = (arg.cmd53.blockMode) ? (arg.cmd53.count * 64) : length;

	return sdio_transferBulk(arg.cmd53.dir, arg.cmd53.blockMode, arg.cmd53.address,
		arg.cmd53.areaIndex, (uint8_t *)data, len);
}


void cyhalHandlerHelper(void *arg)
{
	conv(arg, CYHAL_SDIO_CARD_INTERRUPT);
}


/* NOTE: obj is ignored, state instance is held by the SDIO API*/
void cyhal_sdio_register_irq(cyhal_sdio_t *obj, cyhal_sdio_irq_handler_t handler, void *handler_arg)
{
	/* FIXME: nasty function pointer conversion using global variable */
	conv = handler;
	sdio_eventRegister(SDIO_EVENT_CARD_IRQ, cyhalHandlerHelper, handler_arg);
}


/* NOTE: obj is ignored, state instance is held by the SDIO API*/
void cyhal_sdio_irq_enable(cyhal_sdio_t *obj, cyhal_sdio_irq_event_t event, bool enable)
{
	sdio_eventEnable(SDIO_EVENT_CARD_IRQ, enable);
}
