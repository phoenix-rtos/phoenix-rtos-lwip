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

#include "cyhal_sdio.h"
#include "cyhal_utils.h"
#include "cyabs_rtos.h"
#include "cy_log.h"
#include "physmmap.h"

#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/interrupt.h>


#define USDHC2_ADDR 0x2194000
#define USDHC2_IRQ  (32 + 23)

#define DMA_BUFFER_SIZE 2048  // should be large enough to hold whole Wi-Fi frame

enum { ds_addr = 0,
	blk_att,
	cmd_arg,
	cmd_xfer_typ,
	cmd_rsp0,
	cmd_rsp1,
	cmd_rsp2,
	cmd_rsp3,
	data_buff_acc_port,
	pres_state,
	prot_ctrl,
	sys_ctrl,
	int_status,
	int_status_en,
	int_signal_en,
	autocmd12_err_status,
	host_ctrl_cap,
	wtmk_lvl,
	mix_ctrl,
	force_event = 20,
	adma_err_status,
	adma_sys_addr,
	dll_ctrl = 24,
	dll_status,
	clk_tune_ctrl_status,
	vend_spec = 48,
	mmc_boot,
	vend_spec2,
	tuning_ctrl };


static struct {
	volatile uint32_t *base;

	handle_t cmd_lock;

	void *dmaptr;
	addr_t dmaphys;

	volatile bool irq_enabled;

	handle_t irq_handle;
	handle_t irq_lock;
	handle_t irq_cond;

	cyhal_sdio_irq_handler_t irq_handler;
	void *irq_handler_arg;

	volatile bool irq_thread_finish;
	cy_thread_t irq_thread_id;
} sdio_common;


#if 0
static void dump_registers(void)
{
	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "SDIO registers dump:\n");
	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "\tblk_att       = 0x%x\n", *(sdio_common.base + blk_att));
	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "\tpres_state    = 0x%x\n", *(sdio_common.base + pres_state));
	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "\tprot_ctrl     = 0x%x\n", *(sdio_common.base + prot_ctrl));
	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "\tsys_ctrl      = 0x%x\n", *(sdio_common.base + sys_ctrl));
	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "\tint_status    = 0x%x\n", *(sdio_common.base + int_status));
	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "\tint_status_en = 0x%x\n", *(sdio_common.base + int_status_en));
	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "\tint_signal_en = 0x%x\n", *(sdio_common.base + int_signal_en));
	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "\thost_ctrl_cap = 0x%x\n", *(sdio_common.base + host_ctrl_cap));
	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "\tmix_ctrl      = 0x%x\n", *(sdio_common.base + mix_ctrl));
	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "\tvend_spec     = 0x%x\n", *(sdio_common.base + vend_spec));
	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "\tvend_spec2    = 0x%x\n", *(sdio_common.base + vend_spec2));
	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "\ttuning_ctrl   = 0x%x\n", *(sdio_common.base + tuning_ctrl));
}
#endif


static int alloc_dma_buffer(void)
{
	size_t size = DMA_BUFFER_SIZE;
	size_t psize;

	sdio_common.dmaptr = dmammap(size);
	if (sdio_common.dmaptr == NULL)
		return -1;

	psize = size;
	sdio_common.dmaphys = mphys(sdio_common.dmaptr, &psize);

	if (size != psize) {
		cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "SDIO DMA buffer size != psize (%zu != %zu)\n", size, psize);
		munmap(sdio_common.dmaptr, size);
		sdio_common.dmaptr = NULL;
		return -1;
	}

	if (sdio_common.dmaphys & 3) {
		cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "SDIO DMA buffer physical address is not aligned (%x)\n", sdio_common.dmaphys);
		munmap(sdio_common.dmaptr, size);
		sdio_common.dmaptr = NULL;
		return -1;
	}

	return 0;
}


static int wait_for_cmd(uint32_t flags, uint32_t wait_us, uint32_t max_cnt)
{
	uint32_t i, val;

	// FIXME: ???
	usleep(10);

	for (i = 0; i < max_cnt; ++i) {
		val = *(sdio_common.base + int_status);

		/* check for errors */
		if (val & 0x107f0000) {
			if (val & (1 << 28)) /* DMAE=1 */
				cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "SDIO cmd error (DMA Error)\n");
			if (val & (1 << 22)) /* DEBE=1 */
				cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "SDIO cmd error (Data End Bit Error)\n");
			if (val & (1 << 21)) /* DCE=1 */
				cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "SDIO cmd error (Data CRC Error)\n");
			if (val & (1 << 20)) /* DTOE=1 */
				cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "SDIO cmd error (Data Timeout Error)\n");
			if (val & (1 << 19)) /* CIE=1*/
				cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "SDIO cmd error (Command Index Error)\n");
			if (val & (1 << 18)) /* CEBE=1 */
				cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "SDIO cmd error (Command End Bit Error)\n");
			if (val & (1 << 17)) /* CCE=1 */
				cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "SDIO cmd error (Command CRC Error)\n");
			if (val & (1 << 16)) /* CTOE=1 */
				cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "SDIO cmd error (Command Timeout Error)\n");
			return -1;
		}

		if ((val & flags) == flags)
			return 0;

		usleep(wait_us);
	}

	cy_log_msg(CYLF_SDIO, CY_LOG_WARNING, "SDIO cmd timeout\n");

	return -1;
}


static int reset_all(uint8_t sdclkfs, uint8_t dvs)
{
	uint32_t i, val;

	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "reset SDIO\n");

	*(sdio_common.base + sys_ctrl) = (1 << 24) | (sdclkfs << 8) | (dvs << 4) | 0xf; /* RSTA=1 */

	// FIXME: ???
	usleep(10);

	for (i = 0; i < 10; ++i) {
		val = *(sdio_common.base + sys_ctrl) & (1 << 24);
		if (val == 0)
			return 0;
		usleep(10);
	}

	cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "failed to reset SDIO\n");

	return -1;
}


static int reset_cmd_block(void)
{
	uint32_t i, val;

	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "reset SDIO cmd block\n");

	val = *(sdio_common.base + sys_ctrl);
	val |= 1 << 25; /* RSTC=1 */
	*(sdio_common.base + sys_ctrl) = val;

	// FIXME: ???
	usleep(10);

	for (i = 0; i < 10; ++i) {
		val = *(sdio_common.base + sys_ctrl) & (1 << 25);
		if (val == 0)
			return 0;
		usleep(10);
	}

	cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "failed to reset SDIO cmd block\n");

	return -1;
}


static int reset_data_block(void)
{
	uint32_t i, val;

	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "reset SDIO data block\n");

	val = *(sdio_common.base + sys_ctrl);
	val |= 1 << 26; /* RSTD=1 */
	*(sdio_common.base + sys_ctrl) = val;

	// FIXME: ???
	usleep(10);

	for (i = 0; i < 10; ++i) {
		val = *(sdio_common.base + sys_ctrl) & (1 << 26);
		if (val == 0)
			return 0;
		usleep(10);
	}

	cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "failed to reset SDIO data block\n");

	return -1;
}


static void sdio_irq_thread(void *arg)
{
	bool finish;
	uint32_t val;

	while (1) {
		mutexLock(sdio_common.irq_lock);

		while (1) {
			finish = sdio_common.irq_thread_finish;
			if (finish) {
				break;
			}

			val = *(sdio_common.base + int_status);
			if ((val & (1 << 8)) != 0) {
				break;
			}

			condWait(sdio_common.irq_cond, sdio_common.irq_lock, 0);
		}

		mutexUnlock(sdio_common.irq_lock);

		if (finish) {
			break;
		}

		// cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "got SDIO IRQ\n");

		/* this will also clear CINT */
		val = *(sdio_common.base + int_status_en);
		val &= ~(1 << 8); /* CINTESEN=0 */
		*(sdio_common.base + int_status_en) = val;

		sdio_common.irq_handler(sdio_common.irq_handler_arg, CYHAL_SDIO_CARD_INTERRUPT);

		val = *(sdio_common.base + int_status_en);
		val |= 1 << 8; /* CINTESEN=1 */
		*(sdio_common.base + int_status_en) = val;

		val = *(sdio_common.base + int_signal_en);
		val |= 1 << 8; /* CINTIEN=1 */
		*(sdio_common.base + int_signal_en) = val;

		// cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "done SDIO IRQ\n");
	}

	cy_rtos_exit_thread();
}

/* NOTE: obj is ignored - state is kept in sdio_common */
cy_rslt_t cyhal_sdio_start_irq_thread(cyhal_sdio_t *obj)
{
	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "cyhal_sdio_start_irq_thread\n");
	if (cy_rtos_create_thread(&sdio_common.irq_thread_id, sdio_irq_thread, "SDIO_IRQ", NULL, 1024, 4, NULL) != CY_RSLT_SUCCESS) {
		cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "failed to start SDIO IRQ handler thread\n");
		return CYHAL_SDIO_RSLT_ERR_BAD_PARAM;
	}
	return CY_RSLT_SUCCESS;
}


/* NOTE: obj is ignored - state is kept in sdio_common */
cy_rslt_t cyhal_sdio_init(cyhal_sdio_t *obj)
{
	uint32_t val;

	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "cyhal_sdio_init\n");

	memset(&sdio_common, 0, sizeof(sdio_common));

	do {
		void *ptr = mmap(NULL, _PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_DEVICE | MAP_PHYSMEM | MAP_ANONYMOUS, -1, USDHC2_ADDR);
		if (ptr == MAP_FAILED) {
			cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "failed to mmap SDIO registers\n");
			break;
		}
		sdio_common.base = ptr;

		if (alloc_dma_buffer() < 0) {
			cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "failed to alloc SDIO DMA buffer\n");
			break;
		}

		if (mutexCreate(&sdio_common.cmd_lock) < 0) {
			cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "failed to create SDIO cmd mutex\n");
			break;
		}

		if (mutexCreate(&sdio_common.irq_lock) < 0) {
			cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "failed to create SDIO IRQ handler mutex\n");
			break;
		}

		if (condCreate(&sdio_common.irq_cond) < 0) {
			cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "failed to create SDIO IRQ handler condition\n");
			break;
		}

		if ((cyhal_utils_set_iomux(pctl_mux_csi_vsync, 1) < 0) || /* USDHC2_CLK */
			(cyhal_utils_set_iomux(pctl_mux_csi_hsync, 1) < 0) || /* USDHC2_CMD */
			(cyhal_utils_set_iomux(pctl_mux_csi_d0, 1) < 0) ||    /* USDHC2_DATA0 */
			(cyhal_utils_set_iomux(pctl_mux_csi_d1, 1) < 0) ||    /* USDHC2_DATA1 */
			(cyhal_utils_set_iomux(pctl_mux_csi_d2, 1) < 0) ||    /* USDHC2_DATA2 */
			(cyhal_utils_set_iomux(pctl_mux_csi_d3, 1) < 0)) {    /* USDHC2_DATA3 */
			cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "can't configure SDIO pins iomux\n");
			break;
		}

		if ((cyhal_utils_set_iosel(pctl_isel_usdhc2_clk, 0) < 0) || /* CSI_VSYNC_ALT1 */
			(cyhal_utils_set_iosel(pctl_isel_usdhc2_cmd, 0) < 0) || /* CSI_HSYNC_ALT1 */
			(cyhal_utils_set_iosel(pctl_isel_usdhc2_d0, 0) < 0) ||  /* CSI_DATA00_ALT1 */
			(cyhal_utils_set_iosel(pctl_isel_usdhc2_d1, 0) < 0) ||  /* CSI_DATA01_ALT1 */
			(cyhal_utils_set_iosel(pctl_isel_usdhc2_d2, 2) < 0) ||  /* CSI_DATA02_ALT1 */
			(cyhal_utils_set_iosel(pctl_isel_usdhc2_d3, 0) < 0)) {  /* CSI_DATA03_ALT1 */
			cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "can't configure SDIO pins iosel\n");
			break;
		}

		if ((cyhal_utils_set_iopad(pctl_pad_csi_vsync, 0, 0, 0, 0, 0, 2, 1, 0) < 0) ||
			(cyhal_utils_set_iopad(pctl_pad_csi_hsync, 0, 2, 1, 1, 0, 2, 1, 0) < 0) || /* 100K Ohm Pull up */
			(cyhal_utils_set_iopad(pctl_pad_csi_d0, 0, 2, 1, 1, 0, 2, 1, 0) < 0) ||    /* 100K Ohm Pull up */
			(cyhal_utils_set_iopad(pctl_pad_csi_d1, 0, 2, 1, 1, 0, 2, 1, 0) < 0) ||    /* 100K Ohm Pull up */
			(cyhal_utils_set_iopad(pctl_pad_csi_d2, 0, 2, 1, 1, 0, 2, 1, 0) < 0) ||    /* 100K Ohm Pull up */
			(cyhal_utils_set_iopad(pctl_pad_csi_d3, 0, 2, 1, 1, 0, 2, 1, 0) < 0)) {    /* 100K Ohm Pull up */
			cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "can't configure SDIO pins iopad\n");
			break;
		}

		/* enable USDHC2_CLK */
		if (cyhal_utils_set_devclk(pctl_clk_usdhc2, 3) < 0) {
			cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "can't enable SDIO clock\n");
			break;
		}

		/* reset SDIO and set SDIO clock freq to 400000000 / 2 / (256 * 2) = 390625 Hz */
		reset_all(0x80, 0x1); /* SDCLKFS=0x80 DVS=0x1 */

		/* change card detection pin polarity */
		val = *(sdio_common.base + vend_spec);
		val |= (1 << 5); /* CD_POL=1 */
		*(sdio_common.base + vend_spec) = val;

		/* DMAESEN=1 DEBESEN=1 DCESEN=1 DTOESEN=1 CIESEN=1 CEBESEN=1 CCESEN=1 CTOESEN=1 DINTSEN=1 BGESEN=1 TCSEN=1 CCSEN=1 */
		*(sdio_common.base + int_status_en) = 0x107f000f;

		// dump_registers();

		return CY_RSLT_SUCCESS;
	} while (0);

	cyhal_sdio_free(obj);

	return CYHAL_SDIO_RSLT_ERR_BAD_PARAM;
}


/* NOTE: obj is ignored - state is kept in sdio_common */
void cyhal_sdio_stop_irq_thread(cyhal_sdio_t *obj)
{
	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "cyhal_sdio_stop_irq_thread\n");
	if (sdio_common.irq_thread_id != 0) {
		/* request IRQ thread to finish */
		mutexLock(sdio_common.irq_lock);
		sdio_common.irq_thread_finish = true;
		condSignal(sdio_common.irq_cond);
		mutexUnlock(sdio_common.irq_lock);

		/* wait for IRQ thread to finish */
		cy_rtos_join_thread(&sdio_common.irq_thread_id);
		sdio_common.irq_thread_id = 0;
	}
}


/* NOTE: obj is ignored - state is kept in sdio_common */
void cyhal_sdio_free(cyhal_sdio_t *obj)
{
	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "cyhal_sdio_free\n");

	/* reset SDIO and set SDIO clock freq to 400000000 / 2 / (256 * 2) = 390625 Hz */
	reset_all(0x80, 0x1); /* SDCLKFS=0x80 DVS=0x1 */

	if (sdio_common.irq_handle != 0) {
		resourceDestroy(sdio_common.irq_handle);
	}
	if (sdio_common.irq_lock != 0) {
		resourceDestroy(sdio_common.irq_lock);
	}
	if (sdio_common.irq_cond != 0) {
		resourceDestroy(sdio_common.irq_cond);
	}

	if (sdio_common.cmd_lock != 0) {
		resourceDestroy(sdio_common.cmd_lock);
	}

	if (sdio_common.dmaptr != NULL) {
		munmap(sdio_common.dmaptr, DMA_BUFFER_SIZE);
	}

	if (sdio_common.base != NULL) {
		munmap((void *)sdio_common.base, _PAGE_SIZE);
	}

	memset(&sdio_common, 0, sizeof(sdio_common));
}


/* NOTE: obj is ignored - state is kept in sdio_common */
cy_rslt_t cyhal_sdio_configure(cyhal_sdio_t *obj, const cyhal_sdio_cfg_t *config)
{
	uint32_t val;

	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "cyhal_sdio_configure (freq=%u)\n", config->frequencyhal_hz);

	if (config->frequencyhal_hz != 50000000 && config->frequencyhal_hz != 25000000) {
		cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "unsupported SDIO clock freq %u\n", config->frequencyhal_hz);
		return CYHAL_SDIO_RSLT_ERR_BAD_PARAM;
	}

	/* set 4-bit mode */
	val = *(sdio_common.base + prot_ctrl);
	val |= 1 << 1;
	*(sdio_common.base + prot_ctrl) = val;

	/* FRC_SDCLK_ON=0 */
	val = *(sdio_common.base + vend_spec);
	val &= ~(1 << 8);
	*(sdio_common.base + vend_spec) = val;

	/* make sure SD clock is stable (SDSTB=0) */
	do {
		val = *(sdio_common.base + pres_state) & (1 << 3);
	} while (!val);

	if (config->frequencyhal_hz == 50000000) {
		/* FREQ = 400000000 / 2 / (4 * 1) = 50000000 */
		*(sdio_common.base + sys_ctrl) = (0x2 << 8) | 0xf; /* SDCLKFS=0x2 DVS=0x0 */
	}
	else {
		/* FREQ = 400000000 / 2 / (8 * 1) = 25000000 */
		*(sdio_common.base + sys_ctrl) = (0x4 << 8) | 0xf; /* SDCLKFS=0x4 DVS=0x0 */
	}

#if 0
    /* FRC_SDCLK_ON=1 */
    val = *(sdio_common.base + vend_spec);
    val |= 1 << 8;
    *(sdio_common.base + vend_spec) = val;
#endif

#if 1
	/* INITA=1 */
	val = *(sdio_common.base + sys_ctrl);
	val |= (1 << 27);
	*(sdio_common.base + sys_ctrl) = val;

	do {
		val = *(sdio_common.base + sys_ctrl) & (1 << 27);
	} while (val);
#endif

	// dump_registers();

	return CY_RSLT_SUCCESS;
}


static cy_rslt_t cyhal_sdio_send_cmd_internal(cyhal_transfer_t direction, cyhal_sdio_command_t command, uint32_t argument, uint32_t *response)
{
	uint32_t val, cmd;

	if (response)
		*response = 0;

	val = *(sdio_common.base + pres_state);
	if (val & 0x7) {
		cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "cannot issue SDIO cmd (pres_state=%x)\n", val);
		return CYHAL_SDIO_RSLT_ERR_BAD_PARAM;
	}

	cmd = (command & 0x3f) << 24;

	/* set response type */
	switch (command) {
		case CYHAL_SDIO_CMD_GO_IDLE_STATE:
			/* no response */
			break;
		case CYHAL_SDIO_CMD_SEND_RELATIVE_ADDR:
			cmd |= 1 << 20;   /* CICEN=1 */
			cmd |= 1 << 19;   /* CCCEN=1 */
			cmd |= 0x2 << 16; /* RSPTYP=2 */
			break;
		case CYHAL_SDIO_CMD_IO_SEND_OP_COND:
			cmd |= 0x2 << 16; /* RSPTYP=2 */
			break;
		case CYHAL_SDIO_CMD_SELECT_CARD:
			cmd |= 1 << 20;   /* CICEN=1 */
			cmd |= 1 << 19;   /* CCCEN=1 */
			cmd |= 0x3 << 16; /* RSPTYP=3 */
			break;
		case CYHAL_SDIO_CMD_GO_INACTIVE_STATE:
			/* no response */
			break;
		case CYHAL_SDIO_CMD_IO_RW_DIRECT:
			cmd |= 1 << 20;   /* CICEN=1 */
			cmd |= 1 << 19;   /* CCCEN=1 */
			cmd |= 0x2 << 16; /* RSPTYP=2 */
			break;
		default:
			return CYHAL_SDIO_RSLT_ERR_BAD_PARAM;
	}

	*(sdio_common.base + mix_ctrl) = 1U << 31;
	*(sdio_common.base + blk_att) = 0;
	*(sdio_common.base + cmd_arg) = argument;
	*(sdio_common.base + cmd_xfer_typ) = cmd;

	/* wait 1 ms max */
	if (wait_for_cmd(0x1, 10, 100) < 0) {
		reset_cmd_block();
		return CYHAL_SDIO_RSLT_ERR_FUNC_RET(CYHAL_SDIO_RET_CMD_TIMEOUT);
	}

	/* clear status flags */
	*(sdio_common.base + int_status) = 0x1; /* CC=1 */

	/* retrieve response */
	switch (command) {
		case CYHAL_SDIO_CMD_GO_IDLE_STATE:
			/* no response */
			break;
		case CYHAL_SDIO_CMD_SEND_RELATIVE_ADDR:
			val = *(sdio_common.base + cmd_rsp0);
			break;
		case CYHAL_SDIO_CMD_IO_SEND_OP_COND:
			val = *(sdio_common.base + cmd_rsp0);
			break;
		case CYHAL_SDIO_CMD_SELECT_CARD:
			val = *(sdio_common.base + cmd_rsp3);
			break;
		case CYHAL_SDIO_CMD_GO_INACTIVE_STATE:
			/* no response */
			break;
		case CYHAL_SDIO_CMD_IO_RW_DIRECT:
			val = *(sdio_common.base + cmd_rsp0);
			break;
		default:
			return CYHAL_SDIO_RSLT_ERR_BAD_PARAM;
	}

	if (response)
		*response = val;

	return CY_RSLT_SUCCESS;
}


/* NOTE: obj is ignored - state is kept in sdio_common */
cy_rslt_t cyhal_sdio_send_cmd(const cyhal_sdio_t *obj, cyhal_transfer_t direction,
	cyhal_sdio_command_t command, uint32_t argument, uint32_t *response)
{
	cy_rslt_t res;

	// cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "cyhal_sdio_send_cmd (dir=%u cmd=%u arg=%x)\n", direction, command, argument);

	for (unsigned int i = 1; i <= 10; ++i) {
		mutexLock(sdio_common.cmd_lock);
		res = cyhal_sdio_send_cmd_internal(direction, command, argument, response);
		mutexUnlock(sdio_common.cmd_lock);

		if (res == CY_RSLT_SUCCESS)
			break;

		cy_log_msg(CYLF_SDIO, CY_LOG_WARNING, "repeating SDIO cmd (cnt=%u)\n", i);

		usleep(1000);
	}

	return res;
}


static cy_rslt_t cyhal_sdio_bulk_transfer_internal(cyhal_transfer_t direction, uint32_t argument, uint32_t *data, uint16_t length, uint32_t *response)
{
	uint32_t val, cmd, mix, blk, block_mode, count;

	block_mode = !!(argument & (1 << 27));
	count = argument & 0x1ff;

	if (response)
		*response = 0;

	val = *(sdio_common.base + pres_state);
	if (val & 0x7) {
		cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "cannot issue SDIO bulk transfer cmd (pres_state=%x)\n", val);
		return CYHAL_SDIO_RSLT_ERR_BAD_PARAM;
	}

	val = *(sdio_common.base + int_status);
	if (val & 0x2) {
		cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "cannot issue SDIO bulk transfer cmd (int_status=%x)\n", val);
		return CYHAL_SDIO_RSLT_ERR_BAD_PARAM;
	}

	if (length > DMA_BUFFER_SIZE) {
		cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "cannot issue SDIO bulk transfer cmd (length=%u > %u)\n", length, DMA_BUFFER_SIZE);
		return CYHAL_SDIO_RSLT_ERR_BAD_PARAM;
	}

	if (direction == CYHAL_WRITE)
		memcpy(sdio_common.dmaptr, data, length);

	cmd = CYHAL_SDIO_CMD_IO_RW_EXTENDED << 24;
	cmd |= 1 << 21;   /* DPSEL=1 */
	cmd |= 1 << 20;   /* CICEN=1 */
	cmd |= 1 << 19;   /* CCCEN=1 */
	cmd |= 0x2 << 16; /* RSPTYP=2 */

	mix = (1U << 31) | (1 << 0); /* DMAEN=1 */
	if (direction == CYHAL_READ)
		mix |= 1 << 4; /* DTDSEL=1 */

	if (block_mode) {
		mix |= (1 << 5); /* MSBSEL=1 */
		mix |= (1 << 1); /* BCEN=1 */

		blk = (count << 16) | 64; /* BLKCNT=count BLKSIZE=64 */
	}
	else {
		blk = (1 << 16) | count; /* BLKCNT=1 BLKSIZE=count */
	}

	*(sdio_common.base + mix_ctrl) = mix;
	*(sdio_common.base + blk_att) = blk;
	*(sdio_common.base + ds_addr) = sdio_common.dmaphys;
	*(sdio_common.base + cmd_arg) = argument;
	*(sdio_common.base + cmd_xfer_typ) = cmd;

	/* wait 1 ms max */
	if (wait_for_cmd(0xb, 10, 100) < 0) {
		reset_cmd_block();
		reset_data_block();
		return CYHAL_SDIO_RSLT_ERR_FUNC_RET(CYHAL_SDIO_RET_CMD_TIMEOUT);
	}

	/* clear status flags */
	*(sdio_common.base + int_status) = 0xb; /* DINT=1 TC=1 CC=1 */

	if (direction == CYHAL_READ)
		memcpy(data, sdio_common.dmaptr, length);

	/* retrieve response */
	val = *(sdio_common.base + cmd_rsp0);

	if (response)
		*response = val;

	return CY_RSLT_SUCCESS;
}

/* NOTE: obj is ignored - state is kept in sdio_common */
cy_rslt_t cyhal_sdio_bulk_transfer(cyhal_sdio_t *obj, cyhal_transfer_t direction, uint32_t argument,
	uint32_t *data, uint16_t length, uint32_t *response)
{
	cy_rslt_t res;

	// cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "cyhal_sdio_bulk_transfer (dir=%u arg=%u length=%u)\n", direction, argument, length);

	for (unsigned int i = 1; i <= 10; ++i) {
		mutexLock(sdio_common.cmd_lock);
		res = cyhal_sdio_bulk_transfer_internal(direction, argument, data, length, response);
		mutexUnlock(sdio_common.cmd_lock);

		if (res == CY_RSLT_SUCCESS)
			break;

		cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "repeating SDIO bulk transfer cmd (cnt=%d)\n", i);

		usleep(1000);
	}


	return res;
}

static int sdio_irq_handler(unsigned int n, void *arg)
{
	uint32_t val;

	val = *(sdio_common.base + int_signal_en);
	val &= ~(1 << 8); /* CINTIEN=0 */
	*(sdio_common.base + int_signal_en) = val;

	return 0;
}


/* NOTE: obj is ignored - state is kept in sdio_common */
void cyhal_sdio_register_irq(cyhal_sdio_t *obj, cyhal_sdio_irq_handler_t handler, void *handler_arg)
{
	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "cyhal_sdio_register_irq\n");

	sdio_common.irq_handler = handler;
	sdio_common.irq_handler_arg = handler_arg;

	interrupt(USDHC2_IRQ, sdio_irq_handler, NULL, sdio_common.irq_cond, &sdio_common.irq_handle);
}


/* NOTE: obj is ignored - state is kept in sdio_common */
void cyhal_sdio_irq_enable(cyhal_sdio_t *obj, cyhal_sdio_irq_event_t event, bool enable)
{
	uint32_t val;

	cy_log_msg(CYLF_SDIO, CY_LOG_DEBUG, "cyhal_sdio_irq_enable (event=%x enable=%u)\n", event, enable);

	// NOTE: only CYHAL_SDIO_CARD_INTERRUPT event is supported
	if (event != CYHAL_SDIO_CARD_INTERRUPT) {
		cy_log_msg(CYLF_SDIO, CY_LOG_ERR, "unsupported SDIO IRQ event %u\n", event);
		return;
	}

	if (enable != sdio_common.irq_enabled) {
		val = *(sdio_common.base + int_status_en);
		if (enable)
			*(sdio_common.base + int_status_en) = val | (1 << 8); /* CINTESEN=1 */
		else
			*(sdio_common.base + int_status_en) = val & ~(1 << 8); /* CINTESEN=0 */

		val = *(sdio_common.base + int_signal_en);
		if (enable)
			*(sdio_common.base + int_signal_en) = val | (1 << 8); /* CINTIEN=1 */
		else
			*(sdio_common.base + int_signal_en) = val & ~(1 << 8); /* CINTIEN=0 */

		sdio_common.irq_enabled = enable;
	}
}
