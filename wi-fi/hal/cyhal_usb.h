/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP Wi-Fi - USB HAL
 *
 * Copyright 2025 Phoenix Systems
 * Author: Julian Uziembło
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#ifndef PHOENIX_CYHAL_USB_H_
#define PHOENIX_CYHAL_USB_H_

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

#include "cy_result.h"
#include "cyabs_rtos.h"
#include "cyhal_modules.h"
#include "cyhal_hw_types.h"

#define CYHAL_USB_RSLT_ERR_DEVICE_OP(err) CY_RSLT_CREATE(CY_RSLT_TYPE_ERROR, CYHAL_RSLT_MODULE_USB, err)


typedef struct {
	uint32_t vid, pid;
} cyhal_usb_devinfo_t;


typedef struct {
	const cyhal_usb_devinfo_t *filters; /* USB device filters */
	size_t nfilters;

	size_t bulkRecvBufSz;
	void (*onInsertion)(cyhal_usb_devinfo_t *info);
	void (*onDeletion)(cyhal_usb_devinfo_t *info);
	void (*onBulkRecv)(const void *buf, size_t len);
} cyhal_usb_config_t;


/** Initialize the USB peripheral
 *
 * @param[out] obj The USB object
 * @param[in] path USB device path
 * @return The status of the init request
 */
cy_rslt_t cyhal_usb_init(cyhal_usb_t *obj, cyhal_usb_config_t *ops);


/** Deinitialize the USB peripheral.
 *
 * @param[in,out] obj The USB object
 * @return The status of the deinit request
 */
cy_rslt_t cyhal_usb_deinit(cyhal_usb_t *obj);


/** Send download command
 *
 * @param[in] obj The USB object
 * @param cmd command to send (CYHAL_USB_DL_CMD_*)
 * @param[out] buffer buffer to store the response, should be at least buflen size
 * @param buflen length of buffer
 * @return The status of the cmd request
 */
cy_rslt_t cyhal_usb_dl_cmd(const cyhal_usb_t *obj, uint8_t cmd, uint16_t wIndex, void *buffer, size_t buflen);


/** Start RX
 *
 * @param[in] obj The USB object
 * @return The status of the start RX request
 */
cy_rslt_t cyhal_usb_start_bulk_rx(const cyhal_usb_t *obj);


/** Stop RX
 *
 * @param[in] obj The USB object
 * @return The status of the stop RX request
 */
cy_rslt_t cyhal_usb_stop_bulk_rx(const cyhal_usb_t *obj);


/** Send bulk
 *
 * @param[in] obj The USB object
 * @param[in] buffer buffer to send, should be at least buflen size
 * @param buflen length of buffer
 * @return The status of bulk send
 */
cy_rslt_t cyhal_usb_bulk_send(const cyhal_usb_t *obj, void *buffer, size_t *buflen);


/** Send ctrl
 *
 * @param[in] obj The USB object
 * @param[in] buffer buffer to send, should be at least buflen size
 * @param buflen length of buffer
 * @return The status of ctrl send
 */
cy_rslt_t cyhal_usb_ctrl_send(const cyhal_usb_t *obj, void *buffer, size_t *buflen);


/** Receive ctrl
 *
 * @param[in] obj The USB object
 * @param[out] buffer buffer to receive into, should be at least buflen size
 * @param buflen length of buffer
 * @return The status of ctrl receive
 */
cy_rslt_t cyhal_usb_ctrl_receive(const cyhal_usb_t *obj, void *buffer, size_t *buflen);


#endif /* PHOENIX_CYHAL_USB_H_ */
