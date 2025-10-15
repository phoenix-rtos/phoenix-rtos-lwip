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

#include <stdlib.h>

#include "cyhal_modules.h"
#include "cy_result.h"
#include "cyhal_hw_types.h"

/* Control messages: bRequest values */
#define CYHAL_USB_DL_CMD_GETSTATE      0x0  /* returns the rdl_state_t struct */
#define CYHAL_USB_DL_CMD_CHECK_CRC     0x1  /* currently unused */
#define CYHAL_USB_DL_CMD_GO            0x2  /* execute downloaded image */
#define CYHAL_USB_DL_CMD_START         0x3  /* initialize dl state */
#define CYHAL_USB_DL_CMD_REBOOT        0x4  /* reboot the device in 2 seconds */
#define CYHAL_USB_DL_CMD_GETVER        0x5  /* returns the bootrom_id_t struct */
#define CYHAL_USB_DL_CMD_GO_PROTECTED  0x6  /* execute the downloaded code and set reset event to occur in 2 seconds. It is the responsibility of the downloaded code to clear this event */
#define CYHAL_USB_DL_CMD_EXEC          0x7  /* jump to a supplied address */
#define CYHAL_USB_DL_CMD_RESETCFG      0x8  /* To support single enum on dongle - not used by bootloader */
#define CYHAL_USB_DL_CMD_DEFER_RESP_OK 0x9  /* Potentially defer the response to setup if resp unavailable */
#define CYHAL_USB_DL_CMD_RDHW          0x10 /* Read a hardware address (Ctl-in) */
#define CYHAL_USB_DL_CMD_RDHW32        0x10 /* Read a 32 bit word */
#define CYHAL_USB_DL_CMD_RDHW16        0x11 /* Read 16 bits */
#define CYHAL_USB_DL_CMD_RDHW8         0x12 /* Read an 8 bit byte */
#define CYHAL_USB_DL_CMD_WRHW          0x14 /* Write a hardware address (Ctl-out) */
#define CYHAL_USB_DL_CMD_WRHW_BLK      0x13 /* Block write to hardware access */

/* States */
#define CYHAL_USB_DL_STATE_WAITING      0 /* waiting to rx first pkt */
#define CYHAL_USB_DL_STATE_READY        1 /* hdr was good, waiting for more of the compressed image */
#define CYHAL_USB_DL_STATE_BAD_HDR      2 /* hdr was corrupted */
#define CYHAL_USB_DL_STATE_BAD_CRC      3 /* compressed image was corrupted */
#define CYHAL_USB_DL_STATE_RUNNABLE     4 /* download was successful,waiting for go cmd */
#define CYHAL_USB_DL_STATE_START_FAIL   5 /* failed to initialize correctly */
#define CYHAL_USB_DL_STATE_NVRAM_TOOBIG 6 /* host specified nvram data exceeds DL_NVRAM value */
#define CYHAL_USB_DL_STATE_IMAGE_TOOBIG 7 /* firmware image too big */

#define WHD_USB_MAX_BULK_TRANSFER_SIZE (512) /* Max packet size for high speed USB device */

#define CYHAL_USB_RSLT_ERR_DEVICE_NOT_FOUND CY_RSLT_CREATE(CY_RSLT_TYPE_ERROR, CYHAL_RSLT_MODULE_USB, 0x1)
#define CYHAL_USB_RSLT_ERR_DEVICE_OP(err)   CY_RSLT_CREATE(CY_RSLT_TYPE_ERROR, CYHAL_RSLT_MODULE_USB, err)


/** Initialize the USB peripheral
 *
 * @param[out] obj The USB object
 * @param[in] path USB device path
 * @return The status of the init request
 */
cy_rslt_t cyhal_usb_init(cyhal_usb_t *obj, const char *path);


/** Release the USB peripheral.
 *
 * @param[in,out] obj The USB object
 * @return The status of the deinit request
 */
cy_rslt_t cyhal_usb_free(cyhal_usb_t *obj);


/** Get saved chip ID from USB
 *
 * @param[in,out] obj The USB object
 * @param[out] chip The output chip ID
 * @return The status of the get chip request
 */
cy_rslt_t cyhal_usb_get_chip(const cyhal_usb_t *obj, uint32_t *chip);


/** Set chip ID in USB
 *
 * @param[in,out] obj The USB object
 * @param[out] chip The chip ID to set
 * @return The status of the set chip request
 */
cy_rslt_t cyhal_usb_set_chip(const cyhal_usb_t *obj, uint32_t chip);


/** Wait USB state (down/up)
 *
 * @param[in] path File path to the USB
 * @param state The state to wait for: false=down, true=up
 * @return The status of USB
 */
cy_rslt_t cyhal_usb_wait_state(const char *path, bool state);


/** Send download command
 *
 * @param[in] obj The USB object
 * @param cmd command to send (CYHAL_USB_DL_CMD_*)
 * @param[out] buffer buffer to store the response, should be at least buflen size
 * @param buflen length of buffer
 * @return The status of the cmd request
 */
cy_rslt_t cyhal_usb_dl_cmd(const cyhal_usb_t *obj, uint8_t cmd, void *buffer, size_t buflen);


/** Send bulk
 *
 * @param[in] obj The USB object
 * @param[in] buffer buffer to send, should be at least buflen size
 * @param buflen length of buffer
 * @return The status of bulk send
 */
cy_rslt_t cyhal_usb_bulk_send(const cyhal_usb_t *obj, void *buffer, size_t *buflen);


/** Receive bulk
 *
 * @param[in] obj The USB object
 * @param[out] buffer buffer to receive into, should be at least buflen size
 * @param buflen length of buffer
 * @return The status of bulk receive
 */
cy_rslt_t cyhal_usb_bulk_receive(const cyhal_usb_t *obj, void *buffer, size_t *buflen);


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
