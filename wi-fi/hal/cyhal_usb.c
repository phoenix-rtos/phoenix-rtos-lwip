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

#include "cybsp.h"
#if (CYBSP_WIFI_INTERFACE_TYPE == CYBSP_USB_INTERFACE)

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/minmax.h>
#include <unistd.h>

#include <usbprocdriver.h>
#include <usbdriver.h>
#include <usbhost.h>
#include <usb.h>

#include "cy_log.h"
#include "cyabs_rtos.h"
#include "cyhal_usb.h"

#include <board_config.h>

#ifndef CYHAL_USB_DRIVER_THREAD_PRIO
#define CYHAL_USB_DRIVER_THREAD_PRIO 4
#endif

/* Has to be 1 as onBulkRecv() may be putting the data into an SPSC queue. */
#define CYHAL_USB_DRIVER_THREADS 1


typedef struct {
	cyhal_usb_config_t config;

	usb_driver_t *driver;
	handle_t mutex;

	struct {
		int id, dev, bus, interface;
		cyhal_usb_devinfo_t info;
	} dev;

	int pipeCtrl, pipeIntIn, pipeBulkIn, pipeBulkOut;

	int urb;
	bool rxStarted;
} usb_priv_t;


static int _cyhal_usb_startRx(usb_driver_t *drv)
{
	usb_priv_t *priv = drv->priv;
	int err;

	if (priv->rxStarted) {
		return 0;
	}

	err = usb_transferAsync(drv, priv->pipeBulkIn, priv->urb, priv->config.bulkRecvBufSz, NULL);
	if (err >= 0) {
		priv->rxStarted = true;
	}

	return err;
}


static int _cyhal_usb_stopRx(usb_driver_t *drv)
{
	usb_priv_t *priv = drv->priv;
	int err;

	if (!priv->rxStarted) {
		return 0;
	}

	err = usb_urbCancel(drv, priv->pipeBulkIn, priv->urb);
	if (err >= 0) {
		priv->rxStarted = false;
	}

	return err;
}


static int cyhal_usb_handleInsertion(usb_driver_t *drv, usb_devinfo_t *ins, usb_event_insertion_t *event_out)
{
	usb_priv_t *priv = drv->priv;
	int err = 0;

	mutexLock(priv->mutex);

	if (priv->dev.id != 0) { /* one device already inserted */
		mutexUnlock(priv->mutex);
		assert(priv->dev.id != ins->locationID); /* sanity check: new device can't have the same locationID as the already inserted one */
		cy_log_msg(CYLF_USB, CY_LOG_WARNING, "one device already running (id=%d) and this driver cannot handle multiple devices - dropping new device id=%d.\n", priv->dev.id, ins->locationID);
		return 0;
	}

	priv->urb = -1;

	do {
		priv->pipeCtrl = usb_open(drv, ins, usb_transfer_control, 0);
		if (priv->pipeCtrl < 0) {
			cy_log_msg(CYLF_USB, CY_LOG_ERR, "failed to open ctrl pipe\n");
			err = -EIO;
			break;
		}

		err = usb_setConfiguration(drv, priv->pipeCtrl, 1);
		if (err < 0) {
			cy_log_msg(CYLF_USB, CY_LOG_ERR, "failed to set configuration\n");
			err = -EIO;
			break;
		}

		priv->pipeIntIn = usb_open(drv, ins, usb_transfer_interrupt, usb_dir_in);
		if (priv->pipeIntIn < 0) {
			cy_log_msg(CYLF_USB, CY_LOG_ERR, "failed to open interrupt IN pipe\n");
			err = -EIO;
			break;
		}

		priv->pipeBulkIn = usb_open(drv, ins, usb_transfer_bulk, usb_dir_in);
		if (priv->pipeBulkIn < 0) {
			cy_log_msg(CYLF_USB, CY_LOG_ERR, "failed to open bulk IN pipe\n");
			err = -EIO;
			break;
		}

		priv->pipeBulkOut = usb_open(drv, ins, usb_transfer_bulk, usb_dir_out);
		if (priv->pipeBulkOut < 0) {
			cy_log_msg(CYLF_USB, CY_LOG_ERR, "failed to open bulk OUT pipe\n");
			err = -EIO;
			break;
		}

		priv->urb = usb_urbAlloc(drv, priv->pipeBulkIn, NULL, usb_dir_in, priv->config.bulkRecvBufSz, usb_transfer_bulk);
		if (priv->urb < 0) {
			cy_log_msg(CYLF_USB, CY_LOG_ERR, "failed to allocate URB\n");
			err = -ENOMEM;
			break;
		}

		priv->dev.id = ins->locationID;
		priv->dev.dev = ins->dev;
		priv->dev.bus = ins->bus;
		priv->dev.interface = ins->interface;
		priv->dev.info = (cyhal_usb_devinfo_t) {
			.vid = ins->descriptor.idVendor,
			.pid = ins->descriptor.idProduct,
		};
	} while (0);

	mutexUnlock(priv->mutex);

	if (err < 0) {
		return err;
	}

	/* don't create filesystem devices by ourselves (at least for now) */
	event_out->deviceCreated = false;
	priv->config.onInsertion(&priv->dev.info);

	return 0;
}


static int cyhal_usb_handleDeletion(usb_driver_t *drv, usb_deletion_t *del)
{
	usb_priv_t *priv = drv->priv;

	assert(priv->dev.id != 0); /* sanity check: device has to be inserted before deletion */

	if (priv->dev.dev == del->dev && priv->dev.bus == del->bus && priv->dev.interface == del->interface) {
		priv->config.onDeletion(&priv->dev.info);

		mutexLock(priv->mutex);
		(void)usb_urbFree(drv, priv->pipeBulkIn, priv->urb);
		memset(&priv->dev, 0, sizeof(priv->dev));
		mutexUnlock(priv->mutex);
	}

	return 0;
}


static int cyhal_usb_handleCompletion(usb_driver_t *drv, usb_completion_t *completion, const char *data, size_t len)
{
	usb_priv_t *priv = drv->priv;
	int err = usb_transferAsync(drv, priv->pipeBulkIn, priv->urb, priv->config.bulkRecvBufSz, NULL);
	priv->config.onBulkRecv(data, len);
	return err;
}


static int cyhal_usb_doInit(usb_driver_t *drv, void *arg)
{
	usb_priv_t *priv = drv->priv;
	int err = mutexCreate(&priv->mutex);
	if (err < 0) {
		cy_log_msg(CYLF_USB, CY_LOG_ERR, "could not create USB lock\n");
	}
	return err;
}


static int cyhal_usb_doDestroy(usb_driver_t *drv)
{
	usb_priv_t *priv = drv->priv;
	resourceDestroy(priv->mutex);
	return EOK;
}


static usb_driver_t cyhal_usb_drv = {
	.name = "cyusb",
	.handlers = {
		.insertion = cyhal_usb_handleInsertion,
		.deletion = cyhal_usb_handleDeletion,
		.completion = cyhal_usb_handleCompletion,
	},
	.ops = {
		.init = cyhal_usb_doInit,
		.destroy = cyhal_usb_doDestroy,
	},
};


static inline cy_rslt_t cyhal_usb_convert_result(ssize_t result, int err)
{
	return (result >= 0) ? CY_RSLT_SUCCESS : CYHAL_USB_RSLT_ERR_DEVICE_OP(abs(err));
}


cy_rslt_t cyhal_usb_init(cyhal_usb_t *obj, cyhal_usb_config_t *config)
{
	if (obj == NULL) {
		return CY_RTOS_BAD_PARAM;
	}

	if (obj->usb_priv != NULL) {
		cy_log_msg(CYLF_USB, CY_LOG_ERR, "usb is already initialized\n");
		return CY_RTOS_GENERAL_ERROR;
	}

	int err, i;
	usb_priv_t *priv;
	usb_device_id_t *filters;

	obj->usb_priv = NULL;

	priv = calloc(1, sizeof(*priv) + (config->nfilters * sizeof(*priv->driver->filters)));
	if (priv == NULL) {
		cy_log_msg(CYLF_USB, CY_LOG_ERR, "no memory for usb_priv\n");
		return CY_RTOS_NO_MEMORY;
	}

	filters = (void *)((uintptr_t)priv + sizeof(*priv));
	for (i = 0; i < config->nfilters; i++) {
		filters[i] = (usb_device_id_t) {
			.vid = config->filters->vid,
			.pid = config->filters->pid,
			.dclass = USBDRV_ANY,
			.subclass = USBDRV_ANY,
			.protocol = USBDRV_ANY,
		};
	}

	priv->config = *config;
	priv->driver = &cyhal_usb_drv;
	priv->driver->filters = filters;
	priv->driver->nfilters = config->nfilters;
	priv->driver->priv = priv;

	err = usb_driverThreadpoolSpawn(priv->driver, CYHAL_USB_DRIVER_THREAD_PRIO, CYHAL_USB_DRIVER_THREADS, NULL, 0);
	if (err < 0) {
		cy_log_msg(CYLF_USB, CY_LOG_ERR, "failed to initialize USB driver\n");
		free(priv);
		return cyhal_usb_convert_result(err, err);
	}

	obj->usb_priv = priv;

	return CY_RSLT_SUCCESS;
}


cy_rslt_t cyhal_usb_deinit(cyhal_usb_t *obj)
{
	if (obj == NULL || obj->usb_priv == NULL) {
		return CY_RTOS_BAD_PARAM;
	}

	usb_priv_t *priv = obj->usb_priv;
	(void)usb_driverThreadpoolDestroy(&cyhal_usb_drv);
	free(priv);
	obj->usb_priv = NULL;

	return CY_RSLT_SUCCESS;
}


/** Start RX
 *
 * @param[in] obj The USB object
 * @return The status of the start RX request
 */
cy_rslt_t cyhal_usb_start_bulk_rx(const cyhal_usb_t *obj)
{
	if (obj == NULL || obj->usb_priv == NULL) {
		return CY_RTOS_BAD_PARAM;
	}

	usb_priv_t *priv = obj->usb_priv;
	mutexLock(priv->mutex);
	int err = _cyhal_usb_startRx(priv->driver);
	mutexUnlock(priv->mutex);
	return cyhal_usb_convert_result(err, err);
}


/** Stop RX
 *
 * @param[in] obj The USB object
 * @return The status of the stop RX request
 */
cy_rslt_t cyhal_usb_stop_bulk_rx(const cyhal_usb_t *obj)
{
	if (obj == NULL || obj->usb_priv == NULL) {
		return CY_RTOS_BAD_PARAM;
	}

	usb_priv_t *priv = obj->usb_priv;
	mutexLock(priv->mutex);
	int err = _cyhal_usb_stopRx(priv->driver);
	mutexUnlock(priv->mutex);
	return cyhal_usb_convert_result(err, err);
}


cy_rslt_t cyhal_usb_dl_cmd(const cyhal_usb_t *obj, uint8_t cmd, uint16_t wIndex, void *buffer, size_t buflen)
{
	if (obj == NULL || obj->usb_priv == NULL) {
		return CY_RTOS_BAD_PARAM;
	}
	const usb_priv_t *priv = obj->usb_priv;
	usb_setup_packet_t setup = {
		.bmRequestType = REQUEST_DIR_DEV2HOST | REQUEST_TYPE_VENDOR | REQUEST_RECIPIENT_INTERFACE,
		.bRequest = cmd,
		.wValue = 0,
		.wIndex = wIndex,
		.wLength = buflen,
	};
	int err = usb_transferControl(priv->driver, priv->pipeCtrl, &setup, buffer, buflen, usb_dir_in);
	return cyhal_usb_convert_result(err, err);
}


cy_rslt_t cyhal_usb_bulk_send(const cyhal_usb_t *obj, void *buffer, size_t *buflen)
{
	if (obj == NULL || obj->usb_priv == NULL) {
		return CY_RTOS_BAD_PARAM;
	}

	const usb_priv_t *priv = obj->usb_priv;

	ssize_t err = usb_transferBulk(priv->driver, priv->pipeBulkOut, buffer, *buflen, usb_dir_out);
	if (err < 0) {
		return CYHAL_USB_RSLT_ERR_DEVICE_OP(abs(err));
	}

	*buflen = (size_t)err;
	return CY_RSLT_SUCCESS;
}


/* bulk_recv is a callback (onRecv) */


cy_rslt_t cyhal_usb_ctrl_send(const cyhal_usb_t *obj, void *buffer, size_t *buflen)
{
	if (obj == NULL || obj->usb_priv == NULL) {
		return CY_RTOS_BAD_PARAM;
	}

	const usb_priv_t *priv = obj->usb_priv;
	usb_setup_packet_t setup = {
		.bmRequestType = REQUEST_DIR_HOST2DEV | REQUEST_TYPE_CLASS | REQUEST_RECIPIENT_INTERFACE,
		.bRequest = 0,
		.wValue = 0,
		.wIndex = 0,
		.wLength = *buflen,
	};
	int err = usb_transferControl(priv->driver, priv->pipeCtrl, &setup, buffer, *buflen, usb_dir_out);
	cy_rslt_t result = cyhal_usb_convert_result(err, err);
	if (result == CY_RSLT_SUCCESS) {
		*buflen = err;
	}

	return result;
}


cy_rslt_t cyhal_usb_ctrl_receive(const cyhal_usb_t *obj, void *buffer, size_t *buflen)
{
	if (obj == NULL || obj->usb_priv == NULL) {
		return CY_RTOS_BAD_PARAM;
	}

	const usb_priv_t *priv = obj->usb_priv;
	usb_setup_packet_t setup = {
		.bmRequestType = REQUEST_DIR_DEV2HOST | REQUEST_TYPE_CLASS | REQUEST_RECIPIENT_INTERFACE,
		.bRequest = 1,
		.wValue = 0,
		.wIndex = 0,
		.wLength = *buflen,
	};
	int err = usb_transferControl(priv->driver, priv->pipeCtrl, &setup, buffer, *buflen, usb_dir_in);
	cy_rslt_t result = cyhal_usb_convert_result(err, err);
	if (result == CY_RSLT_SUCCESS) {
		*buflen = err;
	}

	return result;
}


#endif /* (CYBSP_WIFI_INTERFACE_TYPE == CYBSP_USB_INTERFACE) */
