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

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <string.h>
#include <sys/msg.h>
#include <unistd.h>

#include "cy_result.h"
#include "usbwlan.h"

#include "cy_log.h"
#include "cyabs_rtos.h"
#include "cyhal_usb.h"


typedef struct {
	int fd;
	oid_t oid;
} usb_priv_t;


cy_rslt_t cyhal_usb_init(cyhal_usb_t *obj, const char *path)
{
	if (obj == NULL) {
		return CY_RTOS_BAD_PARAM;
	}

	usb_priv_t *priv;
	oid_t oid;

	obj->usb_priv = NULL;

	if (lookup(path, NULL, &oid) < 0) {
		return CYHAL_USB_RSLT_ERR_DEVICE_NOT_FOUND;
	}

	priv = malloc(sizeof(*priv));
	if (priv == NULL) {
		cy_log_msg(CYLF_USB, CY_LOG_ERR, "no memory for usb_priv\n");
		return CY_RTOS_NO_MEMORY;
	}
	memset(priv, 0, sizeof(*priv));

	priv->oid = oid;
	priv->fd = open(path, O_RDWR);
	if (priv->fd < 0) {
		cy_log_msg(CYLF_USB, CY_LOG_ERR, "couldn't open %s: %s (%d)\n", path, strerror(errno), errno);
		free(priv);
		return CYHAL_USB_RSLT_ERR_DEVICE_OP(errno);
	}

	obj->usb_priv = priv;

	return CY_RSLT_SUCCESS;
}


cy_rslt_t cyhal_usb_wait_state(const char *path, bool state)
{
	int result;
	__attribute__((unused)) oid_t oid;

	do {
		result = lookup(path, NULL, &oid);
		usleep(10 * 1000);
	} while ((result >= 0) != state);

	return CY_RSLT_SUCCESS;
}


static ssize_t cyhal_usb_devctl(const usb_priv_t *priv, void *buffer, size_t buflen, const usbwlan_i_t *imsg)
{
	bool is_tx;
	msg_t msg = {
		.type = mtDevCtl,
		.oid = priv->oid,
	};

	switch (imsg->type) {
		case usbwlan_ctrlOut:
		case usbwlan_regWrite:
			is_tx = true;
			msg.i.data = buffer;
			msg.i.size = buflen;
			break;

		case usbwlan_setChip:
			is_tx = false;
			msg.i.data = buffer;
			msg.i.size = buflen;
			break;

		case usbwlan_ctrlIn:
		case usbwlan_regRead:
		case usbwlan_dl:
		case usbwlan_getChip:
			is_tx = false;
			msg.o.data = buffer;
			msg.o.size = buflen;
			break;

		case usbwlan_abort:
			is_tx = false;
			break;

		default:
			return -EOPNOTSUPP;
	}

	memcpy(msg.i.raw, imsg, sizeof(*imsg));

	int length = msgSend(priv->oid.port, &msg);
	if (length < 0) {
		return length;
	}
	else {
		if (msg.o.err < 0) {
			return msg.o.err;
		}
		else {
			length = msg.o.err;
		}
	}

	if (is_tx && length != buflen) {
		return -EINVAL;
	}

	return length;
}


cy_rslt_t cyhal_usb_free(cyhal_usb_t *obj)
{
	if (obj == NULL || obj->usb_priv == NULL) {
		return CY_RTOS_BAD_PARAM;
	}

	usb_priv_t *priv = obj->usb_priv;

	if (priv != NULL) {
		if (priv->fd != -1) {
			usbwlan_i_t abortmsg = { .type = usbwlan_abort };
			cyhal_usb_devctl(priv, NULL, 0, &abortmsg);
			close(priv->fd);
			priv->fd = -1;
		}
		memset(&priv->oid, 0, sizeof(priv->oid));

		free(priv);
		obj->usb_priv = NULL;
	}

	return CY_RSLT_SUCCESS;
}


static inline cy_rslt_t cyhal_usb_convert_result(ssize_t result)
{
	return (result >= 0) ? CY_RSLT_SUCCESS : CYHAL_USB_RSLT_ERR_DEVICE_OP(result);
}


cy_rslt_t cyhal_usb_get_chip(const cyhal_usb_t *obj, uint32_t *chip)
{
	if (obj == NULL || obj->usb_priv == NULL) {
		return CY_RTOS_BAD_PARAM;
	}
	const usb_priv_t *priv = obj->usb_priv;
	const usbwlan_i_t imsg = { .type = usbwlan_getChip };
	return cyhal_usb_convert_result(cyhal_usb_devctl(priv, chip, sizeof(*chip), &imsg));
}


cy_rslt_t cyhal_usb_set_chip(const cyhal_usb_t *obj, uint32_t chip)
{
	if (obj == NULL || obj->usb_priv == NULL) {
		return CY_RTOS_BAD_PARAM;
	}
	const usb_priv_t *priv = obj->usb_priv;
	const usbwlan_i_t imsg = { .type = usbwlan_setChip };
	int res = cyhal_usb_devctl(priv, &chip, sizeof(chip), &imsg);
	printf("result is %d\n", res);
	return cyhal_usb_convert_result(res);
}


cy_rslt_t cyhal_usb_dl_cmd(const cyhal_usb_t *obj, uint8_t cmd, void *buffer, size_t buflen)
{
	if (obj == NULL || obj->usb_priv == NULL) {
		return CY_RTOS_BAD_PARAM;
	}
	const usb_priv_t *priv = obj->usb_priv;
	const usbwlan_i_t imsg = {
		.type = usbwlan_dl,
		.dl = {
			.cmd = cmd,
			.wIndex = (cmd == CYHAL_USB_DL_CMD_GO) ? 1 : 0,
		}
	};
	return cyhal_usb_convert_result(cyhal_usb_devctl(priv, buffer, buflen, &imsg));
}


cy_rslt_t cyhal_usb_bulk_send(const cyhal_usb_t *obj, void *buffer, size_t *buflen)
{
	if (obj == NULL || obj->usb_priv == NULL) {
		return CY_RTOS_BAD_PARAM;
	}

	const usb_priv_t *priv = obj->usb_priv;
	ssize_t status;
	ssize_t remaining = *buflen;
	uint8_t *ptr = buffer;

	while (remaining > 0) {
		status = write(priv->fd, ptr, remaining);
		if (status < 0) {
			if ((errno == EAGAIN) || (errno == EINTR)) {
				usleep(100);
				continue;
			}
			else {
				return CYHAL_USB_RSLT_ERR_DEVICE_OP(errno);
			}
		}
		remaining -= status;
		ptr += status;
	}

	*buflen = (size_t)(ptr - (uint8_t *)buffer);
	return CY_RSLT_SUCCESS;
}


cy_rslt_t cyhal_usb_bulk_receive(const cyhal_usb_t *obj, void *buffer, size_t *buflen)
{
	if (obj == NULL || obj->usb_priv == NULL) {
		return CY_RTOS_BAD_PARAM;
	}

	const usb_priv_t *priv = obj->usb_priv;
	ssize_t status;

	for (;;) {
		status = read(priv->fd, buffer, *buflen);
		if (status < 0 && (errno == EAGAIN || errno == EINTR)) {
			usleep(100);
			continue;
		}
		else {
			break;
		}
	}

	if (status < 0) {
		return CYHAL_USB_RSLT_ERR_DEVICE_OP(errno);
	}

	*buflen = status;
	return CY_RSLT_SUCCESS;
}


cy_rslt_t cyhal_usb_ctrl_send(const cyhal_usb_t *obj, void *buffer, size_t *buflen)
{
	if (obj == NULL || obj->usb_priv == NULL) {
		return CY_RTOS_BAD_PARAM;
	}

	const usb_priv_t *priv = obj->usb_priv;
	const usbwlan_i_t umsg = { .type = usbwlan_ctrlOut };
	ssize_t status;
	cy_rslt_t result;

	for (;;) {
		status = cyhal_usb_devctl(priv, buffer, *buflen, &umsg);
		if (status < 0 && (errno == EAGAIN || errno == EINTR)) {
			usleep(100);
			continue;
		}
		else {
			break;
		}
	}

	result = cyhal_usb_convert_result(status);
	if (result == CY_RSLT_SUCCESS) {
		*buflen = status;
	}

	return result;
}


cy_rslt_t cyhal_usb_ctrl_receive(const cyhal_usb_t *obj, void *buffer, size_t *buflen)
{
	if (obj == NULL || obj->usb_priv == NULL) {
		return CY_RTOS_BAD_PARAM;
	}

	const usb_priv_t *priv = obj->usb_priv;
	const usbwlan_i_t umsg = { .type = usbwlan_ctrlIn };
	ssize_t status;
	cy_rslt_t result;

	for (;;) {
		status = cyhal_usb_devctl(priv, buffer, *buflen, &umsg);
		if (status < 0 && (errno == EAGAIN || errno == EINTR)) {
			usleep(100);
			continue;
		}
		else {
			break;
		}
	}

	result = cyhal_usb_convert_result(status);
	if (result == CY_RSLT_SUCCESS) {
		*buflen = status;
	}

	return result;
}
