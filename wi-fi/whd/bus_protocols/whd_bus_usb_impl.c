// TODO: transfer to cyhal_usb?

/*
 * Copyright 2023, Cypress Semiconductor Corporation (an Infineon company)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** @file
 *  Implementation of USB bus low level functions
 *  by using em-USB Host middleware.
 */

#include <sys/minmax.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/msg.h>
#include <unistd.h>

#include "cy_result.h"
#include "cyabs_rtos.h"
#include "cybsp_wifi.h"

#include "usbwlan.h"
#include "whd_buffer_api.h"

#if (CYBSP_WIFI_INTERFACE_TYPE == CYBSP_USB_INTERFACE)

#include "whd_bus_usb_protocol.h"

/******************************************************
 *             Constants
 ******************************************************/

#define WHD_USB_RX_QUEUE_SIZE 16

/******************************************************
 *             Structures
 ******************************************************/

static struct {
	char usb_device_path[32];
	oid_t usb_device_oid;
	int usb_device_fd;

	atomic_bool usb_device_ready;
	atomic_bool fw_started;

	struct {
		cy_thread_t thread;
		cy_semaphore_t semaphore;
		cy_queue_t queue;
		atomic_bool should_exit;
	} rx;

	cy_thread_t device_notify_thread;
} whd_bus_usb_device_info;


/* Backplane & jtag accesses */
typedef struct {
	uint32_t cmd;  /* tag to identify the cmd */
	uint32_t addr; /* backplane address for write */
	uint32_t len;  /* length of data: 1, 2, 4 bytes */
	uint32_t data; /* data to write */
} whd_bus_usb_hwacc_t;


/******************************************************
 *             Static Function Declarations
 ******************************************************/
static whd_result_t whd_bus_usb_start_device_status_thread(void);
static whd_result_t whd_bus_usb_on_device_ready(void);
static void whd_bus_usb_on_device_removed(void);

static whd_result_t whd_bus_usb_convert_status(int status);

static void whd_usb_rx_thread(void *arg);


// TODO: prototype + call THIS in whd_bus_usb_deinit (or *_detach?)
void deinit_usb(whd_driver_t whd_driver)
{
	// TODO: deinit queue, exit both threads
	whd_bus_usb_device_info.rx.should_exit = true;
	if (whd_bus_usb_device_info.usb_device_fd != -1) {
		(void)close(whd_bus_usb_device_info.usb_device_fd);
	}
	whd_bus_usb_device_info.usb_device_fd = -1;
	whd_bus_usb_device_info.usb_device_oid = (oid_t) { 0 };
	whd_bus_usb_device_info.usb_device_ready = false;
	whd_bus_usb_device_info.fw_started = false;
	(void)cy_rtos_queue_deinit(&whd_bus_usb_device_info.rx.queue);
}


whd_result_t init_usb(whd_driver_t whd_driver, bool wait_usb)
{
	whd_result_t retval;

	whd_bus_usb_device_info.rx.should_exit = false;
	whd_bus_usb_device_info.fw_started = false;
	whd_bus_usb_device_info.usb_device_ready = false;
	// TODO: get path from (somewhere?)
	memcpy(whd_bus_usb_device_info.usb_device_path, "/dev/wlan0", sizeof("/dev/wlan0"));
	whd_bus_usb_device_info.usb_device_fd = -1;

	// TODO: async notification instead of polling for device (somehow)
	retval = whd_bus_usb_start_device_status_thread();
	if (retval != WHD_SUCCESS) {
		fprintf(stderr, "whd_bus_usb_device_notify: could not start notify thread\n");
		return retval;
	}

	retval = cy_rtos_init_semaphore(&whd_bus_usb_device_info.rx.semaphore, 1, 0);
	if (retval != CY_RSLT_SUCCESS) {
		fprintf(stderr, "whd_bus_usb_device_notify: could not init semaphore\n");
		return WHD_HAL_ERROR;
	}

	/* Create RX task */
	retval = cy_rtos_create_thread(&whd_bus_usb_device_info.rx.thread,
			whd_usb_rx_thread,
			"whd_usb_rx",
			NULL,
			2048,
			max(whd_driver->thread_info.thread_priority - 1, 0),
			NULL);

	if (retval != WHD_SUCCESS) {
		fprintf(stderr, "Could not start whd_usb_rx thread: %d\n", retval);
		return WHD_HAL_ERROR;
	}

	/* Initialize rx queue */
	retval = whd_bus_rx_queue_init();
	if (retval != WHD_SUCCESS) {
		fprintf(stderr, "Could not initialize rx_queue: %d\n", retval);
		return WHD_HAL_ERROR;
	}

	/* Waiting connection of USB dangle */
	// TODO: wait on cond maybe?
	if (wait_usb) {
		WPRINT_WHD_INFO(("WHD: Waiting USB dongle...\n"));

		while (!whd_bus_usb_device_info.usb_device_ready) {
			usleep(500 * 1000);
		}

		WPRINT_WHD_INFO(("WHD: Dongle found!...\n"));
	}

	return WHD_SUCCESS;
}


/***************************************************************************************************
 * whd_usb_rx_thread_notify
 **************************************************************************************************/
void whd_usb_rx_thread_notify(void)
{
	cy_rtos_set_semaphore(&whd_bus_usb_device_info.rx.semaphore, false /* ignored */);
}


__attribute__((unused)) static void hexdump_packet(const void *buf, size_t len)
{
	printf("as str: %.*s\n", (int)len, (const char *)buf);
	for (size_t i = 0; i < len; i++) {
		if (i != 0 && i % 8 == 0) {
			printf("\n");
		}
		printf("%02x ", ((uint8_t *)buf)[i]);
	}
	printf("\n\n");
}


/***************************************************************************************************
 * whd_usb_rx_thread
 **************************************************************************************************/
static whd_result_t whd_bus_usb_handle_rx(whd_driver_t whd_driver, whd_buffer_t whd_rx_buffer)
{
	fflush(stdout);
	uint8_t *data = whd_buffer_get_current_piece_data_pointer(whd_driver, whd_rx_buffer);
	ssize_t size = read(whd_bus_usb_device_info.usb_device_fd, data, WHD_USB_MAX_RECEIVE_BUF_SIZE);

	if (size > 0) {
		// WPRINT_WHD_INFO(("%s: read %dB from USB\n", __FUNCTION__, size));
		/* Set final size of received packet */
		whd_buffer_set_size(whd_driver, whd_rx_buffer, size);
		whd_bus_rx_queue_enqueue(whd_rx_buffer);
	}
	else {
		WPRINT_WHD_ERROR(("FATAL: read on fd=%d failed: res=%d, %s (%d)\n", whd_bus_usb_device_info.usb_device_fd, size, strerror(errno), errno));
		return WHD_HAL_ERROR;
	}

	return WHD_SUCCESS;
}


static void whd_usb_rx_thread(void *arg)
{
	(void)arg;
	whd_driver_t whd_driver = cybsp_get_wifi_driver();
	whd_buffer_t whd_rx_buffer = NULL;

	WPRINT_WHD_INFO(("whd_usb_rx_thread started\n"));

	for (;;) {
		if (whd_bus_usb_device_info.rx.should_exit) {
			WPRINT_WHD_INFO(("whd_usb_rx_thread: exiting\n"));
			break;
		}

		if (!(whd_bus_usb_device_info.fw_started && (whd_bus_is_up(whd_driver) == WHD_TRUE))) {
			cy_rtos_delay_milliseconds(10);
			continue;
		}

		if (!whd_bus_rx_queue_is_full()) {
			if (whd_host_buffer_get(whd_driver, &whd_rx_buffer, WHD_NETWORK_RX, WHD_USB_MAX_RECEIVE_BUF_SIZE, CY_RTOS_NEVER_TIMEOUT) != WHD_SUCCESS) {
				WPRINT_WHD_ERROR(("whd_host_buffer_get failed\n"));
				cy_rtos_delay_milliseconds(1);
				continue;
			}

			if (whd_bus_usb_handle_rx(whd_driver, whd_rx_buffer) != WHD_SUCCESS) {
				WPRINT_WHD_ERROR(("handle RX failed %s:%d\n", __FILE__, __LINE__));
				whd_buffer_release(whd_driver, whd_rx_buffer, WHD_NETWORK_RX);
			}
		}
		else {
			WPRINT_WHD_INFO(("whd queue is full, going to sleep\n"));
			whd_thread_notify(whd_driver);
			cy_rtos_get_semaphore(&whd_bus_usb_device_info.rx.semaphore, CY_RTOS_NEVER_TIMEOUT, false /* ignored */);
		}

		whd_thread_notify(whd_driver);
	}
}


static int whd_bus_usb_ctrl(void *buffer, uint32_t buflen, const usbwlan_i_t *umsg)
{
	msg_t msg = {
		.type = mtDevCtl,
		.oid = whd_bus_usb_device_info.usb_device_oid,
	};

	switch (umsg->type) {
		case usbwlan_ctrl_out:
		case usbwlan_reg_write:
			msg.i.data = buffer;
			msg.i.size = buflen;
			break;

		case usbwlan_ctrl_in:
		case usbwlan_reg_read:
			msg.o.data = buffer;
			msg.o.size = buflen;
			break;

		case usbwlan_dl:
			msg.i.data = buffer;
			msg.i.size = buflen;
			msg.o.data = buffer;
			msg.o.size = buflen;
			break;

		default:
			return -1;
	}

	usbwlan_i_t *imsg = (usbwlan_i_t *)&msg.i.raw;
	memcpy(imsg, umsg, sizeof(*imsg));

	int length = msgSend(whd_bus_usb_device_info.usb_device_oid.port, &msg);
	if (length == 0 && msg.o.err != 0) {
		length = msg.o.err;
	}

	// TODO: check if msg.o.size == buflen (only on TX)
	if (length > 0) {
		memcpy(buffer, msg.o.data, length);
	}

	return length;
}


/***************************************************************************************************
 * whd_bus_usb_dl_cmd
 **************************************************************************************************/
whd_result_t whd_bus_usb_dl_cmd(whd_driver_t whd_driver, uint8_t cmd, void *buffer, uint32_t buflen)
{
	const usbwlan_i_t imsg = {
		.type = usbwlan_dl,
		.dl = {
			.cmd = cmd,
			.wIndex = (cmd == WHD_USB_DL_GO) ? 1 : 0,
		}
	};
	return whd_bus_usb_convert_status(whd_bus_usb_ctrl(buffer, buflen, &imsg));
}


/***************************************************************************************************
 * whd_bus_usb_dl_go
 **************************************************************************************************/
whd_result_t whd_bus_usb_dl_go(whd_driver_t whd_driver)
{
	(void)whd_bus_usb_dl_cmd(whd_driver, WHD_USB_DL_GO, NULL, 0);

	/* Force set not ready */
	whd_bus_usb_device_info.usb_device_ready = false;

	/* Wait new enumeration */
	while (!whd_bus_usb_device_info.usb_device_ready) {
		// TODO: adjust sleep amount
		usleep(100 * 1000);
	}

	whd_bus_usb_device_info.fw_started = true;

	return WHD_SUCCESS;
}


/***************************************************************************************************
 * whd_bus_usb_bulk_send
 **************************************************************************************************/
whd_result_t whd_bus_usb_bulk_send(whd_driver_t whd_driver, void *buffer, int len)
{
	(void)whd_driver;
	ssize_t status;

	/* Writes data to the BULK device */
	do {
		status = write(whd_bus_usb_device_info.usb_device_fd, buffer, len);
	} while (status != 0 && errno == EAGAIN);

	if (status != len) {
		fprintf(stderr, "WHD: write() failed: %s (%d)\n", strerror(errno), errno);
		fflush(stderr);
	}

	return whd_bus_usb_convert_status(status);
}


/***************************************************************************************************
 * whd_bus_usb_bulk_receive
 **************************************************************************************************/
whd_result_t whd_bus_usb_bulk_receive(whd_driver_t whd_driver, void *buffer, int len)
{
	(void)whd_driver;
	ssize_t status;

	/* Reads data from the BULK device */
	do {
		status = read(whd_bus_usb_device_info.usb_device_fd, buffer, len);
	} while (status != 0 && errno == EAGAIN);

	if (status != len) {
		fprintf(stderr, "WHD: read() failed: %d", status);
		fflush(stderr);
	}

	return whd_bus_usb_convert_status(status);
}


// TODO: unused, delete
#if 0
/*
   The bootloader supports additional commands to read and write data to/from backplane addresses
	DL_RDHW8: read an 8-bit value from a backplane address
	DL_RDHW16: read a 16-bit value from a backplane address (must be 2-byte aligned)
	DL_RDHW32: read a 32-bit value from a backplane address (must be 4-byte aligned)

   For example, to read the first 16-bit word of 43236 CIS (the CIS region begins at offset 0x30 of
	  OTP, which starts at backplane address 0x18000800):
	bmRequestType: 0xC1 (Read Vendor Interface)
	bRequest: 0x11 (DL_RDHW16)
	wValue:   0x0830 (lower 16 bits of backplane address)
	wIndex:   0x1800 (upper 16 bits of backplane address)
	wLength:  sizeof(hwacc_t)

	response buffer should be a pointer to type hwacc_t; if successful, the value read will be in
	   the hwacc_t.data field
	DL_WRHW: write a 8/16/32 bit value to a backplane address, observing byte alignment requirements

   For example, to write a 32-bit word to backplane address 0x18000634:
	bmRequestType: 0x41 (Write Vendor Interface)
	bRequest: 0x14 (DL_WRHW)
	wValue:   0x0001
	wIndex:   0x0000
	wLength:  sizeof(hwacc_t)

	buffer should be a pointer to type hwacc_t:
	hwacc.cmd  = 0x14 (DL_WRHW)
	hwacc.addr = 0x18000634
	hwacc.data = 32-bit value to write
	hwacc.len  = 4
 */
whd_result_t whd_bus_usb_readreg(whd_driver_t whd_driver, uint32_t regaddr, uint32_t datalen, uint32_t *value)
{
	whd_result_t status;
	whd_bus_usb_hwacc_t hwacc;
	uint32_t cmd;

	if (datalen == 1) {
		cmd = WHD_USB_DL_RDHW8;
	}
	else if (datalen == 2) {
		cmd = WHD_USB_DL_RDHW16;
	}
	else if (datalen == 4) {
		cmd = WHD_USB_DL_RDHW32;
	}
	else {
		return WHD_HAL_ERROR;
	}

	const usbwlan_i_t umsg = {
		.type = usbwlan_reg_read,
		.reg = {
			.cmd = cmd,
			.regaddr = regaddr,
		}
	};
	status = whd_bus_usb_ctrl(&hwacc, sizeof(whd_bus_usb_hwacc_t), &umsg);

	*value = hwacc.data;

	return status;
}


/***************************************************************************************************
 * whd_bus_usb_writereg
 **************************************************************************************************/
whd_result_t whd_bus_usb_writereg(whd_driver_t whd_driver, uint32_t regaddr, uint32_t datalen,
		uint32_t data)
{
	if (datalen != 1 && datalen != 2 && datalen != 4) {
		return WHD_HAL_ERROR;
	}

	whd_result_t status;
	whd_bus_usb_hwacc_t hwacc = {
		.cmd = WHD_USB_DL_WRHW,
		.addr = regaddr,
		.data = data,
		.len = datalen,
	};

	const usbwlan_i_t umsg = {
		.type = usbwlan_reg_write,
		.reg = {
			.cmd = WHD_USB_DL_WRHW,
			.regaddr = regaddr,
		}
	};
	status = whd_bus_usb_ctrl(&hwacc, sizeof(whd_bus_usb_hwacc_t), &umsg);

	return whd_bus_usb_convert_status(status);
}
#endif


/* Device data transfer functions */
whd_result_t whd_bus_usb_send_ctrl(whd_driver_t whd_driver, void *buffer, uint32_t *len)
{
	const usbwlan_i_t umsg = { .type = usbwlan_ctrl_out };
	ssize_t status;

	do {
		status = whd_bus_usb_ctrl(buffer, *len, &umsg);
	} while (status < 0);

	*len = status;

	return whd_bus_usb_convert_status(status);
}


/***************************************************************************************************
 * whd_bus_usb_receive_ctrl_buffer
 **************************************************************************************************/
whd_result_t whd_bus_usb_receive_ctrl_buffer(whd_driver_t whd_driver, whd_buffer_t *buffer)
{
	whd_host_buffer_get(whd_driver, buffer, WHD_NETWORK_RX,
			(unsigned short)(WHD_USB_MAX_RECEIVE_BUF_SIZE + (uint16_t)sizeof(whd_buffer_header_t)),
			(whd_sdpcm_has_tx_packet(whd_driver) ? 0 : WHD_RX_BUF_TIMEOUT));

	const usbwlan_i_t umsg = { .type = usbwlan_ctrl_in };
	ssize_t status;
	uint8_t *rx_buf = whd_buffer_get_current_piece_data_pointer(whd_driver, *buffer);

	do {
		status = whd_bus_usb_ctrl(rx_buf, WHD_USB_MAX_RECEIVE_BUF_SIZE, &umsg);
	} while (status < 0);

	if (status > 0) {
		(void)whd_buffer_set_size(whd_driver, *buffer, status);
	}
	else {
		status = -1;
	}

	return whd_bus_usb_convert_status(status);
}


static void whd_bus_usb_device_notify_thread(void *arg)
{
	(void)arg;

	oid_t oid;
	int res;
	int last_res = -1;

	// TODO: async poll in usb driver?
	for (;;) {
		res = lookup(whd_bus_usb_device_info.usb_device_path, NULL, &oid);

		if (res != last_res) {
			if (res >= 0) {
				/* device found */
				if (whd_bus_usb_on_device_ready() == WHD_SUCCESS) {
					whd_bus_usb_device_info.usb_device_oid = oid;
					whd_bus_usb_device_info.usb_device_ready = true;
				}
			}
			else {
				whd_bus_usb_device_info.usb_device_ready = false;
				whd_bus_usb_device_info.usb_device_oid = (oid_t) { 0 };
				whd_bus_usb_on_device_removed();
			}

			last_res = res;
		}

		// TODO: better sleep amount
		usleep(100 * 1000);
	}
}


/***************************************************************************************************
 * whd_bus_usb_device_notify
 **************************************************************************************************/
static whd_result_t whd_bus_usb_start_device_status_thread(void)
{
	// TODO: proper prio (or better: async wait for in/out events instead of this)
	cy_rslt_t result = cy_rtos_create_thread(&whd_bus_usb_device_info.device_notify_thread,
			whd_bus_usb_device_notify_thread,
			"whd_usb_present_thread", NULL,
			2048, 2, NULL);

	return (result == CY_RSLT_SUCCESS) ? WHD_SUCCESS : WHD_HAL_ERROR;
}


/***************************************************************************************************
 * whd_bus_usb_on_device_ready
 **************************************************************************************************/
static whd_result_t whd_bus_usb_on_device_ready(void)
{
	if (whd_bus_usb_device_info.usb_device_fd == -1) {
		whd_bus_usb_device_info.usb_device_fd = open(whd_bus_usb_device_info.usb_device_path, O_RDWR);
		if (whd_bus_usb_device_info.usb_device_fd < 0) {
			WPRINT_WHD_ERROR(("%s:%d: open() failed (%d)\n", __FILE__, __LINE__, errno));
			return WHD_HAL_ERROR;
		}
		printf("WHD: got fd %d\n", whd_bus_usb_device_info.usb_device_fd);
	}
	return WHD_SUCCESS;
}


/***************************************************************************************************
 * whd_bus_usb_on_device_removed
 **************************************************************************************************/
static void whd_bus_usb_on_device_removed(void)
{
	if (whd_bus_usb_device_info.usb_device_fd != -1) {
		printf("WHD: closing file %d\n", whd_bus_usb_device_info.usb_device_fd);
		(void)close(whd_bus_usb_device_info.usb_device_fd);
		whd_bus_usb_device_info.usb_device_fd = -1;
	}
}


/***************************************************************************************************
 * whd_bus_usb_convert_status
 **************************************************************************************************/
static whd_result_t whd_bus_usb_convert_status(ssize_t status)
{
	return (status >= 0) ? WHD_SUCCESS : WHD_HAL_ERROR;
}


/* Initialize rx_queue */
whd_result_t whd_bus_rx_queue_init(void)
{
#if 0
	static uint8_t whd_queue_buf[WHD_USB_RX_QUEUE_SIZE * sizeof(whd_buffer_t *)];
	whd_bus_usb_device_info.rx.queue.data = (void **)whd_queue_buf;
#endif

	int err = cy_rtos_queue_init(&whd_bus_usb_device_info.rx.queue, WHD_USB_RX_QUEUE_SIZE, sizeof(whd_buffer_t *));
	if (err != CY_RSLT_SUCCESS) {
		printf("cy_rtos_queue_init: error: %d\n", err);
		return WHD_QUEUE_ERROR;
	}
	return WHD_SUCCESS;
}


/* Checks if the queue is full */
bool whd_bus_rx_queue_is_full(void)
{
	size_t num_spaces;
	cy_rtos_queue_space(&whd_bus_usb_device_info.rx.queue, &num_spaces);
	return (num_spaces > 0) ? false : true;
}


/* Returns the total number of elements in the queue */
size_t whd_bus_rx_queue_size(void)
{
	size_t num = 0;
	cy_rtos_queue_count(&whd_bus_usb_device_info.rx.queue, &num);
	return num;
}


/* Adds an element to the end of the queue  */
whd_result_t whd_bus_rx_queue_enqueue(whd_buffer_t *data)
{
	cy_rslt_t status = cy_rtos_queue_put(&whd_bus_usb_device_info.rx.queue, &data, CY_RTOS_NEVER_TIMEOUT);
	return status ? WHD_QUEUE_ERROR : WHD_SUCCESS;
}


/* Removes an element from the front of the queue */
whd_result_t whd_bus_rx_queue_dequeue(whd_buffer_t *data)
{
	cy_rslt_t status = cy_rtos_queue_get(&whd_bus_usb_device_info.rx.queue, data, CY_RTOS_NEVER_TIMEOUT);
	return status ? WHD_QUEUE_ERROR : WHD_SUCCESS;
}


#endif /* (CYBSP_WIFI_INTERFACE_TYPE == CYBSP_USB_INTERFACE) */
