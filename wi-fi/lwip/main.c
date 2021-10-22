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

#include "lwip/sys.h"

#include "whd_wifi_api.h"
#include "whd_wlioctl.h"
#include "cybsp.h"
#include "cybsp_wifi.h"
#include "cy_lwip.h"
#include "cyabs_rtos.h"
#include "cy_lwip_log.h"

#include <string.h>
#include <sys/minmax.h>
#include <posix/utils.h>


#define WIFI_THREAD_PRIO    4
#define WIFI_THREAD_STACKSZ (4 * _PAGE_SIZE)

#define WIFI_DEV_ID   0
#define WIFI_DEV_NAME "/dev/wifi"

#define AP_SECURITY_MODE WHD_SECURITY_WPA2_AES_PSK
#define AP_CHANNEL       1

#define SNPRINTF_APPEND(fmt, ...) \
	do { \
		if (!overflow) { \
			int n = snprintf(buf, size, fmt, ##__VA_ARGS__); \
			if (n >= size) \
				overflow = 1; \
			else { \
				size -= n; \
				buf += n; \
			} \
		} \
	} while (0)


static struct {
	bool running;
	whd_ssid_t ssid;
	uint8_t key[WSEC_MAX_PSK_LEN];
	uint8_t key_len;
	cy_lwip_nw_interface_t iface;
	struct {
		int busy;
		char buf[64];
		int len;
	} dev;
} wifi_common;

static ip_static_addr_t ap_addr = {
	.addr = IPADDR4_INIT_BYTES(192, 168, 2, 1),
	.netmask = IPADDR4_INIT_BYTES(255, 255, 255, 0),
	.gateway = IPADDR4_INIT_BYTES(192, 168, 2, 1)
};


int wifi_ap_set_ssid(const char *ssid, size_t len)
{
	if (len > SSID_NAME_SIZE) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi SSID (max length is %u)\n", SSID_NAME_SIZE);
		return -1;
	}

	memcpy(wifi_common.ssid.value, ssid, len);
	wifi_common.ssid.length = len;

	return 0;
}


int wifi_ap_set_key(const char *key, size_t len)
{
	if (len < WSEC_MIN_PSK_LEN) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi key (min length is %u)\n", WSEC_MIN_PSK_LEN);
		return -1;
	}

	if (len > WSEC_MAX_PSK_LEN) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi key (max length is %u)\n", WSEC_MAX_PSK_LEN);
		return -1;
	}

	memcpy(wifi_common.key, key, len);
	wifi_common.key_len = len;

	return 0;
}


int wifi_ap_start(void)
{
	cy_rslt_t result;

	if (wifi_common.running) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_WARNING, "Wi-Fi is already running\n");
		return 0;
	}

	result = cybsp_init();
	if (result != CY_RSLT_SUCCESS) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't init Wi-Fi HW\n");
		return -1;
	}

	result = cybsp_wifi_init_primary(&wifi_common.iface.whd_iface);
	if (result != CY_RSLT_SUCCESS) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't init Wi-Fi interface\n");
		cybsp_free();
		return -2;
	}

	wifi_common.iface.role = CY_LWIP_AP_NW_INTERFACE;

	result = cy_lwip_add_interface(&wifi_common.iface, &ap_addr);
	if (result != CY_RSLT_SUCCESS) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't add Wi-Fi interface\n");
		cybsp_wifi_deinit(wifi_common.iface.whd_iface);
		cybsp_free();
		return -3;
	}

	result = cy_lwip_network_up(&wifi_common.iface);
	if (result != CY_RSLT_SUCCESS) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't bring up Wi-Fi interface\n");
		cy_lwip_remove_interface(&wifi_common.iface);
		cybsp_wifi_deinit(wifi_common.iface.whd_iface);
		cybsp_free();
		return -4;
	}

	result = whd_wifi_init_ap(wifi_common.iface.whd_iface, &wifi_common.ssid, AP_SECURITY_MODE, wifi_common.key, wifi_common.key_len, AP_CHANNEL);
	if (result != CY_RSLT_SUCCESS) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't init Wi-Fi AP\n");
		cy_lwip_network_down(&wifi_common.iface);
		cy_lwip_remove_interface(&wifi_common.iface);
		cybsp_wifi_deinit(wifi_common.iface.whd_iface);
		cybsp_free();
		return -5;
	}

	result = whd_wifi_start_ap(wifi_common.iface.whd_iface);
	if (result != CY_RSLT_SUCCESS) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't start Wi-Fi AP\n");
		cy_lwip_network_down(&wifi_common.iface);
		cy_lwip_remove_interface(&wifi_common.iface);
		cybsp_wifi_deinit(wifi_common.iface.whd_iface);
		cybsp_free();
		return -6;
	}

	wifi_common.running = true;

	return 0;
}


void wifi_ap_stop(void)
{
	if (!wifi_common.running) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_WARNING, "Wi-Fi is already stopped\n");
		return;
	}

	whd_wifi_stop_ap(wifi_common.iface.whd_iface);
	cy_lwip_network_down(&wifi_common.iface);
	cy_lwip_remove_interface(&wifi_common.iface);
	cybsp_wifi_deinit(wifi_common.iface.whd_iface);
	cybsp_free();

	wifi_common.running = false;
}


static int wifi_dev_open(int flags)
{
	char *buf;
	size_t size;
	int overflow = 0;

	if (wifi_common.dev.busy)
		return -EBUSY;

	buf = wifi_common.dev.buf;
	size = sizeof(wifi_common.dev.buf);

	SNPRINTF_APPEND("running=%u\n", wifi_common.running);

	if (overflow)
		return -EFBIG;

	wifi_common.dev.busy = 1;
	wifi_common.dev.len = buf - wifi_common.dev.buf;

	return 0;
}


static int wifi_dev_close(void)
{
	if (!wifi_common.dev.busy)
		return -EBADF;
	wifi_common.dev.busy = 0;
	return 0;
}


static int wifi_dev_read(char *data, size_t size, offs_t offset)
{
	int cnt;

	if (offset > wifi_common.dev.len)
		return -ERANGE;

	cnt = min(size, wifi_common.dev.len - offset);
	memcpy(data, wifi_common.dev.buf + offset, cnt);

	return cnt;
}


static int wifi_dev_write(char *data, size_t size)
{
	if (size >= 5 && strncmp("ssid ", data, 5) == 0) {
		wifi_ap_set_ssid(data + 5, size - 5);
	}
	else if (size >= 4 && strncmp("key ", data, 4) == 0) {
		wifi_ap_set_key(data + 4, size - 4);
	}
	else if (strncmp("start", data, size) == 0) {
		wifi_ap_start();
	}
	else if (strncmp("stop", data, size) == 0) {
		wifi_ap_stop();
	}
	else {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "got unknown Wi-Fi command\n");
		return -EINVAL;
	}

	return size;
}


int wifi_dev_init(unsigned int port)
{
	oid_t wifi_oid = { port, WIFI_DEV_ID };

	return create_dev(&wifi_oid, WIFI_DEV_NAME);
}


static void wifi_thread(void *arg)
{
	cy_rslt_t result;
	unsigned int port;

	result = cy_log_init(CY_LOG_INFO);
	if (result != CY_RSLT_SUCCESS) {
		printf("phoenix-rtos-lwip: can't init Wi-Fi logs\n");
		return;
	}

	if (portCreate(&port) < 0) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create Wi-Fi port\n");
		return;
	}

	if (wifi_dev_init(port) < 0) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create Wi-Fi device\n");
		return;
	}

	for (;;) {
		msg_t msg = { 0 };
		unsigned long int rid;

		if (msgRecv(port, &msg, &rid) < 0)
			continue;

		switch (msg.type) {
			case mtOpen:
				msg.o.io.err = wifi_dev_open(msg.i.openclose.flags);
				break;

			case mtClose:
				msg.o.io.err = wifi_dev_close();
				break;

			case mtRead:
				msg.o.io.err = wifi_dev_read(msg.o.data, msg.o.size, msg.i.io.offs);
				break;

			case mtWrite:
				msg.o.io.err = wifi_dev_write(msg.i.data, msg.i.size);
				break;

			default:
				msg.o.io.err = -EINVAL;
				break;
		}

		msgRespond(port, &msg, rid);
	}
}


__constructor__(1000) void init_wifi(void)
{
	int err;

	if ((err = sys_thread_opt_new("wifi", wifi_thread, NULL, WIFI_THREAD_STACKSZ, WIFI_THREAD_PRIO, NULL))) {
		errout(err, "thread(wifi)");
	}
}
