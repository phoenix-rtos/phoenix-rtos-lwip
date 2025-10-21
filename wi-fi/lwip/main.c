/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP Wi-Fi
 *
 * Copyright 2021, 2026 Phoenix Systems
 * Author: Ziemowit Leszczynski, Julian Uziembło
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <ctype.h>
#include <string.h>
#include <sys/minmax.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <posix/utils.h>

#include "whd_wifi_api.h"
#include "whd_wlioctl.h"
#include "cybsp.h"
#include "cybsp_wifi.h"
#include "cy_lwip.h"
#include "cy_lwip_log.h"
#include "cy_log.h"

#include "lwipopts.h"
#include "netif.h"
#include "lwip/sys.h"

/* timeout for STA scanning in seconds */
#ifndef WIFI_STA_SCAN_TIMEOUT_SECONDS
#define WIFI_STA_SCAN_TIMEOUT_SECONDS 15
#endif

/* number of STA scans in the timeout time */
#ifndef WIFI_STA_N_SCANS
#define WIFI_STA_N_SCANS 3
#endif

_Static_assert(WIFI_STA_SCAN_TIMEOUT_SECONDS > 0, "STA scan timeout has to be positive");
_Static_assert(WIFI_STA_N_SCANS > 0, "Number of STA scans has to be positive");
_Static_assert(((float)WIFI_STA_SCAN_TIMEOUT_SECONDS / WIFI_STA_N_SCANS) >= 5.0f, "At least 5 seconds needed for every STA scan");

#define WIFI_THREAD_PRIO    4
#define WIFI_THREAD_STACKSZ 4096

#define WIFI_FLAG_STARTED (1U << 0)
#define WIFI_FLAG_FAILED  (1U << 1)
#define WIFI_FLAG_FINISH  (1U << 2)

#define STA_DEV_ID    0
#define STA_DEV_NAME  "/dev/wifi/sta"
#define STA_SCAN_TYPE WHD_SCAN_TYPE_ACTIVE
#define STA_BSS_TYPE  WHD_BSS_TYPE_ANY

#define AP_DEV_ID        1
#define AP_DEV_NAME      "/dev/wifi/ap"
#define AP_SECURITY_MODE WHD_SECURITY_WPA2_AES_PSK
#define AP_CHANNEL       1

#define CTRL_DEV_ID   2
#define CTRL_DEV_NAME "/dev/wifi/ctrl"

#define CONST_STRLEN(str) (sizeof(str) - 1)

#define SNPRINTF_APPEND(overflow, buf, size, fmt, ...) \
	do { \
		if (!overflow) { \
			int n = snprintf(buf, size, fmt, ##__VA_ARGS__); \
			if (n >= size) { \
				overflow = true; \
			} \
			else { \
				size -= n; \
				buf += n; \
			} \
		} \
	} while (0)


struct wifi_device {
	handle_t lock;
	handle_t cond;

	whd_ssid_t ssid;
	struct {
		uint8_t value[WSEC_MAX_PSK_LEN];
		uint8_t len;
	} key;


	bool busy;
	int len;
	char buf[128];
	cy_lwip_nw_interface_t iface;

	union {
		struct {
			handle_t tid;
			volatile uint8_t flags;
			uint32_t idleCurrent;
			uint32_t timeout;
			ip_static_addr_t addr;
		} apPriv;

		struct {
			handle_t tid;
			whd_scan_result_t scanResult;
		} staPriv;
	};
};


enum wifi_state {
	wifi_off,
	wifi_idle,
	wifi_running,
};


static struct {
	bool initialized;
	uint32_t msgport;
	handle_t msgtid;

	union {
		struct {
			struct wifi_device sta;
			struct wifi_device ap;
		};
		struct wifi_device dev[2];
	};

	struct {
		bool busy;
		uint32_t port;
		int len;
		char buf[16];
		handle_t lock;
		handle_t cond;
		handle_t tid;
	} ctrl;
} wifi_common = {
	.ap.apPriv.addr = {
		/* default AP address */
		.addr = IPADDR4_INIT_BYTES(192, 168, 2, 1),
		.netmask = IPADDR4_INIT_BYTES(255, 255, 255, 0),
		.gateway = IPADDR4_INIT_BYTES(192, 168, 2, 1),
	},
};


static const char *trim(const char *str, size_t *len)
{
	size_t sz = *len;
	while (sz > 0 && !isgraph(*str)) {
		str++;
		sz--;
	}

	while (sz > 0 && !isgraph(str[sz - 1])) {
		sz--;
	}

	*len = sz;

	return str;
}


static int wifi_ap_set_timeout(const char *data, size_t len)
{
	char buf[16];
	long int timeout;
	char *endp;

	if (len > (sizeof(buf) - 1)) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi timeout (max length is %u)\n", sizeof(buf) - 1);
		return -1;
	}

	memcpy(buf, data, len);
	buf[len] = '\0';

	errno = 0;
	timeout = strtol(buf, &endp, 0);
	if (errno != 0 || endp == buf) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi timeout (bad timeout value)\n");
		return -1;
	}
	else if (timeout < 0) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi timeout (min value is 0)\n");
		return -1;
	}
	else if (timeout > UINT32_MAX) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi timeout (max value is %u)\n", UINT32_MAX);
		return -1;
	}
	else {
		/* nothing */
	}

	mutexLock(wifi_common.ap.lock);
	wifi_common.ap.apPriv.timeout = timeout;
	mutexUnlock(wifi_common.ap.lock);

	return 0;
}


static int wifi_set_ssid(id_t id, const char *ssid, size_t len)
{
	if (len > SSID_NAME_SIZE) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi SSID (max length is %u)\n", SSID_NAME_SIZE);
		return -1;
	}

	mutexLock(wifi_common.dev[id].lock);
	memcpy(wifi_common.dev[id].ssid.value, ssid, len);
	wifi_common.dev[id].ssid.length = len;
	mutexUnlock(wifi_common.dev[id].lock);

	return 0;
}


static int wifi_set_key(id_t id, const char *key, size_t len)
{
	if (len < WSEC_MIN_PSK_LEN) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi key (min length is %u)\n", WSEC_MIN_PSK_LEN);
		return -1;
	}

	if (len > WSEC_MAX_PSK_LEN) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi key (max length is %u)\n", WSEC_MAX_PSK_LEN);
		return -1;
	}

	mutexLock(wifi_common.dev[id].lock);
	memcpy(wifi_common.dev[id].key.value, key, len);
	wifi_common.dev[id].key.len = len;
	mutexUnlock(wifi_common.dev[id].lock);

	return 0;
}


static void wifi_remove_interface(cy_lwip_nw_interface_t *interface)
{
	cy_lwip_network_down(interface);
	cy_lwip_remove_interface(interface);
}


static whd_result_t wifi_add_interface(cy_lwip_nw_interface_t *interface, ip_static_addr_t *addr)
{
	whd_result_t result;

	result = cy_lwip_add_interface(interface, addr);
	if (result != CY_RSLT_SUCCESS) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't add Wi-Fi interface\n");
		return result;
	}

	result = cy_lwip_network_up(interface);
	if (result != CY_RSLT_SUCCESS) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't bring up Wi-Fi interface\n");
		cy_lwip_remove_interface(interface);
		return result;
	}

	return WHD_SUCCESS;
}


static enum wifi_state wifi_get_state(struct wifi_device *dev)
{
	if (dev->iface.whd_iface == NULL) {
		return wifi_off;
	}

	if (dev == &wifi_common.ap) {
		uint8_t buf[sizeof(uint32_t) + 4 * sizeof(whd_mac_t)];
		whd_maclist_t *clients = (whd_maclist_t *)buf;
		whd_result_t result;

		memset(buf, 0, sizeof(buf));
		clients->count = 4;

		result = whd_wifi_get_associated_client_list(wifi_common.ap.iface.whd_iface, buf, sizeof(buf));
		if (result != WHD_SUCCESS || clients->count == 0) {
			return wifi_idle;
		}

		return wifi_running;
	}
	if (dev == &wifi_common.sta) {
		return whd_wifi_is_ready_to_transceive(wifi_common.sta.iface.whd_iface) != WHD_SUCCESS ? wifi_idle : wifi_running;
	}
	else {
		return wifi_idle;
	}
}


static void wifi_ap_main_loop(void)
{
	for (;;) {
		bool finish = false;
		bool updateIdle = false;
		bool checkIdle = false;
		unsigned int condTimeout = 0;

		mutexLock(wifi_common.ap.lock);

		if ((wifi_common.ap.apPriv.flags & WIFI_FLAG_FINISH) != 0) {
			finish = true;
		}

		if (wifi_common.ap.apPriv.timeout != 0) {
			if (wifi_common.ap.apPriv.idleCurrent < wifi_common.ap.apPriv.timeout) {
				updateIdle = true;
				condTimeout = 1;
			}
			else {
				checkIdle = true;
				condTimeout = 60;
			}
		}

		mutexUnlock(wifi_common.ap.lock);

		if (!finish && checkIdle) {
			if (wifi_get_state(&wifi_common.ap) == wifi_idle) {
				finish = true;
			}
		}

		if (finish) {
			break;
		}

		mutexLock(wifi_common.ap.lock);
		condWait(wifi_common.ap.cond, wifi_common.ap.lock, condTimeout * 1000000ULL);

		if (updateIdle) {
			wifi_common.ap.apPriv.idleCurrent += 1;
		}

		mutexUnlock(wifi_common.ap.lock);
	}
}


static void wifi_ap_thread(void *arg)
{
	(void)arg;
	bool started = false;
	bool ifaceAdded = false;
	cy_rslt_t result;

	do {
		whd_ssid_t ssid;
		uint8_t key[WSEC_MAX_PSK_LEN];
		uint8_t keyLen;

		mutexLock(wifi_common.ap.lock);
		ssid = wifi_common.ap.ssid;
		memcpy(key, wifi_common.ap.key.value, sizeof(key));
		keyLen = wifi_common.ap.key.len;
		mutexUnlock(wifi_common.ap.lock);

		result = whd_wifi_init_ap(wifi_common.ap.iface.whd_iface, &ssid, AP_SECURITY_MODE, key, keyLen, AP_CHANNEL);
		if (result != WHD_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't init Wi-Fi AP\n");
			break;
		}

		result = whd_wifi_start_ap(wifi_common.ap.iface.whd_iface);
		if (result != WHD_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't start Wi-Fi AP\n");
			break;
		}
		started = true;

		result = wifi_add_interface(&wifi_common.ap.iface, &wifi_common.ap.apPriv.addr);
		if (result != WHD_SUCCESS) {
			break;
		}
		ifaceAdded = true;
	} while (0);

	mutexLock(wifi_common.ap.lock);
	wifi_common.ap.apPriv.flags |= (result == WHD_SUCCESS) ? WIFI_FLAG_STARTED : WIFI_FLAG_FAILED;
	condSignal(wifi_common.ap.cond);
	mutexUnlock(wifi_common.ap.lock);

	if (result == WHD_SUCCESS) {
		wifi_ap_main_loop();
	}

	if (started) {
		whd_wifi_stop_ap(wifi_common.ap.iface.whd_iface);
	}

	if (ifaceAdded) {
		wifi_remove_interface(&wifi_common.ap.iface);
	}

	wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, "AP: stopped\n");

	mutexLock(wifi_common.ap.lock);
	wifi_common.ap.apPriv.tid = 0;
	mutexUnlock(wifi_common.ap.lock);
}


static void wifi_scan_result_cb(whd_scan_result_t **result_ptr, void *user_data, whd_scan_status_t status)
{
	switch (status) {
		case WHD_SCAN_ABORTED:
			return;

		case WHD_SCAN_COMPLETED_SUCCESSFULLY:
			break;

		case WHD_SCAN_INCOMPLETE: {
			if ((*result_ptr)->SSID.length != 0) {
				whd_ssid_t *ssid = user_data;
				if ((*result_ptr)->SSID.length != ssid->length || memcmp((*result_ptr)->SSID.value, ssid->value, ssid->length) != 0) {
					return;
				}
			}
			break;
		}

		default:
			return;
	}

	mutexLock(wifi_common.sta.lock);
	condSignal(wifi_common.sta.cond);
	if (result_ptr != NULL) {
		/* set to NULL to signal to WHD that we got what we wanted */
		*result_ptr = NULL;
	}
	mutexUnlock(wifi_common.sta.lock);
}


static int wifi_sta_connect(void)
{
	whd_result_t result;
	whd_ssid_t ssid;
	uint8_t key[WSEC_MAX_PSK_LEN];
	uint8_t keyLen;
	time_t left;
	bool wifiJoined = false;
	bool ifaceAdded = false;
	struct timespec tp;
	time_t when, now;

	if (wifi_get_state(&wifi_common.sta) == wifi_running) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "STA is already connected\n");
		return -1;
	}

	mutexLock(wifi_common.sta.lock);

	ssid = wifi_common.sta.ssid;
	memcpy(key, wifi_common.sta.key.value, sizeof(key));
	keyLen = wifi_common.sta.key.len;

	mutexUnlock(wifi_common.sta.lock);

	left = WIFI_STA_SCAN_TIMEOUT_SECONDS;

	do {
		result = whd_wifi_set_ioctl_value(wifi_common.sta.iface.whd_iface, WLC_SET_BAND, WLC_BAND_AUTO);
		if (result != WHD_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "couldn't set auto band on interface\n");
			break;
		}

		if (clock_gettime(CLOCK_MONOTONIC, &tp) < 0) {
			result = WHD_SCAN_ABORTED;
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "couldn't get current time: %s (%d)\n", strerror(errno), errno);
			break;
		}
		now = tp.tv_sec;
		when = now + WIFI_STA_SCAN_TIMEOUT_SECONDS;

		mutexLock(wifi_common.sta.lock);
		memset(&wifi_common.sta.staPriv.scanResult, 0, sizeof(wifi_common.sta.staPriv.scanResult));
		wifi_common.sta.staPriv.scanResult.security = WHD_SECURITY_UNKNOWN;
		do {
			left = when - now;
			if (left <= 0) {
				result = WHD_SCAN_ABORTED;
				break;
			}
			result = whd_wifi_scan(wifi_common.sta.iface.whd_iface, STA_SCAN_TYPE, STA_BSS_TYPE,
					&ssid, NULL, NULL, NULL, wifi_scan_result_cb, &wifi_common.sta.staPriv.scanResult, &ssid);
			condWait(wifi_common.sta.cond, wifi_common.sta.lock, min((WIFI_STA_SCAN_TIMEOUT_SECONDS * 1000000ULL) / WIFI_STA_N_SCANS, left * 1000000ULL));

			(void)whd_wifi_stop_scan(wifi_common.sta.iface.whd_iface);

			if (clock_gettime(CLOCK_MONOTONIC, &tp) < 0) {
				result = WHD_SCAN_ABORTED;
				wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "couldn't get current time: %s (%d)\n", strerror(errno), errno);
				break;
			}
			now = tp.tv_sec;
			if (now >= when) {
				result = WHD_SCAN_ABORTED;
				break;
			}
		} while (result == WHD_SUCCESS && wifi_common.sta.staPriv.scanResult.security == WHD_SECURITY_UNKNOWN);

		if (result != WHD_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't get network's security\n");
			mutexUnlock(wifi_common.sta.lock);
			break;
		}

		result = whd_wifi_join_specific(wifi_common.sta.iface.whd_iface, &wifi_common.sta.staPriv.scanResult, key, keyLen);
		if (result != WHD_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't join requested network\n");
			mutexUnlock(wifi_common.sta.lock);
			break;
		}
		mutexUnlock(wifi_common.sta.lock);
		wifiJoined = true;

		result = wifi_add_interface(&wifi_common.sta.iface, NULL);
		if (result != WHD_SUCCESS) {
			break;
		}
		ifaceAdded = true;
	} while (0);

	if (result != WHD_SUCCESS) {
		if (ifaceAdded) {
			wifi_remove_interface(&wifi_common.sta.iface);
		}
		if (wifiJoined) {
			whd_wifi_leave(wifi_common.sta.iface.whd_iface);
		}
		return -1;
	}

	return 0;
}


static void wifi_sta_disconnect(void)
{
	if (wifi_get_state(&wifi_common.sta) != wifi_running) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "STA is not connected\n");
		return;
	}
	wifi_remove_interface(&wifi_common.sta.iface);
	whd_wifi_leave(wifi_common.sta.iface.whd_iface);
}


static int wifi_ap_start(void)
{
	uint8_t flags;

	mutexLock(wifi_common.ap.lock);

	/* reset idle timeout in any case */
	wifi_common.ap.apPriv.idleCurrent = 0;

	if (wifi_common.ap.apPriv.tid != 0) {
		mutexUnlock(wifi_common.ap.lock);
		return 0;
	}

	wifi_common.ap.apPriv.flags = 0;

	if (sys_thread_opt_new("wifi-ap", wifi_ap_thread, NULL, WIFI_THREAD_STACKSZ, WIFI_THREAD_PRIO, &wifi_common.ap.apPriv.tid) < 0) {
		mutexUnlock(wifi_common.ap.lock);
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create AP thread\n");
		return -1;
	}

	while (wifi_common.ap.apPriv.flags == 0) {
		condWait(wifi_common.ap.cond, wifi_common.ap.lock, 0);
	}

	flags = wifi_common.ap.apPriv.flags;

	mutexUnlock(wifi_common.ap.lock);

	return ((flags & WIFI_FLAG_STARTED) != 0) ? 0 : -1;
}


static void wifi_ap_stop(void)
{
	handle_t tid;

	mutexLock(wifi_common.ap.lock);

	if (wifi_common.ap.apPriv.tid == 0) {
		mutexUnlock(wifi_common.ap.lock);
		return;
	}

	tid = wifi_common.ap.apPriv.tid;
	wifi_common.ap.apPriv.flags |= WIFI_FLAG_FINISH;
	condSignal(wifi_common.ap.cond);

	mutexUnlock(wifi_common.ap.lock);

	sys_thread_join(tid);
}


static int wifi_sta_get_connected(whd_ssid_t *ssid)
{
	whd_bss_info_t info;
	__attribute__((unused)) whd_security_t security;
	whd_result_t result = whd_wifi_get_ap_info(wifi_common.sta.iface.whd_iface, &info, &security);
	if (result != WHD_SUCCESS) {
		return -1;
	}

	if (ssid != NULL) {
		memcpy(ssid->value, info.SSID, sizeof(ssid->value));
		ssid->length = info.SSID_len;
	}

	return 0;
}


static int wifi_dev_open(id_t id, int flags)
{
	char *buf;
	size_t size;
	bool overflow = false;

	if (wifi_common.dev[id].busy) {
		return -EBUSY;
	}

	buf = wifi_common.dev[id].buf;
	size = sizeof(wifi_common.dev[id].buf);

	mutexLock(wifi_common.dev[id].lock);

	if (id == STA_DEV_ID) {
		SNPRINTF_APPEND(overflow, buf, size, "ssid=%.*s\n", wifi_common.sta.ssid.length, wifi_common.sta.ssid.value);
		enum wifi_state state = wifi_get_state(&wifi_common.sta);
		if (state == wifi_running) {
			whd_ssid_t ssid;
			if (wifi_sta_get_connected(&ssid) < 0) {
				wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Failed to get SSID of connected network\n");
			}
			else {
				SNPRINTF_APPEND(overflow, buf, size, "current=%.*s\n", ssid.length, ssid.value);
			}
		}
		SNPRINTF_APPEND(overflow, buf, size, "running=%u\n", state == wifi_running ? 1U : 0U);
	}
	else if (id == AP_DEV_ID) {
		SNPRINTF_APPEND(overflow, buf, size, "timeout=%u\n", wifi_common.ap.apPriv.timeout);
		SNPRINTF_APPEND(overflow, buf, size, "ssid=%.*s\n", wifi_common.ap.ssid.length, wifi_common.ap.ssid.value);
		SNPRINTF_APPEND(overflow, buf, size, "running=%u\n", wifi_common.ap.apPriv.tid != 0);
	}
	else {
		/* nothing */
	}


	mutexUnlock(wifi_common.dev[id].lock);

	if (overflow) {
		return -EFBIG;
	}

	wifi_common.dev[id].busy = true;
	wifi_common.dev[id].len = buf - wifi_common.dev[id].buf;

	return 0;
}


static int wifi_dev_close(id_t id)
{
	if (!wifi_common.dev[id].busy) {
		return -EBADF;
	}
	wifi_common.dev[id].busy = false;
	return 0;
}


static int wifi_dev_read(id_t id, char *data, size_t size, off_t offset)
{
	int cnt;

	if (offset > wifi_common.dev[id].len) {
		return -ERANGE;
	}

	cnt = min(size, wifi_common.dev[id].len - offset);
	memcpy(data, wifi_common.dev[id].buf + offset, cnt);

	return cnt;
}


static int wifi_dev_write(id_t id, const char *data, size_t size)
{
	const size_t inputSize = size;
	data = trim(data, &size);

	if (size >= CONST_STRLEN("ssid ") && strncmp("ssid ", data, 5) == 0) {
		wifi_set_ssid(id, data + 5, size - 5);
	}
	else if (size >= CONST_STRLEN("key ") && strncmp("key ", data, 4) == 0) {
		wifi_set_key(id, data + 4, size - 4);
	}
	else if (id == STA_DEV_ID && size == CONST_STRLEN("connect") && strncmp("connect", data, size) == 0) {
		wifi_sta_connect();
	}
	else if (id == STA_DEV_ID && size == CONST_STRLEN("disconnect") && strncmp("disconnect", data, size) == 0) {
		wifi_sta_disconnect();
	}
	else if (id == AP_DEV_ID && size >= CONST_STRLEN("timeout ") && strncmp("timeout ", data, 8) == 0) {
		wifi_ap_set_timeout(data + 8, size - 8);
	}
	else if (id == AP_DEV_ID && size == CONST_STRLEN("start") && strncmp("start", data, size) == 0) {
		wifi_ap_start();
	}
	else if (id == AP_DEV_ID && size == CONST_STRLEN("stop") && strncmp("stop", data, size) == 0) {
		wifi_ap_stop();
	}
	else {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "got unknown Wi-Fi command: %.*s\n", (int)size, data);
		return -EINVAL;
	}

	return inputSize;
}


static int wifi_dev_init(unsigned int port, id_t id, const char *path)
{
	oid_t wifi_oid = { port, id };

	return create_dev(&wifi_oid, path);
}


static void wifi_msg_thread(void *arg)
{
	for (;;) {
		msg_t msg = { 0 };
		msg_rid_t rid;

		if (msgRecv(wifi_common.msgport, &msg, &rid) < 0) {
			/* should signalize that our port was closed */
			wifi_common.msgport = 0;
			break;
		}

		if ((msg.oid.id != STA_DEV_ID && msg.oid.id != AP_DEV_ID) || !wifi_common.initialized) {
			msg.o.err = -ENODEV;
			msgRespond(wifi_common.msgport, &msg, rid);
			continue;
		}

		switch (msg.type) {
			case mtOpen:
				msg.o.err = wifi_dev_open(msg.oid.id, msg.i.openclose.flags);
				break;

			case mtClose:
				msg.o.err = wifi_dev_close(msg.oid.id);
				break;

			case mtRead:
				msg.o.err = wifi_dev_read(msg.oid.id, msg.o.data, msg.o.size, msg.i.io.offs);
				break;

			case mtWrite:
				msg.o.err = wifi_dev_write(msg.oid.id, msg.i.data, msg.i.size);
				break;

			default:
				msg.o.err = -EOPNOTSUPP;
				break;
		}

		(void)msgRespond(wifi_common.msgport, &msg, rid);
	}
}


static int wifi_init_interfaces(void)
{
	cy_rslt_t result;

	result = cybsp_init();
	if (result != CY_RSLT_SUCCESS) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't init Wi-Fi HW\n");
		return -1;
	}

	/* STA */
	result = cybsp_wifi_init_primary(&wifi_common.sta.iface.whd_iface);
	if (result != CY_RSLT_SUCCESS) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't init Wi-Fi primary interface (STA)\n");
		cybsp_free();
		wifi_common.sta.iface.whd_iface = NULL;
		return -1;
	}

	wifi_common.sta.iface.role = CY_LWIP_STA_NW_INTERFACE;

	/* AP */
	result = cybsp_wifi_init_secondary(&wifi_common.ap.iface.whd_iface, NULL);
	if (result != CY_RSLT_SUCCESS) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't init Wi-Fi secondary interface (AP)\n");
		cybsp_wifi_deinit(wifi_common.sta.iface.whd_iface);
		cybsp_free();
		wifi_common.sta.iface.whd_iface = NULL;
		wifi_common.ap.iface.whd_iface = NULL;
		return -1;
	}

	wifi_common.ap.iface.role = CY_LWIP_AP_NW_INTERFACE;

	return 0;
}


static void wifi_deinit_interfaces(void)
{
	handle_t tid;

	mutexLock(wifi_common.ap.lock);
	tid = wifi_common.ap.apPriv.tid;
	mutexUnlock(wifi_common.ap.lock);

	if (tid != 0) {
		wifi_ap_stop();
	}

	/* checks internally if STA is connected */
	wifi_sta_disconnect();

	/* cybsp_wifi_deinit() deinitializes both interfaces - only needs the
	  interface pointer to get the driver pointer, so it needs to be
	  called only once on any of the interfaces */
	if (wifi_common.sta.iface.whd_iface != NULL) {
		cybsp_wifi_deinit(wifi_common.sta.iface.whd_iface);
		cybsp_free();
	}
	else if (wifi_common.ap.iface.whd_iface != NULL) {
		cybsp_wifi_deinit(wifi_common.ap.iface.whd_iface);
		cybsp_free();
	}
	else {
		/* nothing */
	}
	wifi_common.sta.iface.whd_iface = NULL;
	wifi_common.ap.iface.whd_iface = NULL;
}


static void _wifi_deinit(void)
{
	destroy_dev(AP_DEV_NAME);
	destroy_dev(STA_DEV_NAME);

	if (wifi_common.msgport != (uint32_t)-1) {
		portDestroy(wifi_common.msgport);
		wifi_common.msgport = (uint32_t)-1;
		/* only wait for thread if we can signalize for it to close with portDestroy */
		if (wifi_common.msgtid != 0) {
			sys_thread_join(wifi_common.msgtid);
			wifi_common.msgtid = 0;
		}
	}

	wifi_deinit_interfaces();
	if (wifi_common.sta.lock != -1) {
		resourceDestroy(wifi_common.sta.lock);
		wifi_common.sta.lock = -1;
	}
	if (wifi_common.sta.cond != -1) {
		resourceDestroy(wifi_common.sta.cond);
		wifi_common.sta.cond = -1;
	}
	if (wifi_common.ap.lock != -1) {
		resourceDestroy(wifi_common.ap.lock);
		wifi_common.ap.lock = -1;
	}
	if (wifi_common.ap.cond != -1) {
		resourceDestroy(wifi_common.ap.cond);
		wifi_common.ap.cond = -1;
	}
	wifi_common.initialized = false;
}


static void wifi_deinit(void)
{
	mutexLock(wifi_common.ctrl.lock);
	if (!wifi_common.initialized) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Wi-Fi is not up\n");
	}
	else {
		_wifi_deinit();
	}
	mutexUnlock(wifi_common.ctrl.lock);
}


static int _wifi_init(void)
{
	int err;

	wifi_common.msgport = (uint32_t)-1;
	wifi_common.msgtid = 0;
	wifi_common.sta.lock = -1;
	wifi_common.sta.cond = -1;
	wifi_common.ap.lock = -1;
	wifi_common.ap.cond = -1;

	do {
		err = portCreate(&wifi_common.msgport);
		if (err < 0) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create Wi-Fi port\n");
			break;
		}

		err = mutexCreate(&wifi_common.sta.lock);
		if (err < 0) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create STA lock\n");
			break;
		}

		err = condCreate(&wifi_common.sta.cond);
		if (err < 0) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create STA cond\n");
			break;
		}

		err = mutexCreate(&wifi_common.ap.lock);
		if (err < 0) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create AP lock\n");
			break;
		}

		err = condCreate(&wifi_common.ap.cond);
		if (err < 0) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create AP cond\n");
			break;
		}

		err = wifi_init_interfaces();
		if (err < 0) {
			break;
		}

		err = wifi_dev_init(wifi_common.msgport, STA_DEV_ID, STA_DEV_NAME);
		if (err < 0) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create Wi-Fi STA device\n");
			break;
		}

		err = wifi_dev_init(wifi_common.msgport, AP_DEV_ID, AP_DEV_NAME);
		if (err < 0) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create Wi-Fi AP device\n");
			break;
		}

		/* keep this as the last thing here so that we don't have to deinitialize it on error */
		err = sys_thread_opt_new("wifi-msg", wifi_msg_thread, NULL, WIFI_THREAD_STACKSZ, WIFI_THREAD_PRIO, &wifi_common.msgtid);
		if (err < 0) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create Wi-Fi msgthread\n");
			break;
		}
	} while (0);

	if (err < 0) {
		_wifi_deinit();
	}
	else {
		wifi_common.initialized = true;
	}

	return err;
}


static int wifi_init(void)
{
	int err;

	mutexLock(wifi_common.ctrl.lock);
	if (wifi_common.initialized) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Wi-Fi is already initialized\n");
		err = -1;
	}
	else {
		err = _wifi_init();
	}
	mutexUnlock(wifi_common.ctrl.lock);

	if (err < 0) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "failed to initialize Wi-Fi\n");
	}

	return err;
}


static void wifi_ctrl_thread(void *arg)
{
	msg_t msg;
	msg_rid_t rid;

	int err = mutexCreate(&wifi_common.ctrl.lock);
	if (err < 0) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "could not create ctrl lock\n");
		return;
	}

	err = condCreate(&wifi_common.ctrl.cond);
	if (err < 0) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "could not create ctrl cond\n");
		resourceDestroy(wifi_common.ctrl.lock);
		return;
	}

	err = portCreate(&wifi_common.ctrl.port);
	if (err < 0) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "could not create ctrl port\n");
		resourceDestroy(wifi_common.ctrl.lock);
		resourceDestroy(wifi_common.ctrl.cond);
		return;
	}

	if (wifi_dev_init(wifi_common.ctrl.port, CTRL_DEV_ID, CTRL_DEV_NAME) < 0) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create Wi-Fi ctrl device\n");
		resourceDestroy(wifi_common.ctrl.lock);
		resourceDestroy(wifi_common.ctrl.cond);
		portDestroy(wifi_common.ctrl.port);
		return;
	}

	for (;;) {
		if (msgRecv(wifi_common.ctrl.port, &msg, &rid) < 0) {
			continue;
		}

		switch (msg.type) {
			case mtOpen: {
				if (wifi_common.ctrl.busy) {
					msg.o.err = -EBUSY;
					break;
				}

				mutexLock(wifi_common.ctrl.lock);
				bool running = wifi_common.initialized;
				mutexUnlock(wifi_common.ctrl.lock);

				int bytes = snprintf(wifi_common.ctrl.buf, sizeof(wifi_common.ctrl.buf), "running=%d\n", running ? 1 : 0);
				wifi_common.ctrl.len = bytes;
				wifi_common.ctrl.busy = true;
				msg.o.err = EOK;
				break;
			}

			case mtClose:
				wifi_common.ctrl.busy = false;
				msg.o.err = EOK;
				break;

			case mtRead: {
				off_t offset = msg.i.io.offs;
				if (offset > wifi_common.ctrl.len) {
					msg.o.err = -ERANGE;
					break;
				}

				int cnt = min(msg.o.size, wifi_common.ctrl.len - offset);

				memcpy(msg.o.data, wifi_common.ctrl.buf + offset, cnt);
				msg.o.err = cnt;
				break;
			}

			case mtWrite: {
				const char *data = msg.i.data;
				size_t size = msg.i.size;

				data = trim(data, &size);

				if (size == CONST_STRLEN("on") && strncmp("on", data, size) == 0) {
					wifi_init();
				}
				else if (size == CONST_STRLEN("off") && strncmp("off", data, size) == 0) {
					wifi_deinit();
				}
				else {
					wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "got unknown Wi-Fi command: %.*s\n", (int)size, data);
					msg.o.err = -EINVAL;
					break;
				}
				msg.o.err = msg.i.size;
				break;
			}

			default:
				msg.o.err = -EOPNOTSUPP;
				break;
		}

		(void)msgRespond(wifi_common.ctrl.port, &msg, rid);
	}
}


__constructor__(1000) void init_wifi(void)
{
	int err;

	if (cy_log_init(CY_LOG_INFO) != CY_RSLT_SUCCESS) {
		errout(-ENOSYS, "can't init Wi-Fi logs\n");
	}

	err = sys_thread_opt_new("wifi-ctrl", wifi_ctrl_thread, NULL, WIFI_THREAD_STACKSZ, WIFI_THREAD_PRIO, NULL);
	if (err < 0) {
		cy_log_shutdown();
		errout(err, "thread(wifi-msg)");
	}
}
