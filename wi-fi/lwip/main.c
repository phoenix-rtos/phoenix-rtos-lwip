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

#include <ctype.h>
#include <string.h>
#include <sys/minmax.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <posix/utils.h>

#include "bus_protocols/whd_bus_protocol_interface.h"
#include "whd_wifi_api.h"
#include "whd_wlioctl.h"
#include "cybsp.h"
#include "cybsp_wifi.h"
#include "cy_lwip.h"
#include "cy_lwip_log.h"
#include "cy_log.h"

#include "netif.h"
#include "lwipopts.h"
#include "lwip/sys.h"

#ifndef WIFI_CONCURRENT_MODE_ENABLED
#define WIFI_CONCURRENT_MODE_ENABLED 1
#endif

#define WIFI_THREAD_PRIO    4
#define WIFI_THREAD_STACKSZ 4096

#define WIFI_FLAG_STARTED (1U << 0)
#define WIFI_FLAG_FAILED  (1U << 1)
#define WIFI_FLAG_FINISH  (1U << 2)

#define STA_DEV_ID               0
#define STA_DEV_NAME             "/dev/wifi/sta"
#define STA_SCAN_TYPE            WHD_SCAN_TYPE_ACTIVE
#define STA_BSS_TYPE             WHD_BSS_TYPE_ANY
#define STA_N_SCANS              5
#define STA_SCAN_TIMEOUT_SECONDS 10

#define AP_DEV_ID        1
#define AP_DEV_NAME      "/dev/wifi/ap"
#define AP_START_RETRIES 5
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
	handle_t tid;

	uint32_t idleCurrent;

	uint32_t timeout;
	whd_ssid_t ssid;
	struct {
		uint8_t value[WSEC_MAX_PSK_LEN];
		uint8_t len;
	} key;

	volatile uint8_t flags;

	bool busy;
	int len;
	char buf[128];
	cy_lwip_nw_interface_t iface;
};


enum wifi_state {
	wifi_busFailed = -1,
	wifi_idle = 0,
	wifi_running = 1,
};


static struct {
	bool initialized;

	union {
		struct {
			struct wifi_device sta;
			struct wifi_device ap;
		};
		struct wifi_device dev[2];
	};

	struct {
		bool busy;
		int len;
		char buf[16];
	} ctrl;
} wifi_common;

static ip_static_addr_t ap_addr = {
	.addr = IPADDR4_INIT_BYTES(192, 168, 2, 1),
	.netmask = IPADDR4_INIT_BYTES(255, 255, 255, 0),
	.gateway = IPADDR4_INIT_BYTES(192, 168, 2, 1)
};

static whd_scan_result_t scanResult;


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


static int wifi_set_timeout(id_t id, const char *data, size_t len)
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

	mutexLock(wifi_common.dev[id].lock);
	wifi_common.dev[id].timeout = timeout;
	mutexUnlock(wifi_common.dev[id].lock);

	return 0;
}


static int wifi_set_ssid(id_t id, const char *ssid, size_t len)
{
	ssid = trim(ssid, &len);

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
	key = trim(key, &len);

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


static int wifi_add_interface(cy_lwip_nw_interface_t *interface, ip_static_addr_t *addr)
{
	whd_result_t result;

	result = cy_lwip_add_interface(interface, addr);
	if (result != CY_RSLT_SUCCESS) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't add Wi-Fi interface\n");
		return -1;
	}

	result = cy_lwip_network_up(interface);
	if (result != CY_RSLT_SUCCESS) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't bring up Wi-Fi interface\n");
		cy_lwip_remove_interface(interface);
		return -1;
	}

	return 0;
}


static bool wifi_ap_state(void)
{
	uint8_t buf[sizeof(uint32_t) + 4 * sizeof(whd_mac_t)];
	whd_maclist_t *clients = (whd_maclist_t *)buf;
	whd_result_t result;

	memset(buf, 0, sizeof(buf));
	clients->count = 4;

	result = whd_wifi_get_associated_client_list(wifi_common.ap.iface.whd_iface, buf, sizeof(buf));
	if (result != WHD_SUCCESS) {
		return wifi_busFailed;
	}
	if (clients->count == 0) {
		return wifi_idle;
	}

	return wifi_running;
}


static bool wifi_sta_state(whd_ssid_t *ssid)
{
	if (wifi_common.sta.iface.whd_iface == NULL) {
		return wifi_busFailed;
	}

	if (whd_wifi_is_ready_to_transceive(wifi_common.sta.iface.whd_iface) != WHD_SUCCESS) {
		return wifi_busFailed;
	}

	whd_bss_info_t apInfo;
	whd_security_t security;
	whd_result_t result = whd_wifi_get_ap_info(wifi_common.sta.iface.whd_iface, &apInfo, &security);
	if (result != WHD_SUCCESS) {
		return wifi_idle;
	}

	if (ssid != NULL) {
		memcpy(ssid->value, apInfo.SSID, sizeof(ssid->value));
		ssid->length = apInfo.SSID_len;
	}
	return wifi_running;
}


static enum wifi_state wifi_get_state(struct wifi_device *dev)
{
	whd_mac_t mac;
	if (whd_wifi_get_mac_address(dev->iface.whd_iface, &mac) == WHD_BUS_FAIL) {
		/* whd has exit, so we signal exit too */
		return wifi_busFailed;
	}

	if (dev == &wifi_common.ap) {
		return wifi_ap_state();
	}
	else if (dev == &wifi_common.sta) {
		return wifi_sta_state(NULL);
	}
	else {
		return wifi_busFailed;
	}
}


static void wifi_main_loop(struct wifi_device *dev)
{
	for (;;) {
		bool finish = false;
		bool updateIdle = false;
		bool checkIdle = false;
		unsigned int condTimeout = 0;

		mutexLock(dev->lock);

		if ((dev->flags & WIFI_FLAG_FINISH) != 0) {
			finish = true;
		}

		if (dev->timeout != 0) {
			if (dev->idleCurrent < dev->timeout) {
				updateIdle = true;
				condTimeout = 1;
			}
			else {
				checkIdle = true;
				condTimeout = 60;
			}
		}

		mutexUnlock(dev->lock);

		if (!finish && checkIdle) {
			enum wifi_state state = wifi_get_state(dev);
			if (state == wifi_busFailed || state == wifi_idle) {
				finish = true;
			}
		}

		if (finish) {
			break;
		}

		mutexLock(dev->lock);
		condWait(dev->cond, dev->lock, condTimeout * 1000000ULL);

		if (updateIdle) {
			dev->idleCurrent += 1;
		}

		mutexUnlock(dev->lock);
	}
}


static void wifi_ap_thread(void *arg)
{
	(void)arg;
	bool started = false;

	do {
		cy_rslt_t result;
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

		if (wifi_add_interface(&wifi_common.ap.iface, &ap_addr) < 0) {
			break;
		}

		started = true;
	} while (0);

	mutexLock(wifi_common.ap.lock);
	wifi_common.ap.flags |= started ? WIFI_FLAG_STARTED : WIFI_FLAG_FAILED;
	condSignal(wifi_common.ap.cond);
	mutexUnlock(wifi_common.ap.lock);

	if (started) {
		wifi_main_loop(&wifi_common.ap);
	}

	whd_wifi_stop_ap(wifi_common.ap.iface.whd_iface);
	wifi_remove_interface(&wifi_common.ap.iface);

	wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, "AP: stopped\n");

	mutexLock(wifi_common.ap.lock);
	wifi_common.ap.tid = 0;
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
				if (memcmp((*result_ptr)->SSID.value, ssid->value, ssid->length) != 0) {
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
		*result_ptr = NULL;
	}
	mutexUnlock(wifi_common.sta.lock);
}


static void wifi_sta_thread(void *arg)
{
	(void)arg;
	whd_result_t result;
	whd_ssid_t ssid, connectedTo;
	uint8_t key[WSEC_MAX_PSK_LEN];
	uint8_t keyLen;
	time_t when, now, left;
	bool wifiJoined = false;
	bool ifaceAdded = false;
	struct timespec tp;

	mutexLock(wifi_common.sta.lock);

	ssid = wifi_common.sta.ssid;
	memcpy(key, wifi_common.sta.key.value, sizeof(key));
	keyLen = wifi_common.sta.key.len;

	mutexUnlock(wifi_common.sta.lock);

	left = STA_SCAN_TIMEOUT_SECONDS;

	do {
		enum wifi_state state = wifi_sta_state(&connectedTo);
		if (state == wifi_running) {
			if (memcmp(&connectedTo, &ssid, sizeof(ssid)) == 0) {
				wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, "already connected to this network\n");
				result = WHD_SUCCESS;
				break;
			}
			else {
				result = whd_wifi_leave(wifi_common.sta.iface.whd_iface);
				if (result != WHD_SUCCESS) {
					wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "error leaving network\n");
					break;
				}
			}
		}
		else if (state == wifi_busFailed) {
			result = WHD_BUS_FAIL;
			break;
		}
		else {
			/* Nothing to do */
		}

		result = whd_wifi_set_ioctl_value(wifi_common.sta.iface.whd_iface, WLC_SET_BAND, WLC_BAND_AUTO);
		if (result != WHD_SUCCESS) {
			break;
		}

#if STA_SCAN_TIMEOUT_SECONDS != 0
		if (clock_gettime(CLOCK_MONOTONIC, &tp) < 0) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "couldn't get current time: %s (%d)", strerror(errno), errno);
			break;
		}
		now = tp.tv_sec;
		when = now + STA_SCAN_TIMEOUT_SECONDS;
#endif
		scanResult.security = WHD_SECURITY_UNKNOWN;

		mutexLock(wifi_common.sta.lock);
		do {
			result = whd_wifi_scan(wifi_common.sta.iface.whd_iface, STA_SCAN_TYPE, STA_BSS_TYPE,
					&ssid, NULL, NULL, NULL, wifi_scan_result_cb, &scanResult, &ssid);
			condWait(wifi_common.sta.cond, wifi_common.sta.lock, min((STA_SCAN_TIMEOUT_SECONDS * 1000000ULL) / STA_N_SCANS, left * 1000000ULL));

			(void)whd_wifi_stop_scan(wifi_common.sta.iface.whd_iface);

#if STA_SCAN_TIMEOUT_SECONDS != 0
			if (clock_gettime(CLOCK_MONOTONIC, &tp) < 0) {
				wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "couldn't get current time: %s (%d)", strerror(errno), errno);
				break;
			}
			now = tp.tv_sec;
			if (now >= when) {
				result = WHD_SCAN_ABORTED;
				break;
			}
			left = when - now;
#endif
		} while (result == WHD_SUCCESS && scanResult.security == WHD_SECURITY_UNKNOWN);
		mutexUnlock(wifi_common.sta.lock);

		if (result != WHD_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't get network's security\n");
			break;
		}

		result = whd_wifi_join_specific(wifi_common.sta.iface.whd_iface, &scanResult, key, keyLen);
		if (result != WHD_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't join requested network\n");
			break;
		}
		wifiJoined = true;

		if (wifi_add_interface(&wifi_common.sta.iface, NULL) < 0) {
			result = WHD_INTERFACE_NOT_UP;
			break;
		}
		ifaceAdded = true;
	} while (0);

	mutexLock(wifi_common.sta.lock);
	wifi_common.sta.flags = (result == WHD_SUCCESS) ? WIFI_FLAG_STARTED : WIFI_FLAG_FAILED;
	condSignal(wifi_common.sta.cond);
	mutexUnlock(wifi_common.sta.lock);

	if (result == WHD_SUCCESS) {
		wifi_main_loop(&wifi_common.sta);
	}

	if (ifaceAdded) {
		wifi_remove_interface(&wifi_common.sta.iface);
	}
	if (wifiJoined) {
		whd_wifi_leave(wifi_common.sta.iface.whd_iface);
	}

	wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, "STA: disconnected\n");

	mutexLock(wifi_common.sta.lock);
	wifi_common.sta.tid = 0;
	mutexUnlock(wifi_common.sta.lock);
}


static int wifi_dev_start(struct wifi_device *dev)
{
	void (*thread)(void *);
	const char *threadName;
	struct wifi_device *other;
	uint8_t flags;

	if (dev == &wifi_common.ap) {
		thread = wifi_ap_thread;
		threadName = "wifi-ap";
		other = &wifi_common.sta;
	}
	else if (dev == &wifi_common.sta) {
		thread = wifi_sta_thread;
		threadName = "wifi-sta";
		other = &wifi_common.ap;
	}
	else {
		return -1;
	}

#if !WIFI_CONCURRENT_MODE_ENABLED
	if (other->tid != 0) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't enable %s: concurrent mode is disabled", threadName);
		return -1;
	}
#else
	(void)other;
#endif

	mutexLock(dev->lock);

	/* reset idle timeout in any case */
	dev->idleCurrent = 0;

	if (dev->tid != 0) {
		mutexUnlock(dev->lock);
		return 0;
	}

	dev->flags = 0;

	if (sys_thread_opt_new(threadName, thread, dev, WIFI_THREAD_STACKSZ, WIFI_THREAD_PRIO, &dev->tid) < 0) {
		mutexUnlock(dev->lock);
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create %s thread\n", threadName);
		return -1;
	}

	while (dev->flags == 0) {
		condWait(dev->cond, dev->lock, 0);
	}

	flags = dev->flags;

	mutexUnlock(dev->lock);

	return ((flags & WIFI_FLAG_STARTED) != 0) ? 0 : -1;
}


static void wifi_dev_stop(struct wifi_device *dev)
{
	handle_t tid;

	mutexLock(dev->lock);

	if (dev->tid == 0) {
		mutexUnlock(dev->lock);
		return;
	}

	tid = dev->tid;
	dev->flags |= WIFI_FLAG_FINISH;
	condSignal(dev->cond);

	mutexUnlock(dev->lock);

	sys_thread_join(tid);
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

	SNPRINTF_APPEND(overflow, buf, size, "timeout=%u\n", wifi_common.dev[id].timeout);
	if (id == STA_DEV_ID) {
		SNPRINTF_APPEND(overflow, buf, size, "ssid=%.*s\n", wifi_common.sta.ssid.length, wifi_common.sta.ssid.value);
		whd_ssid_t ssid;
		enum wifi_state state = wifi_sta_state(&ssid);
		if (state == wifi_running) {
			SNPRINTF_APPEND(overflow, buf, size, "connected_to=%.*s\n", ssid.length, ssid.value);
		}
	}
	else if (id == AP_DEV_ID) {
		SNPRINTF_APPEND(overflow, buf, size, "ssid=%.*s\n", wifi_common.ap.ssid.length, wifi_common.ap.ssid.value);
		SNPRINTF_APPEND(overflow, buf, size, "running=%u\n", wifi_common.ap.tid != 0);
	}
	else {
		/* nothing */
	}
	if (wifi_common.dev[id].tid != 0) {
		struct netif *netif = cy_lwip_get_interface(wifi_common.dev[id].iface.role);
		SNPRINTF_APPEND(overflow, buf, size, "ip=%s\n", netif != NULL ? ipaddr_ntoa(&netif->ip_addr) : "unknown");
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
	data = trim(data, &size);

	if (size >= CONST_STRLEN("timeout ") && strncmp("timeout ", data, 8) == 0) {
		wifi_set_timeout(id, data + 8, size - 8);
	}
	else if (size >= CONST_STRLEN("ssid ") && strncmp("ssid ", data, 5) == 0) {
		wifi_set_ssid(id, data + 5, size - 5);
	}
	else if (size >= CONST_STRLEN("key ") && strncmp("key ", data, 4) == 0) {
		wifi_set_key(id, data + 4, size - 4);
	}
	else if (id == STA_DEV_ID && size == CONST_STRLEN("connect") && strncmp("connect", data, size) == 0) {
		wifi_dev_start(&wifi_common.sta);
	}
	else if (id == STA_DEV_ID && size == CONST_STRLEN("disconnect") && strncmp("disconnect", data, size) == 0) {
		wifi_dev_stop(&wifi_common.sta);
	}
	else if (id == AP_DEV_ID && size == CONST_STRLEN("start") && strncmp("start", data, size) == 0) {
		unsigned int retries = AP_START_RETRIES;

		while (wifi_dev_start(&wifi_common.ap) < 0 && retries-- > 0) {
			/* FIXME: temporary workaround - find out why AP doesn't start */
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "retrying to start Wi-Fi AP\n");
		}
	}
	else if (id == AP_DEV_ID && size == CONST_STRLEN("stop") && strncmp("stop", data, size) == 0) {
		wifi_dev_stop(&wifi_common.ap);
	}
	else {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "got unknown Wi-Fi command: %.*s\n", (int)size, data);
		return -EINVAL;
	}

	return size;
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
	tid = wifi_common.ap.tid;
	mutexUnlock(wifi_common.ap.lock);

	if (tid != 0) {
		wifi_dev_stop(&wifi_common.ap);
	}

	mutexLock(wifi_common.sta.lock);
	tid = wifi_common.sta.tid;
	mutexUnlock(wifi_common.sta.lock);

	if (tid != 0) {
		wifi_dev_stop(&wifi_common.sta);
	}

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


static int wifi_dev_init(unsigned int port, id_t id, const char *path)
{
	oid_t wifi_oid = { port, id };

	return create_dev(&wifi_oid, path);
}


static void wifi_deinit(void)
{
	wifi_deinit_interfaces();
	if (wifi_common.sta.lock != -1) {
		resourceDestroy(wifi_common.sta.lock);
	}
	if (wifi_common.sta.cond != -1) {
		resourceDestroy(wifi_common.sta.cond);
	}
	if (wifi_common.ap.lock != -1) {
		resourceDestroy(wifi_common.ap.lock);
	}
	if (wifi_common.ap.cond != -1) {
		resourceDestroy(wifi_common.ap.cond);
	}
}


static int wifi_init(unsigned int port)
{
	int err;

	wifi_common.sta.lock = -1;
	wifi_common.sta.cond = -1;
	wifi_common.ap.lock = -1;
	wifi_common.ap.cond = -1;

	do {
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

		err = wifi_dev_init(port, STA_DEV_ID, STA_DEV_NAME);
		if (err < 0) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create Wi-Fi STA device\n");
			break;
		}

		err = wifi_dev_init(port, AP_DEV_ID, AP_DEV_NAME);
		if (err < 0) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create Wi-Fi AP device\n");
			break;
		}
	} while (0);

	if (err < 0) {
		wifi_deinit();
	}

	return err;
}


static void wifi_cleanup_thread(void *arg)
{
	(void)arg;
	remove(AP_DEV_NAME);
	remove(STA_DEV_NAME);
}


static int wifi_handle_ctrl(unsigned int port, msg_t *msg)
{
	switch (msg->type) {
		case mtOpen: {
			if (wifi_common.ctrl.busy) {
				return -EBUSY;
			}
			int bytes = snprintf(wifi_common.ctrl.buf, sizeof(wifi_common.ctrl.buf), "running=%d", wifi_common.initialized ? 1 : 0);
			wifi_common.ctrl.len = bytes;
			wifi_common.ctrl.busy = true;
			return EOK;
		}

		case mtClose:
			wifi_common.ctrl.busy = false;
			return EOK;

		case mtRead: {
			off_t offset = msg->i.io.offs;
			int cnt = min(msg->o.size, wifi_common.ctrl.len - offset);

			if (offset > wifi_common.ctrl.len) {
				return -ERANGE;
			}

			memcpy(msg->o.data, wifi_common.ctrl.buf + offset, cnt);
			return cnt;
		}

		case mtWrite: {
			const char *data = msg->i.data;
			size_t size = msg->i.size;

			data = trim(data, &size);

			if (size == CONST_STRLEN("on") && strncmp("on", data, size) == 0) {
				oid_t oid __attribute__((unused));
				if (wifi_common.initialized || lookup(AP_DEV_NAME, NULL, &oid) >= 0 || lookup(STA_DEV_NAME, NULL, &oid) >= 0) {
					wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Wi-Fi is already on");
					return size;
				}

				if (wifi_init(port) >= 0) {
					wifi_common.initialized = true;
				}
			}
			else if (size == CONST_STRLEN("off") && strncmp("off", data, size) == 0) {
				if (!wifi_common.initialized) {
					return size;
				}

				wifi_deinit();
				wifi_common.initialized = false;

				/* cleanup asynchroniously - otherwise remove() can't work */
				handle_t tid;
				sys_thread_opt_new("wifi-cleanup", wifi_cleanup_thread, NULL, 1024, 0, &tid);
			}
			else {
				wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "got unknown Wi-Fi command: %.*s\n", (int)size, data);
				return -EINVAL;
			}
			return size;
		}

		default:
			return -EINVAL;
	}
}


static void wifi_msg_thread(void *arg)
{
	cy_rslt_t result;
	unsigned int port;

	result = cy_log_init(CY_LOG_DEBUG);
	if (result != CY_RSLT_SUCCESS) {
		fprintf(stderr, "phoenix-rtos-lwip: can't init Wi-Fi logs\n");
		return;
	}

	if (portCreate(&port) < 0) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create Wi-Fi port\n");
		return;
	}

	if (wifi_dev_init(port, CTRL_DEV_ID, CTRL_DEV_NAME) < 0) {
		portDestroy(port);
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create Wi-Fi ctrl device\n");
		return;
	}

	for (;;) {
		msg_t msg = { 0 };
		msg_rid_t rid;

		if (msgRecv(port, &msg, &rid) < 0) {
			continue;
		}

		if (msg.oid.id == CTRL_DEV_ID) {
			msg.o.err = wifi_handle_ctrl(port, &msg);
			msgRespond(port, &msg, rid);
			continue;
		}

		if ((msg.oid.id != STA_DEV_ID && msg.oid.id != AP_DEV_ID) || !wifi_common.initialized) {
			msg.o.err = -ENODEV;
			msgRespond(port, &msg, rid);
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
				msg.o.err = -EINVAL;
				break;
		}

		msgRespond(port, &msg, rid);
	}
}


__constructor__(1000) void init_wifi(void)
{
	int err = sys_thread_opt_new("wifi-msg", wifi_msg_thread, NULL, WIFI_THREAD_STACKSZ, WIFI_THREAD_PRIO, NULL);
	if (err < 0) {
		errout(err, "thread(wifi-msg)");
	}
}
