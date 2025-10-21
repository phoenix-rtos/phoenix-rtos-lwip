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
#include <stdatomic.h>
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

#include "lwip/sys.h"


#define WIFI_THREAD_PRIO    4
#define WIFI_THREAD_STACKSZ 4096

#define WIFI_AP_FLAG_STARTED (1 << 0)
#define WIFI_AP_FLAG_FAILED  (1 << 1)
#define WIFI_AP_FLAG_FINISH  (1 << 2)

#define AP_DEV_ID        CY_LWIP_AP_NW_INTERFACE
#define AP_DEV_NAME      "/dev/wifi/ap"
#define AP_START_RETRIES 5
#define AP_SECURITY_MODE WHD_SECURITY_WPA2_AES_PSK
#define AP_CHANNEL       1

#define STA_DEV_ID    CY_LWIP_STA_NW_INTERFACE
#define STA_DEV_NAME  "/dev/wifi/sta"
#define STA_SCAN_TYPE WHD_SCAN_TYPE_ACTIVE
#define STA_BSS_TYPE  WHD_BSS_TYPE_ANY
#define STA_N_SCANS   5

#define WIFI_CTRL_DEV_ID   2
#define WIFI_CTRL_DEV_NAME "/dev/wifi/ctrl"

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

	uint32_t timeout;
	whd_ssid_t ssid;
	uint8_t key[WSEC_MAX_PSK_LEN];
	uint8_t key_len;

	bool busy;
	int len;
	char buf[128];
	cy_lwip_nw_interface_t iface;
};


static struct {
	atomic_bool initialized;
	handle_t tid;

	volatile uint8_t flags;
	uint32_t idle_current;

	union {
		struct {
			struct wifi_device sta;
			struct wifi_device ap;
		};
		struct wifi_device dev[2];
	};

	struct {
		bool busy;
		char buf[16];
		int len;
	} ctrl_dev;
} wifi_common;

static ip_static_addr_t ap_addr = {
	.addr = IPADDR4_INIT_BYTES(192, 168, 2, 1),
	.netmask = IPADDR4_INIT_BYTES(255, 255, 255, 0),
	.gateway = IPADDR4_INIT_BYTES(192, 168, 2, 1)
};

static whd_scan_result_t scan_result;


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
	if (errno != 0 || endp == buf || timeout == LONG_MAX) {
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


static int wifi_set_ssid(id_t id, const char *ssid, size_t len)
{
	if (len > SSID_NAME_SIZE) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi SSID (max length is %u)\n", SSID_NAME_SIZE);
		return -1;
	}

	ssid = trim(ssid, &len);

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

	key = trim(key, &len);

	mutexLock(wifi_common.dev[id].lock);
	memcpy(wifi_common.dev[id].key, key, len);
	wifi_common.dev[id].key_len = len;
	mutexUnlock(wifi_common.dev[id].lock);

	return 0;
}


static bool wifi_ap_is_idle(void)
{
	uint8_t buf[sizeof(uint32_t) + 4 * sizeof(whd_mac_t)];
	whd_maclist_t *clients = (whd_maclist_t *)buf;
	cy_rslt_t result;

	memset(buf, 0, sizeof(buf));
	clients->count = 4;

	result = whd_wifi_get_associated_client_list(wifi_common.ap.iface.whd_iface, buf, sizeof(buf));
	if (result == WHD_SUCCESS && clients->count == 0) {
		return true;
	}

	return false;
}


static void wifi_ap_main_loop(void)
{
	for (;;) {
		bool finish = false;
		bool update_idle = false;
		bool check_idle = false;
		unsigned int cond_timeout = 0;

		mutexLock(wifi_common.ap.lock);

		if ((wifi_common.flags & WIFI_AP_FLAG_FINISH) != 0) {
			finish = true;
		}

		if (wifi_common.ap.timeout != 0) {
			if (wifi_common.idle_current < wifi_common.ap.timeout) {
				update_idle = true;
				cond_timeout = 1;
			}
			else {
				check_idle = true;
				cond_timeout = 60;
			}
		}

		mutexUnlock(wifi_common.ap.lock);

		if (!finish && check_idle) {
			if (wifi_ap_is_idle()) {
				finish = true;
			}
		}

		if (finish) {
			break;
		}

		mutexLock(wifi_common.ap.lock);
		condWait(wifi_common.ap.cond, wifi_common.ap.lock, cond_timeout * 1000000ULL);

		if (update_idle) {
			wifi_common.idle_current += 1;
		}

		mutexUnlock(wifi_common.ap.lock);
	}
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


static void wifi_ap_thread(void *arg)
{
	bool started = false;

	do {
		cy_rslt_t result;
		whd_ssid_t ssid;
		uint8_t key[WSEC_MAX_PSK_LEN];
		uint8_t key_len;

		mutexLock(wifi_common.ap.lock);

		ssid = wifi_common.ap.ssid;
		memcpy(key, wifi_common.ap.key, sizeof(key));
		key_len = wifi_common.ap.key_len;

		mutexUnlock(wifi_common.ap.lock);

		result = whd_wifi_init_ap(wifi_common.ap.iface.whd_iface, &ssid, AP_SECURITY_MODE, key, key_len, AP_CHANNEL);
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
	wifi_common.flags |= started ? WIFI_AP_FLAG_STARTED : WIFI_AP_FLAG_FAILED;
	condSignal(wifi_common.ap.cond);
	mutexUnlock(wifi_common.ap.lock);

	if (started) {
		wifi_ap_main_loop();
	}

	whd_wifi_stop_ap(wifi_common.ap.iface.whd_iface);
	wifi_remove_interface(&wifi_common.ap.iface);

	mutexLock(wifi_common.ap.lock);
	wifi_common.tid = 0;
	mutexUnlock(wifi_common.ap.lock);
}


static int wifi_ap_start(void)
{
	uint8_t flags;

	mutexLock(wifi_common.ap.lock);

	/* reset idle timeout in any case */
	wifi_common.idle_current = 0;

	if (wifi_common.tid != 0) {
		mutexUnlock(wifi_common.ap.lock);
		return 0;
	}

	wifi_common.flags = 0;

	if (sys_thread_opt_new("wifi-ap", wifi_ap_thread, NULL, WIFI_THREAD_STACKSZ, WIFI_THREAD_PRIO, &wifi_common.tid) < 0) {
		mutexUnlock(wifi_common.ap.lock);
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create Wi-Fi AP thread\n");
		return -1;
	}

	while (wifi_common.flags == 0) {
		condWait(wifi_common.ap.cond, wifi_common.ap.lock, 0);
	}

	flags = wifi_common.flags;

	mutexUnlock(wifi_common.ap.lock);

	return ((flags & WIFI_AP_FLAG_STARTED) != 0) ? 0 : -1;
}


static void wifi_ap_stop(void)
{
	handle_t tid;

	mutexLock(wifi_common.ap.lock);

	if (wifi_common.tid == 0) {
		mutexUnlock(wifi_common.ap.lock);
		return;
	}

	tid = wifi_common.tid;
	wifi_common.flags |= WIFI_AP_FLAG_FINISH;
	condSignal(wifi_common.ap.cond);

	mutexUnlock(wifi_common.ap.lock);

	sys_thread_join(tid);
}


static bool wifi_sta_is_connected(whd_ssid_t *ssid)
{
	if (wifi_common.sta.iface.whd_iface == NULL) {
		return false;
	}

	if (whd_wifi_is_ready_to_transceive(wifi_common.sta.iface.whd_iface) != WHD_SUCCESS) {
		return false;
	}

	if (ssid != NULL) {
		whd_bss_info_t ap_info;
		whd_security_t security;
		whd_result_t result = whd_wifi_get_ap_info(wifi_common.sta.iface.whd_iface, &ap_info, &security);
		if (result == WHD_SUCCESS) {

			memcpy(ssid->value, ap_info.SSID, sizeof(ssid->value));
			ssid->length = ap_info.length;
			return true;
		}
	}
	return false;
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


static int wifi_sta_connect(void)
{
	whd_result_t result;
	whd_ssid_t ssid, connected_to;
	uint8_t key[WSEC_MAX_PSK_LEN];
	uint8_t key_len;
	time_t when, now, timeout_remaining;
	uint32_t scan_timeout;

	mutexLock(wifi_common.sta.lock);

	ssid = wifi_common.sta.ssid;
	memcpy(key, wifi_common.sta.key, sizeof(key));
	key_len = wifi_common.sta.key_len;
	scan_timeout = wifi_common.sta.timeout;
	timeout_remaining = scan_timeout;

	mutexUnlock(wifi_common.sta.lock);

	do {
		if (wifi_sta_is_connected(&connected_to)) {
			if (memcmp(&connected_to, &ssid, sizeof(ssid)) == 0) {
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

		result = whd_wifi_set_ioctl_value(wifi_common.sta.iface.whd_iface, WLC_SET_BAND, WLC_BAND_AUTO);
		if (result != WHD_SUCCESS) {
			break;
		}

		if (scan_timeout != 0) {
			when = time(NULL) + scan_timeout;
		}
		scan_result.security = WHD_SECURITY_UNKNOWN;

		mutexLock(wifi_common.sta.lock);
		do {
			result = whd_wifi_scan(wifi_common.sta.iface.whd_iface, STA_SCAN_TYPE, STA_BSS_TYPE,
					&ssid, NULL, NULL, NULL, wifi_scan_result_cb, &scan_result, &ssid);
			condWait(wifi_common.sta.cond, wifi_common.sta.lock, timeout_remaining * 1000000ULL / STA_N_SCANS);

			(void)whd_wifi_stop_scan(wifi_common.sta.iface.whd_iface);

			if (scan_timeout != 0) {
				now = time(NULL);
				if (now >= when) {
					result = WHD_SCAN_ABORTED;
					break;
				}
				timeout_remaining = when - now;
			}
		} while (result == WHD_SUCCESS && scan_result.security == WHD_SECURITY_UNKNOWN);
		mutexUnlock(wifi_common.sta.lock);

		if (result != WHD_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't get network's security\n");
			break;
		}

		result = whd_wifi_join(wifi_common.sta.iface.whd_iface, &ssid, scan_result.security, key, key_len);
		if (result != WHD_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't join requested network\n");
			break;
		}

		if (wifi_add_interface(&wifi_common.sta.iface, NULL) < 0) {
			whd_wifi_leave(wifi_common.sta.iface.whd_iface);
			result = WHD_INTERFACE_NOT_UP;
			break;
		}
	} while (0);

	return (result == WHD_SUCCESS) ? 0 : -1;
}


static void wifi_sta_disconnect(void)
{
	if (wifi_sta_is_connected(NULL)) {
		whd_wifi_leave(wifi_common.sta.iface.whd_iface);
	}
	wifi_remove_interface(&wifi_common.sta.iface);
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
		if (wifi_sta_is_connected(&ssid)) {
			SNPRINTF_APPEND(overflow, buf, size, "connected_to=%.*s\n", ssid.length, ssid.value);
		}
	}
	else if (id == AP_DEV_ID) {
		SNPRINTF_APPEND(overflow, buf, size, "ssid=%.*s\n", wifi_common.ap.ssid.length, wifi_common.ap.ssid.value);
		SNPRINTF_APPEND(overflow, buf, size, "running=%u\n", wifi_common.tid != 0);
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
	data = trim(data, &size);
	if (size >= 8 && strncmp("timeout ", data, 8) == 0) {
		wifi_set_timeout(id, data + 8, size - 8);
	}
	else if (size >= 5 && strncmp("ssid ", data, 5) == 0) {
		wifi_set_ssid(id, data + 5, size - 5);
	}
	else if (size >= 4 && strncmp("key ", data, 4) == 0) {
		wifi_set_key(id, data + 4, size - 4);
	}
	else if (id == STA_DEV_ID) {
		if (size == (sizeof("connect") - 1) && strncmp("connect", data, size) == 0) {
			wifi_sta_connect();
		}
		else if (size == (sizeof("disconnect") - 1) && strncmp("disconnect", data, size) == 0) {
			wifi_sta_disconnect();
		}
		else {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "got unknown Wi-Fi command: %.*s\n", (int)size, data);
			return -EINVAL;
		}
	}
	else if (id == AP_DEV_ID) {
		if (size == (sizeof("start") - 1) && strncmp("start", data, size) == 0) {
			unsigned int retries = AP_START_RETRIES;

			while (wifi_ap_start() < 0 && retries-- > 0) {
				/* FIXME: temporary workaround - find out why AP doesn't start */
				wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "retrying to start Wi-Fi AP\n");
			}
		}
		else if (size == (sizeof("stop") - 1) && strncmp("stop", data, size) == 0) {
			wifi_ap_stop();
		}
		else {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "got unknown Wi-Fi command: %.*s\n", (int)size, data);
			return -EINVAL;
		}
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
		return -1;
	}

	wifi_common.sta.iface.role = CY_LWIP_STA_NW_INTERFACE;

	/* AP */
	result = cybsp_wifi_init_secondary(&wifi_common.ap.iface.whd_iface, NULL);
	if (result != CY_RSLT_SUCCESS) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't init Wi-Fi secondary interface (AP)\n");
		cybsp_wifi_deinit(wifi_common.sta.iface.whd_iface);
		cybsp_free();
		return -1;
	}

	wifi_common.ap.iface.role = CY_LWIP_AP_NW_INTERFACE;

	return 0;
}


static void wifi_deinit_interfaces(void)
{
	wifi_ap_stop();
	wifi_sta_disconnect();
	cybsp_wifi_deinit(wifi_common.sta.iface.whd_iface);
	cybsp_free();
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


static void wifi_do_cleanup(void *arg)
{
	(void)arg;
	remove(AP_DEV_NAME);
	remove(STA_DEV_NAME);
}


static int wifi_handle_ctrl(unsigned int port, msg_t *msg)
{
	switch (msg->type) {
		case mtOpen: {
			if (wifi_common.ctrl_dev.busy) {
				return -EBUSY;
			}
			int bytes = snprintf(wifi_common.ctrl_dev.buf, sizeof(wifi_common.ctrl_dev.buf),
					"wifi is %s", atomic_load(&wifi_common.initialized) ? "on" : "off");
			wifi_common.ctrl_dev.len = bytes;
			wifi_common.ctrl_dev.busy = true;
			return EOK;
		}

		case mtClose:
			wifi_common.ctrl_dev.busy = false;
			return EOK;

		case mtRead: {
			off_t offset = msg->i.io.offs;
			int cnt = min(msg->o.size, wifi_common.ctrl_dev.len - offset);

			if (offset > wifi_common.ctrl_dev.len) {
				return -ERANGE;
			}

			memcpy(msg->o.data, wifi_common.ctrl_dev.buf + offset, cnt);
			return cnt;
		}

		case mtWrite: {
			const char *data = msg->i.data;
			size_t size = msg->i.size;

			if (size == (sizeof("on") - 1) && strncmp("on", data, size) == 0) {
				if (atomic_load(&wifi_common.initialized)) {
					return size;
				}

				if (wifi_init(port) >= 0) {
					atomic_store(&wifi_common.initialized, true);
				}
			}
			else if (size == (sizeof("off") - 1) && strncmp("off", data, size) == 0) {
				if (!atomic_load(&wifi_common.initialized)) {
					return size;
				}

				wifi_deinit();
				atomic_store(&wifi_common.initialized, false);

				/* cleanup asynchroniously - otherwise remove() can't work */
				sys_thread_opt_new("wifi-cleanup", wifi_do_cleanup, NULL, 1024, 0, NULL);
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

	if (wifi_dev_init(port, WIFI_CTRL_DEV_ID, WIFI_CTRL_DEV_NAME) < 0) {
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

		if (msg.oid.id == WIFI_CTRL_DEV_ID) {
			msg.o.err = wifi_handle_ctrl(port, &msg);
			msgRespond(port, &msg, rid);
			continue;
		}

		if (msg.oid.id != STA_DEV_ID && msg.oid.id != AP_DEV_ID) {
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
