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

#include "cy_log.h"
#include "lwip/sys.h"

#include "whd_chip_constants.h"
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

#define WIFI_FLAG_STARTED (1 << 0)
#define WIFI_FLAG_FAILED  (1 << 1)
#define WIFI_FLAG_FINISH  (1 << 2)

#define WIFI_START_RETRIES 5

#define WIFI_AP_DEV_ID    0
#define WIFI_AP_DEV_NAME  "/dev/wifi/ap"
#define WIFI_STA_DEV_ID   1
#define WIFI_STA_DEV_NAME "/dev/wifi/sta"

#define AP_SECURITY_MODE WHD_SECURITY_WPA2_AES_PSK
#define AP_CHANNEL       1
#define AP_BAND          CHANSPEC_BAND_2G

#define STA_SCAN_TYPE WHD_SCAN_TYPE_PNO
#define STA_BSS_TYPE  WHD_BSS_TYPE_ANY

#define SNPRINTF_APPEND(overflow, fmt, ...) \
	do { \
		if (!overflow) { \
			int n = snprintf(buf, size, fmt, ##__VA_ARGS__); \
			if (n >= size) \
				overflow = true; \
			else { \
				size -= n; \
				buf += n; \
			} \
		} \
	} while (0)


static struct {
	handle_t lock;
	bool interfaces_initialized;

	struct {
		handle_t cond;
		handle_t tid;
		volatile uint8_t flags;
		uint32_t idle_timeout;
		uint32_t idle_current;
		ip_static_addr_t addr;
	} ap;

	struct {
		handle_t cond;
		uint32_t scan_timeout;
		bool connected;
		whd_ssid_t connected_to;
	} sta;

	struct {
		bool busy;
		char buf[128];
		int len;

		whd_ssid_t ssid;
		uint8_t key[WSEC_MAX_PSK_LEN];
		uint8_t key_len;

		cy_lwip_nw_interface_t iface;
	} dev[2]; /* indexed by device's id */
} wifi_common = {
	.ap.addr = {
		.addr = IPADDR4_INIT_BYTES(192, 168, 2, 1),
		.netmask = IPADDR4_INIT_BYTES(255, 255, 255, 0),
		.gateway = IPADDR4_INIT_BYTES(192, 168, 2, 1) }
};


static int wifi_ap_set_timeout(id_t id, const char *data, size_t len)
{
	char buf[16];
	long int timeout;
	char *endp;

	if (len > (sizeof(buf) - 1)) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi idle timeout (max length is %u)\n", sizeof(buf) - 1);
		return -1;
	}

	memcpy(buf, data, len);
	buf[len] = '\0';

	set_errno(0);
	timeout = strtol(buf, &endp, 0);
	if (errno != 0 || endp == buf || timeout == LONG_MAX) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi idle timeout (bad timeout value)\n");
	}
	else if (timeout < 0) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi idle timeout (min value is 0)\n");
		return -1;
	}
	else if (timeout > UINT32_MAX) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi idle timeout (max value is %u)\n", UINT32_MAX);
		return -1;
	}
	else {
		/* nothing */
	}

	mutexLock(wifi_common.lock);
	if (id == WIFI_AP_DEV_ID) {
		wifi_common.ap.idle_timeout = timeout;
	}
	else if (id == WIFI_STA_DEV_ID) {
		wifi_common.sta.scan_timeout = timeout;
	}
	else {
		/* nothing */
	}
	mutexUnlock(wifi_common.lock);

	return 0;
}


static int wifi_ap_set_ssid(id_t id, const char *ssid, size_t len)
{
	if (len > SSID_NAME_SIZE) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi SSID (max length is %u)\n", SSID_NAME_SIZE);
		return -1;
	}

	mutexLock(wifi_common.lock);
	memcpy(wifi_common.dev[id].ssid.value, ssid, len);
	wifi_common.dev[id].ssid.length = len;
	mutexUnlock(wifi_common.lock);

	return 0;
}


static int wifi_ap_set_key(id_t id, const char *key, size_t len)
{
	if (len < WSEC_MIN_PSK_LEN) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi key (min length is %u)\n", WSEC_MIN_PSK_LEN);
		return -1;
	}

	if (len > WSEC_MAX_PSK_LEN) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi key (max length is %u)\n", WSEC_MAX_PSK_LEN);
		return -1;
	}

	mutexLock(wifi_common.lock);
	memcpy(wifi_common.dev[id].key, key, len);
	wifi_common.dev[id].key_len = len;
	mutexUnlock(wifi_common.lock);

	return 0;
}


static bool wifi_ap_is_idle(void)
{
	uint8_t buf[sizeof(uint32_t) + 4 * sizeof(whd_mac_t)];
	whd_maclist_t *clients = (whd_maclist_t *)buf;
	cy_rslt_t result;

	memset(buf, 0, sizeof(buf));
	clients->count = 4;

	result = whd_wifi_get_associated_client_list(wifi_common.dev[WIFI_AP_DEV_ID].iface.whd_iface, buf, sizeof(buf));
	if (result == WHD_SUCCESS && clients->count == 0) {
		return true;
	}

	return false;
}


static void wifi_deinit_interfaces(void)
{
	/* All below functions are safe to call even if interface has not been initialized */
	for (int i = 0; i < (sizeof(wifi_common.dev) / sizeof(wifi_common.dev[0])); i++) {
		(void)cy_lwip_network_down(&wifi_common.dev[i].iface);
		(void)cy_lwip_remove_interface(&wifi_common.dev[i].iface);
	}
	/* Deinitializes wifi and both interfaces from a pointer to either one */
	(void)cybsp_wifi_deinit(wifi_common.dev[0].iface.whd_iface);
	cybsp_free();

	wifi_common.interfaces_initialized = false;
}


static int wifi_init_interfaces(void)
{
	cy_rslt_t result;

	do {
		result = cybsp_init();
		if (result != CY_RSLT_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't init Wi-Fi HW\n");
			break;
		}

		/* AP */
		result = cybsp_wifi_init_primary(&wifi_common.dev[WIFI_AP_DEV_ID].iface.whd_iface);
		if (result != CY_RSLT_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't init Wi-Fi AP interface\n");
			break;
		}
		wifi_common.dev[WIFI_AP_DEV_ID].iface.role = CY_LWIP_AP_NW_INTERFACE;

		result = cy_lwip_add_interface(&wifi_common.dev[WIFI_AP_DEV_ID].iface, &wifi_common.ap.addr);
		if (result != CY_RSLT_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't add Wi-Fi AP interface\n");
			break;
		}

		result = cy_lwip_network_up(&wifi_common.dev[WIFI_AP_DEV_ID].iface);
		if (result != CY_RSLT_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't bring up Wi-Fi AP interface\n");
			break;
		}

		/* STA */
		result = cybsp_wifi_init_secondary(&wifi_common.dev[WIFI_STA_DEV_ID].iface.whd_iface, NULL);
		if (result != CY_RSLT_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't init Wi-Fi STA interface\n");
			break;
		}
		wifi_common.dev[WIFI_STA_DEV_ID].iface.role = CY_LWIP_STA_NW_INTERFACE;

		result = cy_lwip_add_interface(&wifi_common.dev[WIFI_STA_DEV_ID].iface, NULL);
		if (result != CY_RSLT_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't add Wi-Fi STA interface\n");
			break;
		}

		result = cy_lwip_network_up(&wifi_common.dev[WIFI_STA_DEV_ID].iface);
		if (result != CY_RSLT_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't bring up Wi-Fi STA interface\n");
			break;
		}
	} while (0);

	if (result < 0) {
		wifi_deinit_interfaces();
		return -1;
	}

	wifi_common.interfaces_initialized = true;

	return 0;
}


static void wifi_ap_main_loop(void)
{
	for (;;) {
		bool finish = false;
		bool update_idle = false;
		bool check_idle = false;
		unsigned int cond_timeout = 0;

		mutexLock(wifi_common.lock);

		if ((wifi_common.ap.flags & WIFI_FLAG_FINISH) != 0) {
			finish = true;
		}

		if (wifi_common.ap.idle_timeout != 0) {
			if (wifi_common.ap.idle_current < wifi_common.ap.idle_timeout) {
				update_idle = true;
				cond_timeout = 1;
			}
			else {
				check_idle = true;
				cond_timeout = 60;
			}
		}

		mutexUnlock(wifi_common.lock);

		if (!finish && check_idle) {
			if (wifi_ap_is_idle()) {
				finish = true;
			}
		}

		if (finish) {
			break;
		}

		mutexLock(wifi_common.lock);
		condWait(wifi_common.ap.cond, wifi_common.lock, cond_timeout * 1000000ULL);

		if (update_idle) {
			wifi_common.ap.idle_current += 1;
		}

		mutexUnlock(wifi_common.lock);
	}
}


static void wifi_ap_thread(void *arg)
{
	mutexLock(wifi_common.lock);
	wifi_common.ap.flags |= WIFI_FLAG_STARTED;
	mutexUnlock(wifi_common.lock);

	wifi_ap_main_loop();

	mutexLock(wifi_common.lock);
	wifi_common.ap.tid = 0;
	mutexUnlock(wifi_common.lock);
}


static int wifi_ap_start(void)
{
	whd_result_t result;
	whd_ssid_t ssid;
	uint8_t key[WSEC_MAX_PSK_LEN];
	uint8_t key_len;
	chanspec_t chanspec;

	mutexLock(wifi_common.lock);

	/* reset idle timeout in any case */
	wifi_common.ap.idle_current = 0;

	if (wifi_common.ap.tid != 0) {
		mutexUnlock(wifi_common.lock);
		return 0;
	}

	wifi_common.ap.flags = 0;

	if (!wifi_common.interfaces_initialized) {
		if (wifi_init_interfaces() < 0) {
			return -1;
		}
	}

	ssid = wifi_common.dev[WIFI_AP_DEV_ID].ssid;
	memcpy(key, wifi_common.dev[WIFI_AP_DEV_ID].key, sizeof(key));
	key_len = wifi_common.dev[WIFI_AP_DEV_ID].key_len;
	chanspec = (AP_BAND << 8) | (AP_CHANNEL & 0xff);

	result = whd_wifi_init_ap(wifi_common.dev[WIFI_AP_DEV_ID].iface.whd_iface, &ssid, AP_SECURITY_MODE, key, key_len, chanspec);
	if (result != WHD_SUCCESS) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't init Wi-Fi AP\n");
		wifi_deinit_interfaces();
		return -1;
	}

	result = whd_wifi_start_ap(wifi_common.dev[WIFI_AP_DEV_ID].iface.whd_iface);
	if (result != WHD_SUCCESS) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't start Wi-Fi AP\n");
		wifi_deinit_interfaces();
		return -1;
	}

	if (sys_thread_opt_new("wifi-ap", wifi_ap_thread, NULL, WIFI_THREAD_STACKSZ, WIFI_THREAD_PRIO, &wifi_common.ap.tid) < 0) {
		mutexUnlock(wifi_common.lock);
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create Wi-Fi AP thread\n");
		return -1;
	}

	mutexUnlock(wifi_common.lock);

	return 0;
}


static void wifi_ap_stop(void)
{
	handle_t tid;

	mutexLock(wifi_common.lock);

	if (wifi_common.ap.tid == 0) {
		mutexUnlock(wifi_common.lock);
		return;
	}

	tid = wifi_common.ap.tid;
	wifi_common.ap.flags |= WIFI_FLAG_FINISH;
	condSignal(wifi_common.ap.cond);

	mutexUnlock(wifi_common.lock);

	sys_thread_join(tid);
}


static void whd_scan_result_cb(whd_scan_result_t **result_ptr, void *user_data, whd_scan_status_t status)
{
	switch (status) {
		case WHD_SCAN_ABORTED:
			return;

		case WHD_SCAN_COMPLETED_SUCCESSFULLY:
			break;

		case WHD_SCAN_INCOMPLETE: {
			if ((**result_ptr).SSID.length != 0) {
				whd_ssid_t *ssid = user_data;

				if (memcmp((*result_ptr)->SSID.value, ssid->value, ssid->length) != 0) {
					wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "scanner: SSID mismatch\n");
					return;
				}
			}
			break;
		}

		default:
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "scanner: unknown status %d\n", status);
			return;
	}

	mutexLock(wifi_common.lock);
	if (result_ptr != NULL) {
		*result_ptr = NULL;
	}
	condSignal(wifi_common.sta.cond);
	mutexUnlock(wifi_common.lock);
}


static int wifi_sta_connect(void)
{
	whd_result_t result;
	whd_ssid_t ssid;
	uint8_t key[WSEC_MAX_PSK_LEN];
	uint8_t key_len;
	whd_scan_result_t scan_res;
	time_t when;
	uint32_t scan_timeout;

	mutexLock(wifi_common.lock);

	ssid = wifi_common.dev[WIFI_AP_DEV_ID].ssid;
	memcpy(key, wifi_common.dev[WIFI_AP_DEV_ID].key, sizeof(key));
	key_len = wifi_common.dev[WIFI_AP_DEV_ID].key_len;
	scan_timeout = wifi_common.sta.scan_timeout;

	if (wifi_common.sta.connected) {
		if (memcmp(&wifi_common.sta.connected_to, &ssid, sizeof(ssid)) == 0) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, "already connected to this network\n");
			mutexUnlock(wifi_common.lock);
			return 0;
		}
		else {
			result = whd_wifi_leave(wifi_common.dev[WIFI_STA_DEV_ID].iface.whd_iface);
			if (result != WHD_SUCCESS) {
				wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "error leaving network\n");
				mutexUnlock(wifi_common.lock);
				return -1;
			}
		}
	}

	if (!wifi_common.interfaces_initialized) {
		if (wifi_init_interfaces() < 0) {
			mutexUnlock(wifi_common.lock);
			return -1;
		}
	}

	if (scan_timeout != 0) {
		when = time(NULL) + scan_timeout;
	}

	scan_res.security = WHD_SECURITY_UNKNOWN;
	do {
		result = whd_wifi_scan(wifi_common.dev[WIFI_STA_DEV_ID].iface.whd_iface, STA_SCAN_TYPE, STA_BSS_TYPE,
				&ssid, NULL, NULL, NULL, whd_scan_result_cb, &scan_res, &ssid);
		condWait(wifi_common.sta.cond, wifi_common.lock, scan_timeout * 1000000ULL);
		if (scan_timeout != 0 && time(NULL) > when) {
			result = 1;
			break;
		}
	} while (result == WHD_SUCCESS && scan_res.security == WHD_SECURITY_UNKNOWN);
	(void)whd_wifi_stop_scan(wifi_common.dev[WIFI_STA_DEV_ID].iface.whd_iface);

	if (result != WHD_SUCCESS) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't get network's security\n");
		mutexUnlock(wifi_common.lock);
		return -1;
	}

	result = whd_wifi_join(wifi_common.dev[WIFI_STA_DEV_ID].iface.whd_iface, &ssid, scan_res.security, key, key_len);
	if (result != WHD_SUCCESS) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't join requested network\n");
		mutexUnlock(wifi_common.lock);
		return -1;
	}

	memcpy(&wifi_common.sta.connected_to, &ssid, sizeof(wifi_common.sta.connected_to));
	wifi_common.sta.connected = true;

	mutexUnlock(wifi_common.lock);

	return 0;
}


static void wifi_sta_disconnect(void)
{
	mutexLock(wifi_common.lock);
	if (wifi_common.sta.connected) {
		(void)whd_wifi_leave(wifi_common.dev[WIFI_STA_DEV_ID].iface.whd_iface);
	}
	wifi_common.sta.connected = false;
	mutexUnlock(wifi_common.lock);
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

	mutexLock(wifi_common.lock);

	if (id == WIFI_AP_DEV_ID) {
		SNPRINTF_APPEND(overflow, "running=%u\n", wifi_common.ap.tid != 0);
		SNPRINTF_APPEND(overflow, "timeout=%u\n", wifi_common.ap.idle_timeout);
	}
	else if (id == WIFI_AP_DEV_ID) {
		SNPRINTF_APPEND(overflow, "connected=%u\n", wifi_common.sta.connected);
		if (wifi_common.sta.connected) {
			SNPRINTF_APPEND(overflow, "connected_to=%.*s\n", (int)wifi_common.sta.connected_to.length, wifi_common.sta.connected_to.value);
		}
		SNPRINTF_APPEND(overflow, "timeout=%u\n", wifi_common.sta.scan_timeout);
	}
	else {
		/* nothing */
	}
	SNPRINTF_APPEND(overflow, "ssid=%.*s\n", wifi_common.dev[id].ssid.length, wifi_common.dev[id].ssid.value);

	mutexUnlock(wifi_common.lock);

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
	if (size >= 8 && strncmp("timeout ", data, 8) == 0) {
		wifi_ap_set_timeout(id, data + 8, size - 8);
	}
	else if (size >= 5 && strncmp("ssid ", data, 5) == 0) {
		wifi_ap_set_ssid(id, data + 5, size - 5);
	}
	else if (size >= 4 && strncmp("key ", data, 4) == 0) {
		wifi_ap_set_key(id, data + 4, size - 4);
	}
	else if (id == WIFI_AP_DEV_ID) {
		if (strncmp("start", data, size) == 0) {
			unsigned int retries = WIFI_START_RETRIES;

			while (wifi_ap_start() < 0 && retries-- > 0) {
				/* FIXME: temporary workaround - find out why AP doesn't start */
				wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "retrying to start Wi-Fi AP\n");
			}
		}
		else if (strncmp("stop", data, size) == 0) {
			wifi_ap_stop();
		}
		else {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "got unknown Wi-Fi command: %.*s\n", (int)size, data);
			return -EINVAL;
		}
	}
	else if (id == WIFI_STA_DEV_ID) {
		if (strncmp("connect", data, size) == 0) {
			if (wifi_sta_connect() < 0) {
				return -EINVAL;
			}
		}
		else if (id == WIFI_STA_DEV_ID && strncmp("disconnect", data, size) == 0) {
			wifi_sta_disconnect();
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


static int wifi_dev_init(const char *path, unsigned int port, id_t id)
{
	oid_t wifi_oid = { port, id };

	return create_dev(&wifi_oid, path);
}


static void wifi_msg_thread(void *arg)
{
	cy_rslt_t result;
	unsigned int port;

	result = cy_log_init(CY_LOG_INFO);
	if (result != CY_RSLT_SUCCESS) {
		fprintf(stderr, "phoenix-rtos-lwip: can't init Wi-Fi logs\n");
		return;
	}

	if (portCreate(&port) < 0) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create Wi-Fi port\n");
		return;
	}

	if (wifi_dev_init(WIFI_AP_DEV_NAME, port, WIFI_AP_DEV_ID) < 0) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create Wi-Fi device\n");
		return;
	}

	if (wifi_dev_init(WIFI_STA_DEV_NAME, port, WIFI_AP_DEV_ID) < 0) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create Wi-Fi device\n");
		return;
	}

	for (;;) {
		msg_t msg = { 0 };
		msg_rid_t rid;

		if (msgRecv(port, &msg, &rid) < 0) {
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
	int err;

	err = mutexCreate(&wifi_common.lock);
	if (err < 0) {
		errout(err, "mutexCreate(lock)");
	}

	err = condCreate(&wifi_common.ap.cond);
	if (err < 0) {
		resourceDestroy(wifi_common.lock);
		errout(err, "condCreate(cond)");
	}

	err = condCreate(&wifi_common.sta.cond);
	if (err < 0) {
		resourceDestroy(wifi_common.lock);
		resourceDestroy(wifi_common.ap.cond);
		errout(err, "condCreate(cond)");
	}

	err = sys_thread_opt_new("wifi-msg", wifi_msg_thread, NULL, WIFI_THREAD_STACKSZ, WIFI_THREAD_PRIO, NULL);
	if (err < 0) {
		resourceDestroy(wifi_common.lock);
		resourceDestroy(wifi_common.ap.cond);
		resourceDestroy(wifi_common.sta.cond);
		errout(err, "thread(wifi-msg)");
	}
}
