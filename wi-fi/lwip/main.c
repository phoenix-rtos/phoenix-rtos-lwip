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

#define WIFI_FLAG_STARTED (1 << 0)
#define WIFI_FLAG_FAILED  (1 << 1)
#define WIFI_FLAG_FINISH  (1 << 2)

#define WIFI_START_RETRIES 5

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
	handle_t lock;
	handle_t cond;
	handle_t tid;

	volatile uint8_t flags;
	uint32_t idle_timeout;
	uint32_t idle_current;
	whd_ssid_t ssid;
	uint8_t key[WSEC_MAX_PSK_LEN];
	uint8_t key_len;

	cy_lwip_nw_interface_t iface;

	struct {
		int busy;
		char buf[128];
		int len;
	} dev;
} wifi_common;

static ip_static_addr_t ap_addr = {
	.addr = IPADDR4_INIT_BYTES(192, 168, 2, 1),
	.netmask = IPADDR4_INIT_BYTES(255, 255, 255, 0),
	.gateway = IPADDR4_INIT_BYTES(192, 168, 2, 1)
};


static int wifi_ap_set_idle_timeout(const char *data, size_t len)
{
	char buf[16];
	long int timeout;

	if (len > (sizeof(buf) - 1)) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi idle timeout (max length is %u)\n", sizeof(buf) - 1);
		return -1;
	}

	memcpy(buf, data, len);
	buf[len] = '\0';

	timeout = strtol(buf, NULL, 0);
	if (timeout < 0) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi idle timeout (min value is 0)\n");
		return -1;
	}
	else if (timeout > UINT32_MAX) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi idle timeout (max value is %u)\n", UINT32_MAX);
		return -1;
	}

	mutexLock(wifi_common.lock);
	wifi_common.idle_timeout = timeout;
	mutexUnlock(wifi_common.lock);

	return 0;
}


static int wifi_ap_set_ssid(const char *ssid, size_t len)
{
	if (len > SSID_NAME_SIZE) {
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't set Wi-Fi SSID (max length is %u)\n", SSID_NAME_SIZE);
		return -1;
	}

	mutexLock(wifi_common.lock);
	memcpy(wifi_common.ssid.value, ssid, len);
	wifi_common.ssid.length = len;
	mutexUnlock(wifi_common.lock);

	return 0;
}


static int wifi_ap_set_key(const char *key, size_t len)
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
	memcpy(wifi_common.key, key, len);
	wifi_common.key_len = len;
	mutexUnlock(wifi_common.lock);

	return 0;
}


static int wifi_ap_is_idle(void)
{
	uint8_t buf[sizeof(uint32_t) + 4 * sizeof(whd_mac_t)];
	whd_maclist_t *clients = (whd_maclist_t *)buf;
	cy_rslt_t result;

	memset(buf, 0, sizeof(buf));

	result = whd_wifi_get_associated_client_list(wifi_common.iface.whd_iface, buf, 4);
	if (result == WHD_SUCCESS && clients->count == 0)
		return 1;

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

		if (wifi_common.flags & WIFI_FLAG_FINISH)
			finish = true;

		if (wifi_common.idle_timeout != 0) {
			if (wifi_common.idle_current < wifi_common.idle_timeout) {
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
			if (wifi_ap_is_idle())
				finish = true;
		}

		if (finish)
			break;

		mutexLock(wifi_common.lock);
		condWait(wifi_common.cond, wifi_common.lock, cond_timeout * 1000000ULL);

		if (update_idle)
			wifi_common.idle_current += 1;

		mutexUnlock(wifi_common.lock);
	}
}


static void wifi_ap_thread(void *arg)
{
	bool started = false;

	do {
		cy_rslt_t result;
		whd_ssid_t ssid;
		uint8_t key[WSEC_MAX_PSK_LEN];
		uint8_t key_len;

		mutexLock(wifi_common.lock);

		ssid = wifi_common.ssid;
		memcpy(key, wifi_common.key, sizeof(key));
		key_len = wifi_common.key_len;

		mutexUnlock(wifi_common.lock);

		result = cybsp_init();
		if (result != CY_RSLT_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't init Wi-Fi HW\n");
			break;
		}

		result = cyhal_sdio_start_irq_thread(cybsp_get_wifi_sdio_obj());
		if (result != CY_RSLT_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't start IRQ thread\n");
			cybsp_free();
			break;
		}

		result = cybsp_wifi_init_primary(&wifi_common.iface.whd_iface);
		if (result != CY_RSLT_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't init Wi-Fi interface\n");
			/* cyhal_sdio_stop_irq_thread can be safely called twice */
			cyhal_sdio_stop_irq_thread(cybsp_get_wifi_sdio_obj());
			cybsp_free();
			break;
		}

		wifi_common.iface.role = CY_LWIP_AP_NW_INTERFACE;

		result = cy_lwip_add_interface(&wifi_common.iface, &ap_addr);
		if (result != CY_RSLT_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't add Wi-Fi interface\n");
			cybsp_wifi_deinit(wifi_common.iface.whd_iface);
			cyhal_sdio_stop_irq_thread(cybsp_get_wifi_sdio_obj());
			cybsp_free();
			break;
		}

		result = cy_lwip_network_up(&wifi_common.iface);
		if (result != CY_RSLT_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't bring up Wi-Fi interface\n");
			cy_lwip_remove_interface(&wifi_common.iface);
			cybsp_wifi_deinit(wifi_common.iface.whd_iface);
			cyhal_sdio_stop_irq_thread(cybsp_get_wifi_sdio_obj());
			cybsp_free();
			break;
		}

		result = whd_wifi_init_ap(wifi_common.iface.whd_iface, &ssid, AP_SECURITY_MODE, key, key_len, AP_CHANNEL);
		if (result != CY_RSLT_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't init Wi-Fi AP\n");
			cy_lwip_network_down(&wifi_common.iface);
			cy_lwip_remove_interface(&wifi_common.iface);
			cybsp_wifi_deinit(wifi_common.iface.whd_iface);
			cyhal_sdio_stop_irq_thread(cybsp_get_wifi_sdio_obj());
			cybsp_free();
			break;
		}

		result = whd_wifi_start_ap(wifi_common.iface.whd_iface);
		if (result != CY_RSLT_SUCCESS) {
			wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't start Wi-Fi AP\n");
			cy_lwip_network_down(&wifi_common.iface);
			cy_lwip_remove_interface(&wifi_common.iface);
			cybsp_wifi_deinit(wifi_common.iface.whd_iface);
			cyhal_sdio_stop_irq_thread(cybsp_get_wifi_sdio_obj());
			cybsp_free();
			break;
		}

		started = true;
	} while (0);

	mutexLock(wifi_common.lock);
	wifi_common.flags |= started ? WIFI_FLAG_STARTED : WIFI_FLAG_FAILED;
	condSignal(wifi_common.cond);
	mutexUnlock(wifi_common.lock);

	if (started) {
		wifi_ap_main_loop();

		whd_wifi_stop_ap(wifi_common.iface.whd_iface);
		cy_lwip_network_down(&wifi_common.iface);
		cy_lwip_remove_interface(&wifi_common.iface);
		cybsp_wifi_deinit(wifi_common.iface.whd_iface);
		cyhal_sdio_stop_irq_thread(cybsp_get_wifi_sdio_obj());
		cybsp_free();
	}

	mutexLock(wifi_common.lock);
	wifi_common.tid = 0;
	mutexUnlock(wifi_common.lock);
}


static int wifi_ap_start(void)
{
	uint8_t flags;

	mutexLock(wifi_common.lock);

	/* reset idle timeout in any case */
	wifi_common.idle_current = 0;

	if (wifi_common.tid != 0) {
		mutexUnlock(wifi_common.lock);
		return 0;
	}

	wifi_common.flags = 0;

	if (sys_thread_opt_new("wifi-ap", wifi_ap_thread, NULL, WIFI_THREAD_STACKSZ, WIFI_THREAD_PRIO, &wifi_common.tid) < 0) {
		mutexUnlock(wifi_common.lock);
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "can't create Wi-Fi AP thread\n");
		return -1;
	}

	while (wifi_common.flags == 0) {
		condWait(wifi_common.cond, wifi_common.lock, 0);
	}

	flags = wifi_common.flags;

	mutexUnlock(wifi_common.lock);

	return (flags & WIFI_FLAG_STARTED ? 0 : -1);
}


static void wifi_ap_stop(void)
{
	handle_t tid;

	mutexLock(wifi_common.lock);

	if (wifi_common.tid == 0) {
		mutexUnlock(wifi_common.lock);
		return;
	}

	tid = wifi_common.tid;
	wifi_common.flags |= WIFI_FLAG_FINISH;
	condSignal(wifi_common.cond);

	mutexUnlock(wifi_common.lock);

	sys_thread_join(tid);
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

	mutexLock(wifi_common.lock);

	SNPRINTF_APPEND("running=%u\n", wifi_common.tid != 0);
	SNPRINTF_APPEND("timeout=%u\n", wifi_common.idle_timeout);
	SNPRINTF_APPEND("ssid=%.*s\n", wifi_common.ssid.length, wifi_common.ssid.value);

	mutexUnlock(wifi_common.lock);

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
	if (size >= 8 && strncmp("timeout ", data, 8) == 0) {
		wifi_ap_set_idle_timeout(data + 8, size - 8);
	}
	else if (size >= 5 && strncmp("ssid ", data, 5) == 0) {
		wifi_ap_set_ssid(data + 5, size - 5);
	}
	else if (size >= 4 && strncmp("key ", data, 4) == 0) {
		wifi_ap_set_key(data + 4, size - 4);
	}
	else if (strncmp("start", data, size) == 0) {
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
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "got unknown Wi-Fi command\n");
		return -EINVAL;
	}

	return size;
}


static int wifi_dev_init(unsigned int port)
{
	oid_t wifi_oid = { port, WIFI_DEV_ID };

	return create_dev(&wifi_oid, WIFI_DEV_NAME);
}


static void wifi_msg_thread(void *arg)
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
		msg_rid_t rid;

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

	err = mutexCreate(&wifi_common.lock);
	if (err) {
		errout(err, "mutexCreate(lock)");
	}

	err = condCreate(&wifi_common.cond);
	if (err) {
		resourceDestroy(wifi_common.lock);
		errout(err, "condCreate(cond)");
	}

	if ((err = sys_thread_opt_new("wifi-msg", wifi_msg_thread, NULL, WIFI_THREAD_STACKSZ, WIFI_THREAD_PRIO, NULL))) {
		resourceDestroy(wifi_common.lock);
		resourceDestroy(wifi_common.cond);
		errout(err, "thread(wifi-msg)");
	}
}
