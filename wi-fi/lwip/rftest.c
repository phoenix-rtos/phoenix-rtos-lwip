/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP Wi-Fi RF Test Application
 *
 * Copyright 2021, 2026 Phoenix Systems
 * Author: Ziemowit Leszczynski, Julian Uziembło
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <string.h>
#include <sys/minmax.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <posix/utils.h>
#include <stdbool.h>
#include <math.h>
#include <errno.h>

#include "whd_wifi_api.h"
#include "cybsp.h"
#include "cybsp_wifi.h"
#include "cy_lwip_log.h"
#include "cy_log.h"
#include "whd_wlioctl.h"
#include "whd_buffer_api.h"
#include "whd_chip_constants.h"

#include "lwipopts.h"
#include "lwip/sys.h"


#define CONST_STRLEN(str) (sizeof(str) - 1)


/* RF test state structure */
struct rftest_state {
	handle_t lock;

	bool initialized;
	bool busy;
	int len;
	char buf[256];
	whd_interface_t ifp;
	uint8_t channel;
	uint32_t rateKbps;
	uint8_t powerDbm;
	uint32_t txDelay;
	uint32_t txFrameLength;
	uint32_t txFrameCount;
};


static struct {
	struct rftest_state test;
} rftest_common;


#include "whd_wifi_api.h"
#include <string.h>
#include <stdio.h>


int writeRspf(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	int retVal = vsnprintf(rftest_common.test.buf, sizeof(rftest_common.test.buf), format, ap);
	va_end(ap);

	if (retVal >= sizeof(rftest_common.test.buf)) {
		return -EFBIG;
	}

	if (retVal < 0) {
		return retVal;
	}
	rftest_common.test.len = retVal;
	return 0;
}


static int statusRsp(void)
{
	return writeRspf("ready\nchannel=%u rate=%.1f power=%u\n", rftest_common.test.channel, rftest_common.test.rateKbps / 1000.0f, rftest_common.test.powerDbm);
}


static uint32_t get_rf_test_rspec(uint32_t rate_kbps)
{
	const uint32_t htRates[] = { 6500, 13000, 19500, 26000, 39000, 52000, 58500, 65000 };
	for (size_t idx = 0; idx < (sizeof(htRates) / sizeof(htRates[0])); idx++) {
		if (rate_kbps == htRates[idx]) {
			return WL_RSPEC_BW_20MHZ | WL_RSPEC_ENCODE_HT | idx;
		}
	}
	uint8_t legacyVal = (uint8_t)(rate_kbps / 500);
	return WL_RSPEC_BW_20MHZ | WL_RSPEC_ENCODE_RATE | (legacyVal & WL_RSPEC_RATE_MASK);
}


static int rftest_stop_xx(void)
{
	wl_pkteng_t pkteng = {
		.flags = WL_PKTENG_PER_TX_STOP,
	};

	if (whd_wifi_set_iovar_buffer(rftest_common.test.ifp, "pkteng", &pkteng, sizeof(wl_pkteng_t)) != WHD_SUCCESS) {
		printf("[RF Test] failed pkteng\n");
		return -1;
	}

	return 0;
}


// https://community.murata.com/s/article/Drill-down-Test-Environment-Setup-to-Calculate-Number-of-Packets-on-Receiver-Side
static int rftest_start_xx(bool tx, unsigned nframes)
{
	char fw_version[128];

	printf("[RF Test] start %s...\n", tx ? "TX" : "RX");

	if (whd_wifi_get_wifi_version(rftest_common.test.ifp, fw_version, 128) != WHD_SUCCESS) {
		printf("[RF Test] failed to get firmware version\n");
		return -1;
	}
	printf("Wi-Fi Firmware Version: %s\n", fw_version);
	if (whd_wifi_set_down(rftest_common.test.ifp) != WHD_SUCCESS) {
		printf("[RF Test] failed wifi down\n");
		return -1;
	}
	if (whd_wifi_set_iovar_value(rftest_common.test.ifp, IOVAR_STR_MPC, 0) != WHD_SUCCESS) {
		printf("[RF Test] failed mcp down\n");
		return -1;
	}
	if (whd_wifi_set_iovar_value(rftest_common.test.ifp, "phy_watchdog", 0) != WHD_SUCCESS) {
		printf("[RF Test] failed phy_watchdog down\n");
	}
	if (whd_wifi_set_iovar_value(rftest_common.test.ifp, "glacial_timer", 0x7FFFFFFF) != WHD_SUCCESS) {
		printf("[RF Test] failed glacial_timer\n");
		return -1;
	}
	if (whd_wifi_set_ioctl_value(rftest_common.test.ifp, WLC_SET_BAND, WLC_BAND_2G) != WHD_SUCCESS) {
		printf("[RF Test] failed band\n");
		return -1;
	}
	if (tx) {
		/* TODO: check if safe for RX */
		uint32_t rate = get_rf_test_rspec(rftest_common.test.rateKbps);
		if (whd_wifi_set_iovar_value(rftest_common.test.ifp, IOVAR_STR_2G_RATE, rate) != WHD_SUCCESS) {
			printf("[RF Test] failed rate\n");
			return -1;
		}
	}

	whd_driver_t whd_driver = rftest_common.test.ifp->whd_driver;
	uint32_t chanspec_val = (uint32_t)CH20MHZ_CHSPEC(rftest_common.test.channel);
	uint32_t data = htod32(chanspec_val);
	if (whd_wifi_set_iovar_buffer(rftest_common.test.ifp, IOVAR_STR_CHANSPEC, &data, sizeof(data)) != WHD_SUCCESS) {
		printf("[RF Test] failed to set chanspec via buffer\n");
		return -1;
	}
	if (whd_wifi_set_ioctl_value(rftest_common.test.ifp, WLC_SET_SCANSUPPRESS, 1) != WHD_SUCCESS) {
		printf("[RF Test] failed scansuppress\n");
		return -1;
	}

	if (whd_wifi_set_up(rftest_common.test.ifp) != WHD_SUCCESS) {
		printf("[RF Test] failed wifi up\n");
		return -1;
	}

	if (whd_wifi_set_iovar_value(rftest_common.test.ifp, "phy_forcecal", 1) != WHD_SUCCESS) {
		printf("[RF Test] failed phy_forcecal\n");
		return -1;
	}
	if (whd_wifi_set_iovar_value(rftest_common.test.ifp, "phy_txpwrctrl", 1) != WHD_SUCCESS) {
		printf("[RF Test] failed phy_txpwrctrl\n");
		return -1;
	}

	wl_pkteng_t pkteng;
	if (tx) {
		uint32_t txpwr = ((uint32_t)rftest_common.test.powerDbm * 4u) | WL_TXPWR_OVERRIDE;
		if (whd_wifi_set_iovar_value(rftest_common.test.ifp, IOVAR_STR_QTXPOWER, txpwr) != WHD_SUCCESS) {
			printf("[RF Test] failed pwr\n");
			return -1;
		}

		pkteng = (wl_pkteng_t) {
			.flags = WL_PKTENG_PER_TX_START,
			.delay = rftest_common.test.txDelay,
			.length = rftest_common.test.txFrameLength,
			.nframes = rftest_common.test.txFrameCount,
			.dest.octet = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }
		};
	}
	else {
		pkteng = (wl_pkteng_t) {
			.flags = WL_PKTENG_PER_RX_START,
			.dest.octet = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }
		};
	}

	if (whd_wifi_set_iovar_buffer(rftest_common.test.ifp, "pkteng", &pkteng, sizeof(wl_pkteng_t)) != WHD_SUCCESS) {
		printf("[RF Test] failed pkteng\n");
		return -1;
	}

	return 0;
}


/* TLV ID for wlc-layer counters (wl_cnt_ver_30_t) in extended counter format */
#define WL_CNT_XTLV_WLC 0x100u

#define COUNTER_NOT_AVAILABLE UINT32_MAX

struct rxCounters {
	uint32_t rxframe;
	uint32_t rxbyte;
	uint32_t rxcrc;
	uint32_t rxbadfcs;
	uint32_t rxstrt;
	uint32_t rxerror;
	uint32_t pktengrxducast;
	uint32_t pktengrxdmcast;
};


static int rftest_extract_counters_tlv(const wl_cnt_info_t *cntInfo, struct rxCounters *counters)
{
	const uint8_t *tlvData = cntInfo->data;
	uint16_t remaining = cntInfo->datalen;

	while (remaining >= (uint16_t)sizeof(whd_xtlv_t)) {
		const whd_xtlv_t *tlv = (const whd_xtlv_t *)tlvData;
		/* TLV total size: header (4 bytes) + payload, aligned to 4 bytes */
		uint16_t tlvSize = (uint16_t)(((sizeof(whd_xtlv_t) - 1u + tlv->len) + 3u) & ~3u);

		if (tlv->id == WL_CNT_XTLV_WLC) {
			const wl_cnt_ver_30_t *cnt = (const wl_cnt_ver_30_t *)tlv->data;
			*counters = (struct rxCounters) {
				.rxframe = cnt->rxframe,
				.rxbyte = cnt->rxbyte,
				.rxcrc = cnt->rxcrc,
				.rxbadfcs = COUNTER_NOT_AVAILABLE,
				.rxstrt = COUNTER_NOT_AVAILABLE,
				.rxerror = cnt->rxerror,
				.pktengrxducast = COUNTER_NOT_AVAILABLE,
				.pktengrxdmcast = COUNTER_NOT_AVAILABLE,
			};
			return 0;
		}

		if (remaining < tlvSize) {
			break;
		}
		remaining -= tlvSize;
		tlvData += tlvSize;
	}
	return -1;
}

#define extract_rx_cnt(cnt, out) \
	(out)->rxframe = (cnt)->rxframe; \
	(out)->rxbyte = (cnt)->rxbyte; \
	(out)->rxcrc = (cnt)->rxcrc; \
	(out)->rxbadfcs = (cnt)->rxbadfcs; \
	(out)->rxstrt = (cnt)->rxstrt; \
	(out)->rxerror = (cnt)->rxerror; \
	(out)->pktengrxducast = (cnt)->pktengrxducast; \
	(out)->pktengrxdmcast = (cnt)->pktengrxdmcast;


static int rftest_rx_cnt_reset(void)
{
	// if (whd_wifi_set_iovar_void(rftest_common.test.ifp, IOVAR_STR_RESET_CNTS) != WHD_SUCCESS) {
	uint32_t value = 0;
	if (whd_wifi_get_iovar_value(rftest_common.test.ifp, IOVAR_STR_RESET_CNTS, &value) != WHD_SUCCESS) {
		printf("[RF Test] counter reset failed\n");
		return -1;
	}
	writeRspf("Reset invoked value=%u\n", value);
	return 0;
}


static int rftest_rx_cnt_get(void)
{
	union {
		wl_cnt_info_t info;
		wl_cnt_ver_six_t six;
		wl_cnt_ver_seven_t seven;
		wl_cnt_ver_eight_t eight;
		wl_cnt_ver_ten_t ten;
		uint8_t raw[1600];
	} buffer;

	_Static_assert(sizeof(buffer) == sizeof(buffer.raw), "Unexpected buffer size");

	if (whd_wifi_get_iovar_buffer(rftest_common.test.ifp, IOVAR_STR_COUNTERS, buffer.raw, sizeof(buffer.raw)) != WHD_SUCCESS) {
		printf("[RF Test] counter reading failed\n");
		return -1;
	}

	struct rxCounters counters = {
		.pktengrxducast = UINT32_MAX,
		.pktengrxdmcast = UINT32_MAX
	};
	switch (buffer.info.version) {
		case WL_CNT_EXT_T_VERSION:
			/* Extended TLV-encoded format */
			if (rftest_extract_counters_tlv(&buffer.info, &counters) < 0) {
				printf("[RF Test] WLC counters TLV not found\n");
				return -1;
			}
			break;
		case 6:
			extract_rx_cnt(&buffer.six, &counters);
			break;
		case 7:
			extract_rx_cnt(&buffer.seven, &counters);
			break;
		case 8:
			extract_rx_cnt(&buffer.eight, &counters);
			break;
		case 10:
			extract_rx_cnt(&buffer.ten, &counters);
			break;
		default:
			printf("[RF Test] unexpected counter version: %d\n", buffer.info.version);
			return -1;
	}
	return writeRspf(
			"rxframe=%u rxbyte=%u rxcrc=%u rxbadfcs=%u rxstrt=%u rxerror=%u pktengrxducast=%u pktengrxdmcast=%u\n",
			counters.rxframe, counters.rxbyte, counters.rxcrc,
			counters.rxbadfcs, counters.rxstrt, counters.rxerror,
			counters.pktengrxducast, counters.pktengrxdmcast);
}


static int rftest_start_cw(void)
{
	char fw_version[128];

	printf("[RF Test] start CW...\n");

	if (whd_wifi_get_wifi_version(rftest_common.test.ifp, fw_version, 128) != WHD_SUCCESS) {
		printf("[RF Test] failed to get firmware version\n");
		return -1;
	}
	printf("Wi-Fi Firmware Version: %s\n", fw_version);
	if (whd_wifi_set_down(rftest_common.test.ifp) != WHD_SUCCESS) {
		printf("[RF Test] failed wifi down\n");
		return -1;
	}
	if (whd_wifi_set_iovar_value(rftest_common.test.ifp, IOVAR_STR_MPC, 0) != WHD_SUCCESS) {
		printf("[RF Test] failed mcp down\n");
		return -1;
	}
	if (whd_wifi_set_iovar_value(rftest_common.test.ifp, "phy_watchdog", 0) != WHD_SUCCESS) {
		printf("[RF Test] failed mcp down\n");
		return -1;
	}
	if (whd_wifi_set_iovar_value(rftest_common.test.ifp, "glacial_timer", 0x7FFFFFFF) != WHD_SUCCESS) {
		printf("[RF Test] failed glacial_timer\n");
		return -1;
	}
	if (whd_wifi_set_ioctl_value(rftest_common.test.ifp, WLC_SET_BAND, WLC_BAND_2G) != WHD_SUCCESS) {
		printf("[RF Test] failed band\n");
		return -1;
	}
	whd_driver_t whd_driver = rftest_common.test.ifp->whd_driver;
	uint32_t chanspec_val = (uint32_t)CH20MHZ_CHSPEC(rftest_common.test.channel);
	uint32_t data = htod32(chanspec_val);
	if (whd_wifi_set_iovar_buffer(rftest_common.test.ifp, IOVAR_STR_CHANSPEC, &data, sizeof(data)) != WHD_SUCCESS) {
		printf("[RF Test] failed to set chanspec via buffer\n");
		return -1;
	}

	if (whd_wifi_set_ioctl_value(rftest_common.test.ifp, WLC_SET_SCANSUPPRESS, 1) != WHD_SUCCESS) {
		printf("[RF Test] failed scansuppress\n");
		return -1;
	}

	if (whd_wifi_set_up(rftest_common.test.ifp) != WHD_SUCCESS) {
		printf("[RF Test] failed wifi up\n");
		return -1;
	}

	uint32_t txpwr = ((uint32_t)rftest_common.test.powerDbm * 4u) | WL_TXPWR_OVERRIDE;
	if (whd_wifi_set_iovar_value(rftest_common.test.ifp, IOVAR_STR_QTXPOWER, txpwr) != WHD_SUCCESS) {
		printf("[RF Test] failed pwr\n");
		return -1;
	}

	if (whd_wifi_set_ioctl_value(rftest_common.test.ifp, WLC_FREQ_ACCURACY, 1) != WHD_SUCCESS) {
		printf("[RF Test] failed faccuracy\n");
		return -1;
	}

	return 0;
}


static int rftest_stop_cw(void)
{
	if (whd_wifi_set_ioctl_value(rftest_common.test.ifp, WLC_FREQ_ACCURACY, 0) != WHD_SUCCESS) {
		printf("[RF Test] failed fqaccuracy\n");
		return -1;
	}

	return 0;
}


static int rftest_dev_open(int flags)
{
	(void)flags;
	mutexLock(rftest_common.test.lock);

	if (rftest_common.test.busy) {
		mutexUnlock(rftest_common.test.lock);
		return -EBUSY;
	}

	rftest_common.test.busy = true;
	mutexUnlock(rftest_common.test.lock);
	return 0;
}


static int rftest_dev_close(void)
{
	if (!rftest_common.test.busy) {
		return -EBADF;
	}
	rftest_common.test.busy = false;
	return 0;
}


static int rftest_dev_read(char *data, size_t size, off_t offset)
{
	if (offset > rftest_common.test.len) {
		return -ERANGE;
	}
	size_t cnt = min(size, (size_t)(rftest_common.test.len - offset));
	memcpy(data, rftest_common.test.buf + offset, cnt);
	return cnt;
}


#define CHECK_FIXED_CMD(data, size, cmd) (((size) == CONST_STRLEN(cmd)) && (strncmp((cmd), (data), (size)) == 0))

static inline bool checkCmd(const char *data, size_t dataLen, const char *cmd, size_t cmdLen, char *args)
{
	memset(args, 0, 32);
	if (dataLen < cmdLen) {
		return false;
	}
	if (strncmp(cmd, data, cmdLen) != 0) {
		return false;
	}
	if (dataLen - cmdLen >= 32) {
		return false;
	}
	memcpy(args, data + cmdLen, dataLen - cmdLen);
	return true;
}


#define CHECK_ARGS_CMD(data, size, cmd, args) checkCmd((data), (size), (cmd), CONST_STRLEN(cmd), (args))

static inline int parseArgInt(const char *args, const char *name, int min, int max, int *out)
{
	int endPos = 0;
	int value = 0;
	if ((sscanf(args, "%d%n", &value, &endPos) != 1) || (args[endPos] != '\0')) {
		return -EINVAL;
	}
	if ((value < min) || (value > max)) {
		writeRspf("invalid value for %s: %d\n", name, value);
		return -EINVAL;
	}
	writeRspf("%s set to %d\n", name, value);
	*out = value;
	return 0;
}


static inline int parseArgFloat(const char *args, const char *name, float min, float max, float *out)
{
	int endPos = 0;
	float value = 0;
	if ((sscanf(args, "%f%n", &value, &endPos) != 1) || (args[endPos] != '\0')) {
		return -EINVAL;
	}
	if ((value < min) || (value > max)) {
		writeRspf("invalid value for %s: %f\n", name, value);
		return -EINVAL;
	}
	*out = value;
	return 0;
}


static int rftest_dev_write(const char *data, size_t size)
{
	const size_t inputSize = size;

	/* discard previous response */
	rftest_common.test.len = 0;
	char args[32];

	/* Command: init */
	if (CHECK_FIXED_CMD(data, size, "init")) {
		if (rftest_common.test.initialized) {
			printf("[RF Test] already initialized\n");
			return -EINVAL;
		}

		cy_rslt_t result = cybsp_init();
		if (result != CY_RSLT_SUCCESS) {
			printf("[RF Test] failed to init HW\n");
			return -EIO;
		}

		result = cybsp_wifi_init_primary(&rftest_common.test.ifp);
		if (result != CY_RSLT_SUCCESS) {
			printf("[RF Test] failed to init WiFi\n");
			cybsp_free();
			return -EIO;
		}

		rftest_common.test.initialized = true;
		wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, "[RF Test] initialized\n");
	}
	else if (CHECK_FIXED_CMD(data, size, "status")) {
		statusRsp();
	}
	else if (CHECK_FIXED_CMD(data, size, "tx start")) {
		rftest_start_xx(true, 1000);
	}
	else if (CHECK_FIXED_CMD(data, size, "tx stop")) {
		rftest_stop_xx();
	}
	else if (CHECK_FIXED_CMD(data, size, "rx start")) {
		rftest_start_xx(false, 0);
	}
	else if (CHECK_FIXED_CMD(data, size, "rx stop")) {
		rftest_stop_xx();
	}
	else if (CHECK_FIXED_CMD(data, size, "rx cnt")) {
		rftest_rx_cnt_get();
	}
	else if (CHECK_FIXED_CMD(data, size, "rx cnt reset")) {
		rftest_rx_cnt_reset();
	}
	else if (CHECK_FIXED_CMD(data, size, "cw start")) {
		rftest_start_cw();
	}
	else if (CHECK_FIXED_CMD(data, size, "cw stop")) {
		rftest_stop_cw();
	}
	else if (CHECK_ARGS_CMD(data, size, "set channel ", args)) {
		int value = 0;
		if (parseArgInt(args, "channel", 1, 13, &value) < 0) {
			return -EINVAL;
		}
		rftest_common.test.channel = (uint8_t)value;
	}
	else if (CHECK_ARGS_CMD(data, size, "set txDelay ", args)) {
		int value = 0;
		if (parseArgInt(args, "txDelay", 0, 500, &value) < 0) {
			return -EINVAL;
		}
		rftest_common.test.txDelay = value;
	}
	else if (CHECK_ARGS_CMD(data, size, "set txFrameCount ", args)) {
		int value = 0;
		if (parseArgInt(args, "txFrameCount", 0, 100000, &value) < 0) {
			return -EINVAL;
		}
		rftest_common.test.txFrameCount = value;
	}
	else if (CHECK_ARGS_CMD(data, size, "set txFrameLength ", args)) {
		int value = 0;
		if (parseArgInt(args, "txFrameLength", 0, (UINT32_MAX < INT_MAX) ? UINT32_MAX : INT_MAX, &value) < 0) {
			return -EINVAL;
		}
		rftest_common.test.txFrameLength = value;
	}
	else if (CHECK_ARGS_CMD(data, size, "set rate ", args)) {
		float rate = 0.0f;
		if (parseArgFloat(args, "rate", 0.0f, 127.0f, &rate) < 0) {
			return -EINVAL;
		}
		/* round to nearst 0.5 Mbps */
		rftest_common.test.rateKbps = roundf(rate * 2.0f) * 500;
	}
	else if (CHECK_ARGS_CMD(data, size, "set power ", args)) {
		int pwr = 0;
		if (parseArgInt(args, "power", 0, 30, &pwr) < 0) {
			return -EINVAL;
		}
		rftest_common.test.powerDbm = (uint8_t)pwr;
	}
	else {
		printf("[RF Test] unknown command: %.*s\n", (int)size, data);
		return -EINVAL;
	}
	return inputSize;
}


void rftest_handleCtrl(msg_t *msg)
{
	switch (msg->type) {
		case mtOpen:
			msg->o.err = rftest_dev_open(msg->i.openclose.flags);
			break;

		case mtClose:
			msg->o.err = rftest_dev_close();
			break;

		case mtRead:
			msg->o.err = rftest_dev_read(msg->o.data, msg->o.size, msg->i.io.offs);
			break;

		case mtWrite:
			msg->o.err = rftest_dev_write(msg->i.data, msg->i.size);
			break;

		default:
			msg->o.err = -EOPNOTSUPP;
			break;
	}
	fflush(stdout);
	return;
}


int rftest_init(void)
{
	int err;
	rftest_common.test.lock = -1;
	rftest_common.test.initialized = false;
	rftest_common.test.busy = false;
	rftest_common.test.ifp = NULL;
	rftest_common.test.channel = 1u;
	rftest_common.test.rateKbps = 1000;
	rftest_common.test.powerDbm = 15u;
	rftest_common.test.txFrameCount = 0;
	rftest_common.test.txFrameLength = 64;
	rftest_common.test.txDelay = 20;

	err = mutexCreate(&rftest_common.test.lock);
	if (err < 0) {
		printf("[RF Test] failed to create lock\n");
		return err;
	}

	return 0;
}
