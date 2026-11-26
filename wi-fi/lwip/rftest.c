/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP Wi-Fi RF Test Application
 *
 * Copyright 2026 Phoenix Systems
 * Author: Katarzyna Wojciechowska, Jan Wisniewski
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/minmax.h>
#include <sys/msg.h>

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
#include "cmd.h"
#include "rftest.h"


/* longest command accepted, with the NUL */
#define RFTEST_CMD_MAX 64U

/* largest 802.11 MSDU */
#define RFTEST_FRAME_LEN_MAX 2304

/* default regulatory domain: the certification is done in Poland */
#define RFTEST_COUNTRY_DEFAULT "PL"

/* TLV ID for wlc-layer counters (wl_cnt_ver_30_t) in extended counter format */
#define WL_CNT_XTLV_WLC 0x100U

#define COUNTER_NOT_AVAILABLE UINT32_MAX

/* copies the RX counters (in dongle byte order) from any of the fixed-layout counter versions */
#define RFTEST_RX_CNT_COPY(cnt, out) \
	do { \
		(out)->rxframe = dtoh32((cnt)->rxframe); \
		(out)->rxbyte = dtoh32((cnt)->rxbyte); \
		(out)->rxcrc = dtoh32((cnt)->rxcrc); \
		(out)->rxbadfcs = dtoh32((cnt)->rxbadfcs); \
		(out)->rxstrt = dtoh32((cnt)->rxstrt); \
		(out)->rxerror = dtoh32((cnt)->rxerror); \
		(out)->pktengrxducast = dtoh32((cnt)->pktengrxducast); \
		(out)->pktengrxdmcast = dtoh32((cnt)->pktengrxdmcast); \
	} while (0)


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


/* passed to the command handlers */
struct cmdData {
	bool wifiRunning;
};


static struct {
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
	char country[3]; /* ISO 3166 alpha-2 or a firmware-specific code */
	uint16_t countryRev;
} common;


static int vrsp(const char *format, va_list ap)
{
	int ret = vsnprintf(common.buf, sizeof(common.buf), format, ap);

	if (ret < 0) {
		return ret;
	}

	if ((size_t)ret >= sizeof(common.buf)) {
		return -EFBIG;
	}

	common.len = ret;
	return 0;
}


/* sets the response read back from the device */
static int rsp(const char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = vrsp(format, ap);
	va_end(ap);

	return ret;
}


/* sets the response and logs it as an error */
static void rspError(const char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = vrsp(format, ap);
	va_end(ap);

	if (ret == 0) {
		fprintf(stderr, "rftest: %s", common.buf);
	}
}


static int statusRsp(const cmdCtx_t *ctx)
{
	(void)ctx;
	return rsp("%s\nchannel=%u rate=%.1f power=%u country=%s/%u\n", common.initialized ? "ready" : "not initialized",
			common.channel, common.rateKbps / 1000.0f, common.powerDbm, common.country, common.countryRev);
}


/* 802.11n MCS 0-7 rates (20 MHz, long GI), the index is the MCS */
static const uint32_t htRates[] = { 6500, 13000, 19500, 26000, 39000, 52000, 58500, 65000 };

/* 802.11b/g rates */
static const uint32_t legacyRates[] = { 1000, 2000, 5500, 6000, 9000, 11000, 12000, 18000, 24000, 36000, 48000, 54000 };


static bool rateValid(uint32_t rateKbps)
{
	for (size_t idx = 0; idx < (sizeof(htRates) / sizeof(htRates[0])); idx++) {
		if (rateKbps == htRates[idx]) {
			return true;
		}
	}

	for (size_t idx = 0; idx < (sizeof(legacyRates) / sizeof(legacyRates[0])); idx++) {
		if (rateKbps == legacyRates[idx]) {
			return true;
		}
	}

	return false;
}


static uint32_t rspec(uint32_t rateKbps)
{
	uint32_t legacyVal;

	for (size_t idx = 0; idx < (sizeof(htRates) / sizeof(htRates[0])); idx++) {
		if (rateKbps == htRates[idx]) {
			return WL_RSPEC_BW_20MHZ | WL_RSPEC_ENCODE_HT | idx;
		}
	}

	/* legacy rates are encoded in 500 kbps units */
	legacyVal = rateKbps / 500U;
	return WL_RSPEC_BW_20MHZ | WL_RSPEC_ENCODE_RATE | (legacyVal & WL_RSPEC_RATE_MASK);
}


static int stopPkteng(const cmdCtx_t *ctx)
{
	wl_pkteng_t pkteng = {
		.flags = htod32(WL_PKTENG_PER_TX_STOP),
	};

	(void)ctx;

	if (whd_wifi_set_iovar_buffer(common.ifp, "pkteng", &pkteng, sizeof(wl_pkteng_t)) != WHD_SUCCESS) {
		rspError("failed pkteng stop\n");
		return -EIO;
	}

	return 0;
}


static int prepare(void)
{
	char fwVersion[128];
	whd_driver_t whd_driver = common.ifp->whd_driver; /* used by CH20MHZ_CHSPEC() */
	wl_country_t country = { 0 };
	uint32_t chanspec;
	uint32_t txpwr;

	if (whd_wifi_get_wifi_version(common.ifp, fwVersion, sizeof(fwVersion)) != WHD_SUCCESS) {
		rspError("failed to get firmware version\n");
		return -EIO;
	}
	printf("rftest: firmware version: %s\n", fwVersion);

	if (whd_wifi_set_down(common.ifp) != WHD_SUCCESS) {
		rspError("failed wifi down\n");
		return -EIO;
	}
	if (whd_wifi_set_iovar_value(common.ifp, IOVAR_STR_MPC, 0) != WHD_SUCCESS) {
		rspError("failed mpc down\n");
		return -EIO;
	}
	if (whd_wifi_set_iovar_value(common.ifp, "phy_watchdog", 0) != WHD_SUCCESS) {
		rspError("failed phy_watchdog\n");
		return -EIO;
	}
	if (whd_wifi_set_iovar_value(common.ifp, "glacial_timer", 0x7fffffffU) != WHD_SUCCESS) {
		rspError("failed glacial_timer\n");
		return -EIO;
	}

	/* WLC_SET_COUNTRY with a 4-byte value is read as a country string, so the revision needs the full struct */
	(void)memcpy(country.country_abbrev, common.country, 2);
	(void)memcpy(country.ccode, common.country, 2);
	/* like WHD: revision -1 lets the firmware pick the one configured for the country */
	country.rev = (int32_t)htod32((common.countryRev == 0U) ? -1 : (int32_t)common.countryRev);
	if (whd_wifi_set_iovar_buffer(common.ifp, IOVAR_STR_COUNTRY, &country, sizeof(country)) != WHD_SUCCESS) {
		rspError("failed set country\n");
		return -EIO;
	}

	if (whd_wifi_set_ioctl_value(common.ifp, WLC_SET_BAND, WLC_BAND_2G) != WHD_SUCCESS) {
		rspError("failed band\n");
		return -EIO;
	}

	if (whd_wifi_set_iovar_value(common.ifp, IOVAR_STR_2G_RATE, rspec(common.rateKbps)) != WHD_SUCCESS) {
		rspError("failed rate=%u\n", common.rateKbps);
		return -EIO;
	}

	chanspec = htod32((uint32_t)CH20MHZ_CHSPEC(common.channel));
	if (whd_wifi_set_iovar_buffer(common.ifp, IOVAR_STR_CHANSPEC, &chanspec, sizeof(chanspec)) != WHD_SUCCESS) {
		rspError("failed to set chanspec\n");
		return -EIO;
	}
	if (whd_wifi_set_ioctl_value(common.ifp, WLC_SET_SCANSUPPRESS, 1) != WHD_SUCCESS) {
		rspError("failed scansuppress\n");
		return -EIO;
	}

	if (whd_wifi_set_up(common.ifp) != WHD_SUCCESS) {
		rspError("failed wifi up\n");
		return -EIO;
	}

	if (whd_wifi_set_iovar_value(common.ifp, "phy_forcecal", 1) != WHD_SUCCESS) {
		rspError("failed phy_forcecal\n");
		return -EIO;
	}
	if (whd_wifi_set_iovar_value(common.ifp, "phy_txpwrctrl", 1) != WHD_SUCCESS) {
		rspError("failed phy_txpwrctrl\n");
		return -EIO;
	}

	/* reset the TX power limit before overriding it */
	if (whd_wifi_set_iovar_value(common.ifp, IOVAR_STR_QTXPOWER, 127) != WHD_SUCCESS) {
		rspError("failed txpwr reset\n");
		return -EIO;
	}

	/* qtxpower is in quarter dBm units */
	txpwr = ((uint32_t)common.powerDbm * 4U) | WL_TXPWR_OVERRIDE;
	if (whd_wifi_set_iovar_value(common.ifp, IOVAR_STR_QTXPOWER, txpwr) != WHD_SUCCESS) {
		rspError("failed pwr\n");
		return -EIO;
	}

	return 0;
}


/* https://community.murata.com/s/article/Drill-down-Test-Environment-Setup-to-Calculate-Number-of-Packets-on-Receiver-Side */
static int startTx(const cmdCtx_t *ctx)
{
	wl_pkteng_t pkteng = {
		.flags = htod32(WL_PKTENG_PER_TX_START),
		.delay = htod32(common.txDelay),
		.length = htod32(common.txFrameLength),
		.nframes = htod32(common.txFrameCount),
		.dest.octet = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }
	};

	(void)ctx;

	printf("rftest: start TX\n");
	if (prepare() < 0) {
		return -EIO;
	}

	if (whd_wifi_set_iovar_buffer(common.ifp, "pkteng", &pkteng, sizeof(wl_pkteng_t)) != WHD_SUCCESS) {
		rspError("failed pkteng\n");
		return -EIO;
	}

	return 0;
}


static int startRx(const cmdCtx_t *ctx)
{
	wl_pkteng_t pkteng = {
		.flags = htod32(WL_PKTENG_PER_RX_START),
		.dest.octet = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }
	};

	(void)ctx;

	printf("rftest: start RX\n");
	if (prepare() < 0) {
		return -EIO;
	}

	if (whd_wifi_set_iovar_buffer(common.ifp, "pkteng", &pkteng, sizeof(wl_pkteng_t)) != WHD_SUCCESS) {
		rspError("failed pkteng\n");
		return -EIO;
	}

	return 0;
}


static int countersFromTlv(const wl_cnt_info_t *cntInfo, size_t bufLen, struct rxCounters *counters)
{
	const uint8_t *tlvData = cntInfo->data;
	size_t remaining = min((size_t)dtoh16(cntInfo->datalen), bufLen - offsetof(wl_cnt_info_t, data));
	const size_t hdrLen = offsetof(whd_xtlv_t, data);

	while (remaining >= hdrLen) {
		const whd_xtlv_t *tlv = (const whd_xtlv_t *)tlvData;
		size_t payloadLen = dtoh16(tlv->len);
		/* TLVs are padded to 4 bytes */
		size_t tlvSize = (hdrLen + payloadLen + 3U) & ~(size_t)3U;

		if ((hdrLen + payloadLen) > remaining) {
			break;
		}

		if (dtoh16(tlv->id) == WL_CNT_XTLV_WLC) {
			const wl_cnt_ver_30_t *cnt = (const wl_cnt_ver_30_t *)tlv->data;

			if (payloadLen < sizeof(*cnt)) {
				break;
			}

			*counters = (struct rxCounters) {
				.rxframe = dtoh32(cnt->rxframe),
				.rxbyte = dtoh32(cnt->rxbyte),
				.rxcrc = dtoh32(cnt->rxcrc),
				.rxbadfcs = COUNTER_NOT_AVAILABLE,
				.rxstrt = COUNTER_NOT_AVAILABLE,
				.rxerror = dtoh32(cnt->rxerror),
				.pktengrxducast = COUNTER_NOT_AVAILABLE,
				.pktengrxdmcast = COUNTER_NOT_AVAILABLE,
			};
			return 0;
		}

		if (tlvSize >= remaining) {
			break;
		}
		remaining -= tlvSize;
		tlvData += tlvSize;
	}

	return -1;
}


static int cntReset(const cmdCtx_t *ctx)
{
	/* FW requires GET operation for counter reset, returned value is not important (and not documented) */
	uint32_t value = 0;

	(void)ctx;

	if (whd_wifi_get_iovar_value(common.ifp, IOVAR_STR_RESET_CNTS, &value) != WHD_SUCCESS) {
		rspError("counter reset failed\n");
		return -EIO;
	}

	return 0;
}


static int cntGet(const cmdCtx_t *ctx)
{
	union {
		wl_cnt_info_t info;
		wl_cnt_ver_six_t six;
		wl_cnt_ver_seven_t seven;
		wl_cnt_ver_eight_t eight;
		wl_cnt_ver_ten_t ten;
		uint8_t raw[1600];
	} buffer;
	struct rxCounters counters = {
		.pktengrxducast = COUNTER_NOT_AVAILABLE,
		.pktengrxdmcast = COUNTER_NOT_AVAILABLE,
	};

	(void)ctx;

	_Static_assert(sizeof(buffer) == sizeof(buffer.raw), "Unexpected buffer size");

	if (whd_wifi_get_iovar_buffer(common.ifp, IOVAR_STR_COUNTERS, buffer.raw, sizeof(buffer.raw)) != WHD_SUCCESS) {
		rspError("counter reading failed\n");
		return -EIO;
	}

	switch (dtoh16(buffer.info.version)) {
		case WL_CNT_EXT_T_VERSION:
			/* Extended TLV-encoded format */
			if (countersFromTlv(&buffer.info, sizeof(buffer), &counters) < 0) {
				rspError("WLC counters TLV not found\n");
				return -EIO;
			}
			break;
		case 6:
			RFTEST_RX_CNT_COPY(&buffer.six, &counters);
			break;
		case 7:
			RFTEST_RX_CNT_COPY(&buffer.seven, &counters);
			break;
		case 8:
			RFTEST_RX_CNT_COPY(&buffer.eight, &counters);
			break;
		case 10:
			RFTEST_RX_CNT_COPY(&buffer.ten, &counters);
			break;
		default:
			rspError("unexpected counter version: %u\n", dtoh16(buffer.info.version));
			return -EIO;
	}

	return rsp(
			"rxframe=%u rxbyte=%u rxcrc=%u rxbadfcs=%u rxstrt=%u rxerror=%u pktengrxducast=%u pktengrxdmcast=%u\n",
			counters.rxframe, counters.rxbyte, counters.rxcrc,
			counters.rxbadfcs, counters.rxstrt, counters.rxerror,
			counters.pktengrxducast, counters.pktengrxdmcast);
}


static int startCw(const cmdCtx_t *ctx)
{
	(void)ctx;

	printf("rftest: start CW\n");
	if (prepare() < 0) {
		return -EIO;
	}

	if (whd_wifi_set_ioctl_value(common.ifp, WLC_FREQ_ACCURACY, common.channel) != WHD_SUCCESS) {
		rspError("failed faccuracy\n");
		return -EIO;
	}

	return 0;
}


static int stopCw(const cmdCtx_t *ctx)
{
	(void)ctx;

	if (whd_wifi_set_ioctl_value(common.ifp, WLC_FREQ_ACCURACY, 0) != WHD_SUCCESS) {
		rspError("failed to stop CW 'set fqaccuracy 0'\n");
		return -EIO;
	}

	return 0;
}


static int hwInit(const cmdCtx_t *ctx)
{
	const struct cmdData *data = ctx->userData;
	cy_rslt_t result;

	if (common.initialized) {
		rspError("already initialized\n");
		return -EALREADY;
	}

	/* both use the same SDIO bus and chip */
	if (data->wifiRunning) {
		rspError("Wi-Fi is on, turn it off first\n");
		return -EBUSY;
	}

	result = cybsp_init();
	if (result != CY_RSLT_SUCCESS) {
		rspError("failed to init HW\n");
		return -EIO;
	}

	result = cybsp_wifi_init_primary(&common.ifp);
	if (result != CY_RSLT_SUCCESS) {
		rspError("failed to init WiFi\n");
		cybsp_free();
		return -EIO;
	}

	common.initialized = true;
	wm_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, "rftest: initialized\n");

	return 0;
}


static int hwDeinit(const cmdCtx_t *ctx)
{
	(void)ctx;

	if (common.initialized) {
		(void)cybsp_wifi_deinit(common.ifp);
		cybsp_free();
		common.ifp = NULL;
		common.initialized = false;
	}

	return 0;
}


static int devOpen(void)
{
	if (common.busy) {
		return -EBUSY;
	}

	common.busy = true;
	return 0;
}


static int devClose(void)
{
	if (!common.busy) {
		return -EBADF;
	}

	common.busy = false;
	return 0;
}


static int devRead(char *data, size_t size, off_t offset)
{
	size_t cnt;

	if ((offset < 0) || (offset > common.len)) {
		return -ERANGE;
	}

	cnt = min(size, (size_t)(common.len - offset));
	memcpy(data, common.buf + offset, cnt);

	return (int)cnt;
}


/* parses the integer argument of a "set" command */
static int parseInt(const cmdCtx_t *ctx, int minVal, int maxVal, int *out)
{
	int endPos = 0;
	int value = 0;

	if ((sscanf(ctx->args, "%d%n", &value, &endPos) != 1) || (ctx->args[endPos] != '\0') || (value < minVal) || (value > maxVal)) {
		rspError("invalid value for %s: %s\n", ctx->name, ctx->args);
		return -EINVAL;
	}

	*out = value;

	return 0;
}


/* parses the number argument of a "set" command */
static int parseFloat(const cmdCtx_t *ctx, float minVal, float maxVal, float *out)
{
	int endPos = 0;
	float value = 0.0f;

	if ((sscanf(ctx->args, "%f%n", &value, &endPos) != 1) || (ctx->args[endPos] != '\0') || (value < minVal) || (value > maxVal)) {
		rspError("invalid value for %s: %s\n", ctx->name, ctx->args);
		return -EINVAL;
	}

	*out = value;

	return 0;
}


static int setChannel(const cmdCtx_t *ctx)
{
	int value = 0;

	if (parseInt(ctx, 1, 13, &value) < 0) {
		return -EINVAL;
	}
	common.channel = (uint8_t)value;

	return 0;
}


static int setTxDelay(const cmdCtx_t *ctx)
{
	int value = 0;

	if (parseInt(ctx, 0, 500, &value) < 0) {
		return -EINVAL;
	}
	common.txDelay = (uint32_t)value;

	return 0;
}


static int setTxFrameCount(const cmdCtx_t *ctx)
{
	int value = 0;

	/* 0 transmits until "tx stop" */
	if (parseInt(ctx, 0, 100000, &value) < 0) {
		return -EINVAL;
	}
	common.txFrameCount = (uint32_t)value;

	return 0;
}


static int setTxFrameLength(const cmdCtx_t *ctx)
{
	int value = 0;

	if (parseInt(ctx, 0, RFTEST_FRAME_LEN_MAX, &value) < 0) {
		return -EINVAL;
	}
	common.txFrameLength = (uint32_t)value;

	return 0;
}


static int setRate(const cmdCtx_t *ctx)
{
	float rate = 0.0f;

	if (parseFloat(ctx, 1.0f, 65.0f, &rate) < 0) {
		return -EINVAL;
	}

	/* round to nearest 0.5 Mbps, enough to tell all supported rates apart */
	uint32_t rateKbps = (uint32_t)roundf(rate * 2.0f) * 500U;
	if (!rateValid(rateKbps)) {
		rspError("invalid value for %s: %s (not an 802.11b/g rate or MCS 0-7 rate)\n", ctx->name, ctx->args);
		return -EINVAL;
	}
	common.rateKbps = rateKbps;

	return 0;
}


static int setPower(const cmdCtx_t *ctx)
{
	int value = 0;

	if (parseInt(ctx, 0, 30, &value) < 0) {
		return -EINVAL;
	}
	common.powerDbm = (uint8_t)value;

	return 0;
}


/* "CC" or "CC/REV", where CC is a 2-character upper-case country code (e.g. "PL", "E0/895") */
static int setCountry(const cmdCtx_t *ctx)
{
	const char *args = ctx->args;
	int endPos = 0;
	unsigned int rev = 0;

	if (!(isupper((unsigned char)args[0]) || isdigit((unsigned char)args[0])) ||
			!(isupper((unsigned char)args[1]) || isdigit((unsigned char)args[1]))) {
		rspError("invalid value for %s: %s\n", ctx->name, args);
		return -EINVAL;
	}

	if (args[2] == '/') {
		if ((sscanf(&args[3], "%u%n", &rev, &endPos) != 1) || (args[3 + endPos] != '\0') || (rev > UINT16_MAX)) {
			rspError("invalid value for %s: %s\n", ctx->name, args);
			return -EINVAL;
		}
	}
	else if (args[2] != '\0') {
		rspError("invalid value for %s: %s\n", ctx->name, args);
		return -EINVAL;
	}
	else {
		/* no revision */
	}

	common.country[0] = args[0];
	common.country[1] = args[1];
	common.country[2] = '\0';
	common.countryRev = (uint16_t)rev;

	return 0;
}


static const cmd_t cmds[] = {
	{ "reset", hwDeinit },
	{ "init", hwInit },
	{ "status", statusRsp },
	{ "set channel", setChannel, CMD_ARGS_REQUIRED },
	{ "set txDelay", setTxDelay, CMD_ARGS_REQUIRED },
	{ "set txFrameCount", setTxFrameCount, CMD_ARGS_REQUIRED },
	{ "set txFrameLength", setTxFrameLength, CMD_ARGS_REQUIRED },
	{ "set rate", setRate, CMD_ARGS_REQUIRED },
	{ "set power", setPower, CMD_ARGS_REQUIRED },
	{ "set country", setCountry, CMD_ARGS_REQUIRED },
};


/* commands that need the chip initialized */
static const cmd_t chipCmds[] = {
	{ "tx start", startTx },
	{ "tx stop", stopPkteng },
	{ "rx start", startRx },
	{ "rx stop", stopPkteng },
	{ "rx cnt", cntGet },
	{ "rx cnt reset", cntReset },
	{ "cw start", startCw },
	{ "cw stop", stopCw },
};


static int devWrite(const char *data, size_t size, bool wifiRunning)
{
	const size_t inputSize = size;
	struct cmdData cmdData = { .wifiRunning = wifiRunning };
	cmdCtx_t ctx = { .userData = &cmdData };
	char line[RFTEST_CMD_MAX];
	const cmd_t *cmd;
	int err;

	/* discard previous response */
	common.len = 0;

	data = cmd_trim(data, &size);
	if (size >= sizeof(line)) {
		rspError("command too long\n");
		return -EINVAL;
	}

	/* handlers get NUL-terminated args */
	(void)memcpy(line, data, size);
	line[size] = '\0';

	cmd = cmd_find(cmds, sizeof(cmds) / sizeof(cmds[0]), line, size, &ctx);
	if (cmd == NULL) {
		cmd = cmd_find(chipCmds, sizeof(chipCmds) / sizeof(chipCmds[0]), line, size, &ctx);
		if (cmd == NULL) {
			rspError("unknown command: %s\n", line);
			return -EINVAL;
		}

		if (!common.initialized) {
			rspError("not initialized\n");
			return -ENODEV;
		}
	}

	err = cmd->handler(&ctx);

	return (err < 0) ? err : (int)inputSize;
}


bool rftest_isInitialized(void)
{
	return common.initialized;
}


void rftest_handleCtrl(msg_t *msg, bool wifiRunning)
{
	switch (msg->type) {
		case mtOpen:
			msg->o.err = devOpen();
			break;

		case mtClose:
			msg->o.err = devClose();
			break;

		case mtRead:
			msg->o.err = devRead(msg->o.data, msg->o.size, msg->i.io.offs);
			break;

		case mtWrite:
			msg->o.err = devWrite(msg->i.data, msg->i.size, wifiRunning);
			break;

		default:
			msg->o.err = -EOPNOTSUPP;
			break;
	}

	(void)fflush(stdout);
}


void rftest_init(void)
{
	common.initialized = false;
	common.busy = false;
	common.len = 0;
	common.ifp = NULL;
	common.channel = 1U;
	common.rateKbps = 1000U;
	common.powerDbm = 15U;
	common.txFrameCount = 0U;
	common.txFrameLength = 64U;
	common.txDelay = 20U;
	(void)memcpy(common.country, RFTEST_COUNTRY_DEFAULT, sizeof(common.country));
	common.countryRev = 0U;
}
