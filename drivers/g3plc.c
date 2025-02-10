/*
 * Phoenix-RTOS --- networking stack
 *
 * G3-PLC Adaptation Layer opts
 *
 * Copyright 2025 Phoenix Systems
 *
 * %LICENSE%
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/threads.h>

#include <ps_g3_sap.h>
#include <ps_g3_sap_dl_msgcli.h>
#include <ps_g3_mac_types.h>

#include <sys/list.h>
#include <sys/msg.h>
#include <posix/utils.h>
#include <lowpan6_g3.h>
#include <g3plc.h>
#include <lbp_g3.h>
#include "netif-driver.h"
#include <ps_g3_sap_dl_uart.h>
#include <g3_adp_common.h>

struct g3plc_data_request {
	struct g3plc_data_request *prev, *next;
	ps_g3_mcps_data_request_t req;
	struct lowpan6_link_addr dest;
	struct netif *netif;
	struct pbuf *pbuf;
	u8_t hwaddr[8];
};

struct g3adp_ctl {
	enum { g3adp_set,
		g3adp_get,
		g3adp_test } type;
	char name[32];
};

static struct {
	uint8_t rxstack[1024] __attribute__((aligned(16)));
	uint8_t txstack[1024] __attribute__((aligned(16)));
	uint8_t msgstack[1024] __attribute__((aligned(16)));
	struct netif *netif;
	ps_g3_sap_t sap;
	handle_t reqsLock, mcpsLock, mlmeLock;
	handle_t mcpsCond, reqsCond, mlmeCond;
	volatile int mcpsStatus;
	volatile int mlmeStatus;
	char mlmeGetData[32];
	uint8_t hwaddr[8];
	struct g3plc_data_request *reqs;
	u8_t devType;
	u8_t noauto;
	unsigned port;
} g3plc_priv;

/* TODO: move it to lbp_g3.c */
static struct {
	int is_active;
	struct {
		struct g3plc_scan_entry *entries;
		int size, elements;
	} buf;
} scan = { 0 };

#define ERROR_LOG(...) \
	{ \
		printf(__VA_ARGS__); \
	}

#define DEBUG_LOG(...) \
	{ \
		printf(__VA_ARGS__); \
	}

static void *be_memcpy(void *dest, const void *src, size_t n)
{
	uint8_t *d = dest;
	const uint8_t *s = (const uint8_t *)src + n - 1;
	while (n-- > 0) {
		*d++ = *s--;
	}
	return dest;
}


static struct macMibValue setup_nb_table(ps_g3_mac_nb_entry_t *nb_entry)
{
	struct macMibValue value;
	uint8_t *ptr = (uint8_t *)value.data;

	*ptr++ = nb_entry->short_address && 0xff;
	*ptr++ = (nb_entry->short_address >> 8) & 0xff;
	memcpy(ptr, nb_entry->tone_map.tm, sizeof(nb_entry->tone_map));
	ptr += sizeof(ps_g3_phy_tone_map_t);
	*ptr++ = nb_entry->tone_actives;
	memcpy(ptr, nb_entry->tx_coef, 6);
	ptr += 6;
	*ptr++ = nb_entry->tx_res;
	*ptr++ = nb_entry->tx_gain;
	*ptr++ = nb_entry->mod_type;
	*ptr++ = nb_entry->mod_scheme;
	*ptr++ = nb_entry->phase_diff;
	*ptr++ = nb_entry->lqi;
	*ptr++ = nb_entry->tmr_valid_time & 0xff;
	*ptr++ = (nb_entry->tmr_valid_time >> 8) & 0xff;

	value.length = ptr - value.data;

	return value;
}


static const char *status_to_str(enum macStatus status)
{
	struct {
		uint8_t id;
		const char *str;
	} label[] = {
		{ .id = 0x00, .str = "MAC_STATUS_SUCCESS" },
		{ .id = 0x80, .str = "MAC_STATUS_ALTERNATE_PANID_DETECTION" },
		{ .id = 0xdb, .str = "MAC_STATUS_COUNTER_ERROR" },
		{ .id = 0xdc, .str = "MAC_STATUS_IMPROPER_KEY_TYPE" },
		{ .id = 0xdd, .str = "MAC_STATUS_IMPROPER_SECURITY_LEVEL" },
		{ .id = 0xde, .str = "MAC_STATUS_UNSUPPORTED_LEGACY" },
		{ .id = 0xdf, .str = "MAC_STATUS_UNSUPPORTED_SECURITY" },
		{ .id = 0xe0, .str = "MAC_STATUS_BEACON_LOSS" },
		{ .id = 0xe1, .str = "MAC_STATUS_CHANNEL_ACCESS_FAILURE" },
		{ .id = 0xe2, .str = "MAC_STATUS_DENIED" },
		{ .id = 0xe3, .str = "MAC_STATUS_DISABLE_TRX_FAILURE" },
		{ .id = 0xe4, .str = "MAC_STATUS_SECURITY_ERROR" },
		{ .id = 0xe5, .str = "MAC_STATUS_FRAME_TOO_LONG" },
		{ .id = 0xe6, .str = "MAC_STATUS_INVALID_GTS" },
		{ .id = 0xe7, .str = "MAC_STATUS_INVALID_HANDLE" },
		{ .id = 0xe8, .str = "MAC_STATUS_INVALID_PARAMETER" },
		{ .id = 0xe9, .str = "MAC_STATUS_NO_ACK" },
		{ .id = 0xea, .str = "MAC_STATUS_NO_BEACON" },
		{ .id = 0xeb, .str = "MAC_STATUS_NO_DATA" },
		{ .id = 0xec, .str = "MAC_STATUS_NO_SHORT_ADDRESS" },
		{ .id = 0xed, .str = "MAC_STATUS_OUT_OF_CAP" },
		{ .id = 0xee, .str = "MAC_STATUS_PAN_ID_CONFLICT" },
		{ .id = 0xef, .str = "MAC_STATUS_REALIGNMENT" },
		{ .id = 0xf0, .str = "MAC_STATUS_TRANSACTION_EXPIRED" },
		{ .id = 0xf1, .str = "MAC_STATUS_TRANSACTION_OVERFLOW" },
		{ .id = 0xf2, .str = "MAC_STATUS_TX_ACTIVE" },
		{ .id = 0xf3, .str = "MAC_STATUS_UNAVAILABLE_KEY" },
		{ .id = 0xf4, .str = "MAC_STATUS_UNSUPPORTED_ATTRIBUTE" },
		{ .id = 0xf5, .str = "MAC_STATUS_INVALID_ADDRESS" },
		{ .id = 0xf5, .str = "MAC_STATUS_SUPERFRAME_OVERLAP" },
		{ .id = 0xf6, .str = "MAC_STATUS_ON_TIME_TOO_LONG" },
		{ .id = 0xf7, .str = "MAC_STATUS_PAST_TIME" },
		{ .id = 0xf8, .str = "MAC_STATUS_TRACKING_OFF" },
		{ .id = 0xf9, .str = "MAC_STATUS_INVALID_INDEX" },
		{ .id = 0xfa, .str = "MAC_STATUS_LIMIT_REACHED" },
		{ .id = 0xfb, .str = "MAC_STATUS_READ_ONLY" },
		{ .id = 0xfc, .str = "MAC_STATUS_SCAN_IN_PROGRESS" },
		{ .id = 0xff, .str = NULL },
	};

	unsigned n;
	for (n = 0; label[n].str; n++) {
		if (label[n].id == status) {
			return label[n].str;
		}
	}
	return "(unknown status)";
}


/* Default initial values. Should be read from cfg in the future */
static const u8_t psk[] = { 0xAB, 0x10, 0x34, 0x11, 0x45, 0x11, 0x1B, 0xC3,
	0xC1, 0x2D, 0xE8, 0xFF, 0x11, 0x14, 0x22, 0x04 };
static const u8_t gmk[] = { 0xAF, 0x4D, 0x6D, 0xCC, 0xF1, 0x4D, 0xE7, 0xC1, 0xC4, 0x23, 0x5E, 0x6F, 0xEF, 0x6C, 0x15, 0x1F };

static void mlme_signal(int status)
{
	mutexLock(g3plc_priv.mlmeLock);
	g3plc_priv.mlmeStatus = status;
	condSignal(g3plc_priv.mlmeCond);
	mutexUnlock(g3plc_priv.mlmeLock);
}

/* SAP callbacks */
static void mlme_reset_confirm(ps_g3_sap_t *sap, ps_g3_mlme_reset_confirm_t *confirm)
{
	DEBUG_LOG("mlme_reset_confirm %02x -> %s\n", confirm->status, status_to_str(confirm->status));
	mlme_signal(confirm->status);
}

static void mlme_set_confirm(ps_g3_sap_t *sap, ps_g3_mlme_set_confirm_t *confirm)
{
	DEBUG_LOG("mlme_set_confirm  %02x -> %s\n", confirm->status, status_to_str(confirm->status));
	mlme_signal(confirm->status);
}

static void mlme_get_confirm(ps_g3_sap_t *sap, ps_g3_mlme_get_confirm_t *confirm)
{
	DEBUG_LOG("mlme_get_confirm %02x -> %s\n", confirm->status, status_to_str(confirm->status));
	mutexLock(g3plc_priv.mlmeLock);
	memcpy(g3plc_priv.mlmeGetData, confirm->pib_attr_value.data, confirm->pib_attr_value.length);
	g3plc_priv.mlmeStatus = confirm->status;
	condSignal(g3plc_priv.mlmeCond);
	mutexUnlock(g3plc_priv.mlmeLock);
}

static void mlme_start_confirm(ps_g3_sap_t *sap, ps_g3_mlme_start_confirm_t *confirm)
{
	DEBUG_LOG("mlme_start_confirm %02x -> %s\n", confirm->status, status_to_str(confirm->status));
	mlme_signal(confirm->status);
}

static void mcps_data_confirm(ps_g3_sap_t *sap, ps_g3_mcps_data_confirm_t *confirm)
{
	DEBUG_LOG("mcps_data_confirm %02x -> %s\n", confirm->status, status_to_str(confirm->status));

	mutexLock(g3plc_priv.mcpsLock);
	g3plc_priv.mcpsStatus = confirm->status;
	condSignal(g3plc_priv.mcpsCond);
	mutexUnlock(g3plc_priv.mcpsLock);
}

static void mlme_scan_confirm(ps_g3_sap_t *sap, ps_g3_mlme_scan_confirm_t *confirm)
{
	DEBUG_LOG("mlme_scan_confirm %02x -> %s\n", confirm->status, status_to_str(confirm->status));

	scan.is_active = 0;
	lbp_g3_discovery_confirm(g3plc_priv.netif, confirm->status);
}

static void mlme_beacon_notify_indication(ps_g3_sap_t *sap, ps_g3_mlme_beacon_notify_indication_t *indication)
{
	DEBUG_LOG("mlme_beacon_notify_indication PAN ID %x\n", indication->pan_id);

	if (scan.is_active == 0) {
		return;
	}

	if (scan.buf.elements == scan.buf.size) {
		DEBUG_LOG("Scan buffer full!\n");
		return;
	}

	scan.buf.entries[scan.buf.elements].lba = indication->lba_addr;
	scan.buf.entries[scan.buf.elements].pan_id = indication->pan_id;
	scan.buf.entries[scan.buf.elements].lqi = indication->link_quality;
	scan.buf.entries[scan.buf.elements].rc_coord = indication->rc_coord;
	scan.buf.entries[scan.buf.elements].valid = 1;
	scan.buf.elements++;
}

static void mcps_data_request_test_vector_dump(ps_g3_mcps_data_request_t *request)
{
	int i;

	DEBUG_LOG("\033[1;33m");
	DEBUG_LOG("MCPS-DATA.request test vector:\n");
	DEBUG_LOG("\033[0;36m");
	DEBUG_LOG("%02X,%02X,%04X,", request->src_addr_mode, request->dst_addr.mode, request->dst_pan_id);

	if (request->dst_addr.mode == ps_802154_addr_mode__short) {
		DEBUG_LOG("%04X", request->dst_addr.short_address);
	}
	else {
		for (i = 0; i < 8; i++) {
			DEBUG_LOG("%02X", request->dst_addr.long_address.u8[i]);
		}
	}
	DEBUG_LOG(",");
	for (i = 0; i < request->msdu_len; i++)
		DEBUG_LOG("%02X", request->msdu[i]);

	DEBUG_LOG(",%02X,%02X,%02X,%02X\n", request->tx_opts, request->qos, request->security_level, request->key_index);
	DEBUG_LOG("\033[0m");
}

static void mcps_data_indication(ps_g3_sap_t *sap, ps_g3_mcps_data_indication_t *indication)
{
	struct lowpan6_link_addr src, dst;
	struct g3plc_mcps_indication n_indication;

	DEBUG_LOG("\033[93m(ENTER)mcps_data_indication msdu len: %d\033[0m\n", indication->msdu_len);

	if (indication->src_addr.mode == ps_802154_addr_mode__short) {
		src.addr_len = 2;
		src.addr[0] = indication->src_addr.short_address >> 8;
		src.addr[1] = indication->src_addr.short_address & 0xFF;
		DEBUG_LOG("src addr %04x\n", indication->src_addr.short_address);
	}
	else if (indication->src_addr.mode == ps_802154_addr_mode__long) {
		src.addr_len = 8;
		be_memcpy(src.addr, &indication->src_addr.long_address.u8, src.addr_len);
		DEBUG_LOG("src addr %016llx\n", indication->src_addr.long_address.u64);
	}
	else if (indication->src_addr.mode == ps_802154_addr_mode__none) {
		src.addr_len = 0;
	}
	else {
	}

	if (indication->dst_addr.mode == ps_802154_addr_mode__short) {
		dst.addr_len = 2;
		dst.addr[0] = indication->dst_addr.short_address >> 8;
		dst.addr[1] = indication->dst_addr.short_address & 0xFF;
		DEBUG_LOG("dst addr %04x\n", indication->dst_addr.short_address);
	}
	else if (indication->dst_addr.mode == ps_802154_addr_mode__long) {
		dst.addr_len = 8;
		be_memcpy(dst.addr, indication->dst_addr.long_address.u8, dst.addr_len);
		DEBUG_LOG("dst addr %016llx\n", indication->dst_addr.long_address.u64);
	}
	else {
	}

	n_indication.modulation = indication->modulation;
	n_indication.active_tones = indication->tone_actives;
	n_indication.security_level = indication->security_level;
	n_indication.msdu_linkquality = indication->msdu_linkquality;

	lowpan6_g3_tcpip_input(indication->msdu, indication->msdu_len,
			g3plc_priv.netif, &src, &dst, &n_indication);
}


int g3plc_output(struct netif *netif, struct pbuf *p, const struct lowpan6_link_addr *src, const struct lowpan6_link_addr *dst,
		uint8_t security_level, uint16_t pan_id, uint8_t qos, uint8_t key_index)
{
	struct pbuf *q;
	struct g3plc_data_request *req;
	req = malloc(sizeof(*req));
	if (req == NULL) {
		return -ENOMEM;
	}


	q = pbuf_clone(PBUF_RAW, PBUF_RAM, p);
	if (q == NULL) {
		free(req);
		return -ENOMEM;
	}

	req->req.dst_pan_id = pan_id;
	req->req.qos = qos;
	req->req.key_index = key_index;
	req->req.security_level = security_level;
	req->req.msdu = q->payload;
	req->req.msdu_handle = 0;
	req->req.msdu_len = q->tot_len;
	req->pbuf = q;
	req->dest = *dst;
	req->netif = netif;

	if (src->addr_len == 2) {
		req->req.src_addr_mode = ps_802154_addr_mode__short;
	}
	else if (src->addr_len == 8) {
		req->req.src_addr_mode = ps_802154_addr_mode__long;
	}
	else {
		free(req);
		return -1;
	}

	if (dst->addr_len == 2) {
		req->req.dst_addr.mode = ps_802154_addr_mode__short;
		req->req.dst_addr.short_address = dst->addr[0] << 8 | dst->addr[1];
	}
	else if (dst->addr_len == 8) {
		req->req.dst_addr.mode = ps_802154_addr_mode__long;
		be_memcpy(req->req.dst_addr.long_address.u8, dst->addr, 8);
	}
	else {
		free(req);
		return -1;
	}

	/* Broadcast packet */
	if (req->req.dst_addr.mode == ps_802154_addr_mode__short &&
			req->req.dst_addr.short_address == 0xFFFF) {
		req->req.tx_opts = 0;
	}
	else {
		req->req.tx_opts = 1;
	}

	mcps_data_request_test_vector_dump(&req->req);
	mutexLock(g3plc_priv.reqsLock);
	LIST_ADD(&g3plc_priv.reqs, req);
	condSignal(g3plc_priv.reqsCond);
	mutexUnlock(g3plc_priv.reqsLock);

	return 0;
}


static int g3plc_mac_set(ps_g3_mlme_set_request_t *req)
{
	int ret;

	mutexLock(g3plc_priv.mlmeLock);
	g3plc_priv.sap.clbk.mlme_set_request(&g3plc_priv.sap, req);
	condWait(g3plc_priv.mlmeCond, g3plc_priv.mlmeLock, 0);
	ret = g3plc_priv.mlmeStatus;
	mutexUnlock(g3plc_priv.mlmeLock);

	return ret;
}

static int g3plc_mac_get(ps_g3_mlme_get_request_t *req)
{
	int ret;

	mutexLock(g3plc_priv.mlmeLock);
	g3plc_priv.sap.clbk.mlme_get_request(&g3plc_priv.sap, req);
	condWait(g3plc_priv.mlmeCond, g3plc_priv.mlmeLock, 0);
	ret = g3plc_priv.mlmeStatus;
	mutexUnlock(g3plc_priv.mlmeLock);

	return ret;
}

/* G3-PLC MAC API for the 6LoWPAN layer */
int g3plc_mac_nb_table_lookup_sync(struct lowpan6_link_addr *addr, struct g3plc_mac_nb_entry *entry)
{
	ps_g3_mlme_get_request_t req = { .pib_attr_id = macExtNeighbourLookup };
	u16_t short_addr;
	int ret;

	short_addr = lowpan6_link_addr_to_u16(addr);
	short_addr = (((uint16_t)short_addr >> 8) & 0xff) | (((uint16_t)short_addr << 8) & 0xff00);
	req.pib_attr_index = short_addr;

	ret = g3plc_mac_get(&req);

	if (ret == MAC_STATUS_SUCCESS) {
		/* TODO: do we get active tones correctly? */
		memcpy(entry, g3plc_priv.mlmeGetData, sizeof(struct g3plc_mac_nb_entry));
		DEBUG_LOG("g3plc-drv: nb entry valid for %04X\n", short_addr);
		return 0;
	}

	DEBUG_LOG("g3plc-drv: NO nb entry for %04X\n", short_addr);
	return -1;
}

int g3plc_scan_request(struct g3plc_scan_entry *buf, int size, uint16_t duration)
{
	ps_g3_mlme_scan_request_t req = { .scan_duration = duration };

	DEBUG_LOG("g3plc_scan_request\n");
	g3plc_priv.sap.clbk.mlme_scan_request(&g3plc_priv.sap, &req);
	scan.is_active = 1;
	scan.buf.entries = buf;
	scan.buf.size = size;
	scan.buf.elements = 0;

	return 0;
}

int g3plc_mac_reset(void)
{
	DEBUG_LOG("g3_mac_reset\n");
	ps_g3_mlme_reset_request_t req = { .flags = 1 };
	int ret;

	mutexLock(g3plc_priv.mlmeLock);
	g3plc_priv.sap.clbk.mlme_reset_request(&g3plc_priv.sap, &req);
	condWait(g3plc_priv.mlmeCond, g3plc_priv.mlmeLock, 0);
	ret = g3plc_priv.mlmeStatus;
	mutexUnlock(g3plc_priv.mlmeLock);

	return ret;
}

int g3plc_set_pan_id(uint16_t pan_id)
{
	ps_g3_mlme_set_request_t req = { .pib_attr_id = macPANId, .pib_attr_value = { .length = 2 } };

	req.pib_attr_value.data[0] = pan_id & 0xff;
	req.pib_attr_value.data[1] = pan_id >> 8;
	DEBUG_LOG("g3_pan_id_set %02x%02x\n", req.pib_attr_value.data[1], req.pib_attr_value.data[0]);

	return g3plc_mac_set(&req);
}

int g3plc_get_hwaddr(uint8_t *hwaddr)
{
	DEBUG_LOG("g3_get_hwaddr\n");
	ps_g3_mlme_get_request_t req = { .pib_attr_id = macExtLongAddress };
	int ret;

	ret = g3plc_mac_get(&req);

	if (ret == 0) {
		be_memcpy(hwaddr, g3plc_priv.mlmeGetData, 8);
	}

	DEBUG_LOG(" -> %02x%02x%02x%02x%02x%02x%02x%02x\n", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5], hwaddr[6], hwaddr[7]);

	return ret;
}

int g3plc_set_hwaddr(const uint8_t *hwaddr)
{
	ps_g3_mlme_set_request_t req = { .pib_attr_id = macExtLongAddress, .pib_attr_value = { .length = 8 } };
	DEBUG_LOG("g3plc set hwaddr\n");

	be_memcpy(req.pib_attr_value.data, hwaddr, req.pib_attr_value.length);

	return g3plc_mac_set(&req);
}

int g3plc_set_rc_coord(uint16_t rc_coord)
{
	DEBUG_LOG("g3_set_rc_coord %04x\n", rc_coord);
	ps_g3_mlme_set_request_t req = { .pib_attr_id = macRCCoord, .pib_attr_value = { .length = 2 } };

	req.pib_attr_value.data[0] = (uint8_t)((rc_coord));
	req.pib_attr_value.data[1] = (uint8_t)((rc_coord) >> 8);

	return g3plc_mac_set(&req);
}

int g3plc_set_shortaddr(uint16_t short_addr)
{
	DEBUG_LOG("g3_set_shortaddr %04x\n", short_addr);
	ps_g3_mlme_set_request_t req = { .pib_attr_id = macShortAddress, .pib_attr_value = { .length = 2 } };

	req.pib_attr_value.data[0] = (uint8_t)((short_addr));
	req.pib_attr_value.data[1] = (uint8_t)((short_addr) >> 8);

	return g3plc_mac_set(&req);
}

int g3plc_set_gmk(const uint8_t *gmk, uint8_t gmk_id)
{
	DEBUG_LOG("g3_set_gmk\n");
	ps_g3_mlme_set_request_t req = { .pib_attr_id = macKeyTable, .pib_attr_value = { .length = 16 } };

	req.pib_attr_index = gmk_id;
	memcpy(req.pib_attr_value.data, gmk, req.pib_attr_value.length);

	return g3plc_mac_set(&req);
}

int g3plc_network_start(uint16_t pan_id)
{
	ps_g3_mlme_start_request_t req = { .pan_id = pan_id };
	int ret;

	DEBUG_LOG("g3plc: Network start\n");
	mutexLock(g3plc_priv.mlmeLock);

	g3plc_priv.sap.clbk.mlme_start_request(&g3plc_priv.sap, &req);
	DEBUG_LOG("g3plc: request sent\n");
	condWait(g3plc_priv.mlmeCond, g3plc_priv.mlmeLock, 0);
	ret = g3plc_priv.mlmeStatus;
	mutexUnlock(g3plc_priv.mlmeLock);

	return ret;
}

int g3_nb_table_set(uint16_t addr, uint8_t lqi, uint8_t ind)
{
	ps_g3_mac_nb_entry_t nb_entry = {
		.short_address = addr,
		.tone_map = { { 0x3f, 0 } }, /* FIXME: zero tonemap causes abort(), ps_assert no subcarriers */
		.tx_coef = { 0, 0, 0, 0, 0, 0 },
		.tx_res = 0,
		.tx_gain = 0,
		.mod_type = 0, /* robo */
		.mod_scheme = 0,
		.phase_diff = 0,
		.lqi = lqi,
		.tmr_valid_time = 0xff,
	};
	ps_g3_mlme_set_request_t set_nb_table = {
		.pib_attr_id = macNeighbourTable,
		.pib_attr_index = ind,
		.pib_attr_value = setup_nb_table(&nb_entry),
	};

	return g3plc_mac_set(&set_nb_table);
}


static void g3plc_lbp_init(void)
{
	uint8_t buf[16];

	srand((unsigned int)time(NULL));

	lbp_g3_init(g3plc_priv.netif, psk, buf, g3plc_priv.hwaddr, sizeof(g3plc_priv.hwaddr));
}


static void g3plc_tx_thread(void *arg)
{
	ps_g3_sap_t *sap = (ps_g3_sap_t *)arg;
	struct g3plc_data_request *req;

	lowpan6_g3_tmr_start(g3plc_priv.netif);
	mutexLock(g3plc_priv.mcpsLock);
	for (;;) {
		mutexLock(g3plc_priv.reqsLock);
		while (g3plc_priv.reqs == NULL)
			condWait(g3plc_priv.reqsCond, g3plc_priv.reqsLock, 0);

		req = g3plc_priv.reqs;
		LIST_REMOVE(&g3plc_priv.reqs, req);
		mutexUnlock(g3plc_priv.reqsLock);

		do {
			sap->clbk.mcps_data_request(sap, &req->req);
			condWait(g3plc_priv.mcpsCond, g3plc_priv.mcpsLock, 0);
			usleep(50 * 1000);
		} while (g3plc_priv.mcpsStatus == MAC_STATUS_TRANSACTION_OVERFLOW || g3plc_priv.mcpsStatus == MAC_STATUS_DENIED);
		lowpan6_g3_status_handle(req->netif, req->pbuf, &req->dest, g3plc_priv.mcpsStatus);
		pbuf_free(req->pbuf);
		free(req);
	}
}

static void g3plc_rx_thread(void *arg)
{
	ps_g3_sap_t *sap = (ps_g3_sap_t *)arg;
	for (;;) {
		ps_g3_sap_update(sap);
		usleep(1000); /* yield */
	}
}

static int g3plc_test_cmd(char *test)
{
	if (strcmp(test, "list") != 0) {
		g3plc_print_tests();
		return 0;
	}

	if (g3plc_mac_reset() != 0) {
		DEBUG_LOG("g3plc-drv: Fail to reset MAC!\n");
		return -EINVAL;
	}

	if (g3plc_set_hwaddr(g3plc_priv.hwaddr) != 0) {
		DEBUG_LOG("g3plc-drv: Fail to set MAC extended address\n");
		return -EINVAL;
	}

	if (lowpan6_g3_reset(g3plc_priv.netif) < 0) {
		DEBUG_LOG("g3plc-drv: Fail to set MAC extended address\n");
		return -EINVAL;
	}

	return g3plc_test_run(g3plc_priv.netif, test);
}


static void g3plc_msg_thread(void *arg)
{
	msg_t msg = { 0 };
	msg_rid_t rid;
	struct g3adp_ctl *ctl;

	for (;;) {
		if (msgRecv(g3plc_priv.port, &msg, &rid) < 0) {
			continue;
		}

		switch (msg.type) {
			case mtDevCtl:
				ctl = (struct g3adp_ctl *)msg.i.raw;
				if (ctl->type == g3adp_test) {
					DEBUG_LOG("g3adp: devctl test %s\n", ctl->name);
					msg.o.err = g3plc_test_cmd(ctl->name);
				}
				else if (ctl->type == g3adp_get) {
					msg.o.err = g3plc_get_val(ctl->name);
				}
				else {
				}

			default:
				break;
		}

		msgRespond(g3plc_priv.port, &msg, rid);
	}
}

static int sap_setup(ps_g3_sap_t *sap)
{
	ps_g3_sap_callbacks_t clbk_adp = {
		.mcps_data_request = ps_g3_sap_ser_mcps_data_request,
		.mcps_data_confirm = mcps_data_confirm,
		.mcps_data_indication = mcps_data_indication,
		.mlme_reset_request = ps_g3_sap_ser_mlme_reset_request,
		.mlme_reset_confirm = mlme_reset_confirm,
		.mlme_scan_request = ps_g3_sap_ser_mlme_scan_request,
		.mlme_beacon_notify_indication = mlme_beacon_notify_indication,
		.mlme_scan_confirm = mlme_scan_confirm,
		.mlme_set_request = ps_g3_sap_ser_mlme_set_request,
		.mlme_set_confirm = mlme_set_confirm,
		.mlme_get_request = ps_g3_sap_ser_mlme_get_request,
		.mlme_get_confirm = mlme_get_confirm,
		.mlme_start_request = ps_g3_sap_ser_mlme_start_request,
		.mlme_start_confirm = mlme_start_confirm,
		/* .mlme_comm_status_indication = mlme_comm_status_indication, */
	};
#define USE_SAP_UART 1
#ifdef USE_SAP_UART
	ps_g3_sap_dl_uart_cfg_t sap_dl_cfg = {
		.devname = "/dev/uart3",
	};
	if (ps_g3_sap_init(sap, &ps_g3_sap_dl_uart, &sap_dl_cfg) < 0) {
		printf("ps_g3_sap_init() unable to initialize sap layer");
		return -1;
	}
#else
	if (ps_g3_sap_init(sap, &ps_g3_sap_dl_msgcli, NULL) < 0) {
		return -1;
	}
#endif

	ps_g3_sap_context(sap, NULL);
	ps_g3_sap_callbacks(sap, &clbk_adp);

	return beginthread(g3plc_rx_thread, 4, g3plc_priv.rxstack, sizeof(g3plc_priv.rxstack), &g3plc_priv.sap);
}


static int g3plc_netifInit(struct netif *netif, char *cfg)
{
	u8_t hwaddr[8];
	int i;
	char *hwaddrStr, *arg;
	oid_t oid;

	if (portCreate(&g3plc_priv.port) != 0) {
		DEBUG_LOG("g3plc-drv: can't create port\n");
		return -1;
	}

	oid.port = g3plc_priv.port;
	oid.id = 0;

	if (create_dev(&oid, "/dev/g3adp") < 0) {
		DEBUG_LOG("phoenix-rtos-lwip: can't create /dev/g3adp\n");
		return -EINVAL;
	}

	hwaddrStr = strtok(cfg, ":");
	if (hwaddrStr == NULL || strlen(hwaddrStr) != 16) {
		DEBUG_LOG("g3plc-drv: MAC hwaddr not present or invalid!\n");
		return -EINVAL;
	}

	for (i = 0; i < sizeof(hwaddr); i++) {
		hwaddr[i] = (hwaddrStr[2 * i] - '0') * 16;
		hwaddr[i] += hwaddrStr[2 * i + 1] - '0';
	}

	g3plc_priv.noauto = 0;
	g3plc_priv.devType = LOWPAN6_G3_DEVTYPE_DEVICE;
	while ((arg = strtok(NULL, ":")) != NULL) {
		if (strcmp(arg, "coord") != 0) {
			DEBUG_LOG("setting device type to PAN coordinator\n");
			g3plc_priv.devType = LOWPAN6_G3_DEVTYPE_COORD;
		}
		else if (strcmp(arg, "noauto") != 0) {
			g3plc_priv.noauto = 1;
		}
		else {
		}
	}

	g3plc_priv.netif = netif;

	mutexCreate(&g3plc_priv.mcpsLock);
	mutexCreate(&g3plc_priv.mlmeLock);
	mutexCreate(&g3plc_priv.reqsLock);
	condCreate(&g3plc_priv.mcpsCond);
	condCreate(&g3plc_priv.mlmeCond);
	condCreate(&g3plc_priv.reqsCond);

	if (sap_setup(&g3plc_priv.sap) != 0) {
		DEBUG_LOG("g3plc-drv: Fail to initialize SAP\n");
		return -EINVAL;
	}

	/* TODO: don't start rx thread so early */
	if (g3plc_mac_reset() != 0) {
		DEBUG_LOG("g3plc-drv: Fail to reset MAC!\n");
		return -EINVAL;
	}

	if (g3plc_set_hwaddr(hwaddr) != 0) {
		DEBUG_LOG("g3plc-drv: Fail to set MAC extended address\n");
		return -EINVAL;
	}
	memcpy(g3plc_priv.hwaddr, hwaddr, 8);

	if (lowpan6_g3_if_init(g3plc_priv.netif) != 0) {
		DEBUG_LOG("g3plc-drv: Fail to initialize lowpan6 netif\n");
		return -EINVAL;
	}

	if (g3plc_priv.noauto) {
		lowpan6_g3_set_noauto(g3plc_priv.netif, 1);
	}
	else {
		lowpan6_g3_set_device_type(g3plc_priv.devType);
		if (g3plc_priv.devType == LOWPAN6_G3_DEVTYPE_COORD) {

			if (lowpan6_g3_set_gmk(netif, gmk, 0) != 0) {
				DEBUG_LOG("g3plc-drv: Fail to set GMK\n");
				return -EINVAL;
			}

			if (lowpan6_g3_set_short_addr(netif, 0x00, 0x00) != ERR_OK) {
				DEBUG_LOG("g3plc-drv: Fail to set shord address\n");
				return -EINVAL;
			}
		}
		g3plc_lbp_init();
	}

	int err = 0;
	err = beginthread(g3plc_msg_thread, 4, g3plc_priv.msgstack, sizeof(g3plc_priv.msgstack), NULL);
	if (err != 0) {
		printf("Couldn't begin g3plc_msg_thread thread: %s (%d)", strerror(-err), err);
		return err;
	}

	// netif_set_default(netif);
	err = beginthread(g3plc_tx_thread, 4, g3plc_priv.txstack, sizeof(g3plc_priv.txstack), &g3plc_priv.sap);
	if (err != 0) {
		printf("Couldn't begin g3plc_tx_thread thread: %s (%d)", strerror(-err), err);
		return err;
	}

	return EOK;
}


static netif_driver_t g3plc_drv = {
	.init = g3plc_netifInit,
	.state_sz = sizeof(g3plc_priv),
	.state_align = _Alignof(g3plc_priv),
	.name = "g3plc",
};


__constructor__(1000) void register_driver_g3plc(void)
{
	register_netif_driver(&g3plc_drv);
}
