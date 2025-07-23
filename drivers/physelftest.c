/*
 * Phoenix-RTOS --- networking stack
 *
 * PHY selftest routine
 *
 * Copyright 2025 Phoenix Systems
 * Author: Marek Białowąs, Julian Uziembło
 *
 * %LICENSE%
 */
#include <sys/threads.h>
#include <stdbool.h>
#include <string.h>

#include "lwip/err.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"

#include "physelftest.h"
#include "res-create.h"

#define _TP_DST     "dddddd"
#define _TP_SRC     "ssssss"
#define _TP_ETHTYPE "\x05\xDD" /* eth frame type 0x05DD is undefined */
#define _TP_10DIG   "0123456789"
#define TEST_PACKET _TP_DST _TP_SRC _TP_ETHTYPE \
		_TP_10DIG _TP_10DIG _TP_10DIG _TP_10DIG _TP_10DIG _TP_10DIG _TP_10DIG
#define TEST_PACKET_LEN (sizeof((TEST_PACKET)) - 1)

#define PHYSELFTEST_RESOURCES(s) &(s).rx_lock, 2, ~0x1

#define physelftest_printf(common, fmt, ...) printf("lwip: %s: " fmt "\n", (common).params->module, ##__VA_ARGS__)
#define physelftest_debug_printf(common, fmt, ...) \
	do { \
		if ((common).params->verbose) { \
			physelftest_printf(common, fmt, ##__VA_ARGS__); \
		} \
	} while (0)


static struct {
	handle_t rx_lock;
	handle_t rx_cond;
	enum { rx_invalid = -1,
		rx_no_packet,
		rx_success } rx_status;
	const struct selftest_params *params;
} test_common;


/* self-test RX input function */
static err_t physelftest_netifInput(struct pbuf *p, struct netif *netif)
{
	uint8_t buf[TEST_PACKET_LEN]; /* used only if pbuf is fragmented (should not happen) */

	bool is_valid_pkt = true;

	/* verify contents */
	if (p->len != (TEST_PACKET_LEN + ETH_PAD_SIZE)) {
		physelftest_debug_printf(test_common, "self-test RX: invalid packet length");
		physelftest_debug_printf(test_common, "expected: %zuB", (TEST_PACKET_LEN + ETH_PAD_SIZE));
		physelftest_debug_printf(test_common, "actual:   %uB", p->len);
		is_valid_pkt = false;
	}
	uint8_t *data = pbuf_get_contiguous(p, buf, sizeof(buf), TEST_PACKET_LEN, ETH_PAD_SIZE);
	if (data == NULL || memcmp(TEST_PACKET, data, TEST_PACKET_LEN) != 0) {
		if (test_common.params->verbose) {
			if (data == NULL) {
				data = p->payload;
			}
			physelftest_printf(test_common, "self-test RX: invalid packet contents");

			physelftest_printf(test_common, "expected:");
			for (int i = 0; i < TEST_PACKET_LEN; i++) {
				if (i != 0 && i % 16 == 0) {
					printf("\n");
				}
				printf("%02x ", (uint8_t)TEST_PACKET[i]);
			}
			printf("\n");

			physelftest_printf(test_common, "actual:");
			for (int i = 0; i < p->len; i++) {
				if (i != 0 && i % 16 == 0) {
					printf("\n");
				}
				printf("%02x ", data[i]);
			}
			printf("\n");
		}
		is_valid_pkt = false;
	}
	pbuf_free(p);

	mutexLock(test_common.rx_lock);
	test_common.rx_status = is_valid_pkt ? rx_success : rx_invalid;
	mutexUnlock(test_common.rx_lock);
	condBroadcast(test_common.rx_cond);

	return ERR_OK;
}


/* MACPHY self-test procedure (internal loopback) */
int physelftest(const struct selftest_params *params)
{
	test_common.params = params;
	int err = params->setup(params->netif->state);
	if (err < 0) {
		return err;
	}

	err = create_mutexcond_bulk(PHYSELFTEST_RESOURCES(test_common));
	if (err != 0) {
		return err;
	}

	/* override netif->input */
	netif_input_fn old_input = params->netif->input;
	params->netif->input = physelftest_netifInput;

	int ret = 0;
	do {
		struct pbuf *p = pbuf_alloc(PBUF_RAW, TEST_PACKET_LEN + ETH_PAD_SIZE, PBUF_RAM);
		memset(p->payload, 0, ETH_PAD_SIZE);
		pbuf_take_at(p, TEST_PACKET, TEST_PACKET_LEN, ETH_PAD_SIZE);

		/* try to send and receive packets */
		mutexLock(test_common.rx_lock);
		test_common.rx_status = rx_no_packet;
		if (params->netif->linkoutput(params->netif, p) != ERR_OK) { /* frees pbuf internally */
			physelftest_printf(test_common, "failed to send test packet");
			ret = -1;
			mutexUnlock(test_common.rx_lock);
			break;
		}

		err = 0;
		while ((err != -ETIME) && (test_common.rx_status == rx_no_packet)) {
			/* TX -> RX takes ~4ms, wait for 100ms just to be sure */
			err = condWait(test_common.rx_cond, test_common.rx_lock, 100 * 1000);
		}
		mutexUnlock(test_common.rx_lock);

		if ((err < 0) || (test_common.rx_status != 1)) {
			physelftest_debug_printf(test_common, "Test failed: state->selfTest.rx_valid=%d, %s (%d)",
					test_common.rx_status, strerror(-err), err);
			ret = -1;
		}
		else {
			physelftest_debug_printf(test_common, "Test passed");
		}
		/* successfully received */
	} while (0);

	/* destroy selftest resources */
	(void)resourceDestroy(test_common.rx_cond);
	(void)resourceDestroy(test_common.rx_lock);

	/* restore normal mode */
	params->netif->input = old_input;

	err = params->teardown(params->netif->state);
	if (err < 0) {
		ret = err;
	}

	return ret;
}
