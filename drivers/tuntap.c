/*
 * Phoenix-RTOS --- networking stack
 *
 * TUN/TAP devices
 *
 * Copyright 2019 Phoenix Systems
 * Author: Jan Sikorski, Kamil Amanowicz
 *
 * %LICENSE%
 */

#include "netif-driver.h"
#include "lwip/netifapi.h"

#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/file.h>
#include <sys/threads.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <syslog.h>
#include <posix/utils.h>

#include "fifo.h"

#define PKT_QUEUE_LEN 64
#define TUN_PRIO 3


typedef struct
{
	uint32_t stacks[2][4096];

	struct netif *netif;
	handle_t lock, cond;
	fifo_t *queue;
	int offset;

	enum { DEV_TAP, DEV_TUN } type;
	unsigned port;
} tuntap_priv_t;


#define log_debug(fmt, ...) syslog(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...)  syslog(LOG_INFO, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...)  syslog(LOG_WARNING, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) syslog(LOG_ERR, fmt, ##__VA_ARGS__)

//#define TUN_TRACE(str, ...) TUN_TRACE("tuntap driver: " str "\n", ##__VA_ARGS__)
#define TUN_TRACE(str, ...)

static err_t _tuntap_output_cb(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
	err_t res = ERR_BUF;
	tuntap_priv_t* state = netif->state;

	TUN_TRACE("output cb pbuf tot_len %d\n", p->tot_len);

	mutexLock(state->lock);
	if (!fifo_is_full(state->queue)) {
		res = ERR_OK;
		pbuf_ref(p);
		fifo_push(state->queue, p);
	}
	mutexUnlock(state->lock);
	condSignal(state->cond);

	return res;
}


static err_t tun_output_cb(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
	return _tuntap_output_cb(netif, p, ipaddr);
}


static err_t tap_output_cb(struct netif *netif, struct pbuf *p)
{
	return _tuntap_output_cb(netif, p, NULL);
}


static int _tuntap_write(tuntap_priv_t *state, void *data, size_t size)
{
	struct pbuf *p;

	TUN_TRACE("%c%c%d write size %llu\n", state->netif->name[0], state->netif->name[1], state->netif->num, size);

	if ((p = pbuf_alloc(PBUF_LINK, size, PBUF_RAM)) == NULL)
		return -ENOMEM;

	pbuf_take(p, data, size);
	state->netif->input(p, state->netif);
	return size;
}


static int _tuntap_read(tuntap_priv_t *state, void *data, size_t size)
{
	struct pbuf *p;
	int copied;

	TUN_TRACE("%c%c%d read size %llu\n", state->netif->name[0], state->netif->name[1], state->netif->num, size);
	/* TODO: don't block the thread */
	while (fifo_is_empty(state->queue))
		condWait(state->cond, state->lock, 0);

	p = fifo_pop_back(state->queue);

	if (p->tot_len > size) {
		fifo_push(state->queue, p);
		return -ERANGE;
	}

	TUN_TRACE("read popped pbuf tot_len %d\n", (int)p->tot_len);

	copied = pbuf_copy_partial(p, data, size, state->offset);
	state->offset += copied;
	if (state->offset < p->tot_len) {
		fifo_push(state->queue, p);
	}
	else {
		state->offset = 0;
		pbuf_free(p);
	}

	return copied;
}


static void tuntap_mainLoop(void* _state)
{
	tuntap_priv_t *state = _state;
	msg_t msg;
	msg_rid_t rid;

	while (1) {
		if (msgRecv(state->port, &msg, &rid) < 0) {
			usleep(100 * 1000);
			continue;
		}

		mutexLock(state->lock);
		switch (msg.type) {
		case mtOpen:
			state->netif->flags |= NETIF_FLAG_LINK_UP;
			break;
		case mtClose:
			state->netif->flags &= ~NETIF_FLAG_LINK_UP;
			break;
		case mtWrite:
			msg.o.io.err = _tuntap_write(state, msg.i.data, msg.i.size);
			break;
		case mtRead:
			msg.o.io.err = _tuntap_read(state, msg.o.data, msg.o.size);
			break;
		case mtGetAttr:
			if (msg.i.attr.type != atPollStatus) {
				msg.o.attr.err = -EINVAL;
				break;
			}
			msg.o.attr.val = POLLOUT;
			if (!fifo_is_empty(state->queue))
				msg.o.attr.val |= POLLIN;
			msg.o.attr.err = EOK;
			break;
		}
		mutexUnlock(state->lock);

		msgRespond(state->port, &msg, rid);
	}

	endthread();
}


static int _tuntap_init(struct netif *netif, char *cfg)
{
	oid_t dev;
	tuntap_priv_t *state = netif->state;//malloc(sizeof(tuntap_priv_t));
	if (state == NULL)
		return ERR_MEM;

	state->queue = malloc(sizeof(fifo_t) + PKT_QUEUE_LEN * sizeof(void *));
	if (state->queue == NULL)
		return ERR_MEM;

	fifo_init(state->queue, PKT_QUEUE_LEN);

	condCreate(&state->cond);
	if (state->cond < 0)
		return ERR_MEM;

	mutexCreate(&state->lock);
	if (state->lock < 0)
		return ERR_MEM;

	portCreate(&state->port);
	if (!state->port)
		return ERR_MEM;

	state->netif = netif;
	state->offset = 0;

	dev.port = state->port;
	create_dev(&dev, cfg);

	beginthread(tuntap_mainLoop, TUN_PRIO, state->stacks[0], sizeof(state->stacks[0]), state);
	beginthread(tuntap_mainLoop, TUN_PRIO, state->stacks[1], sizeof(state->stacks[1]), state);

	return ERR_OK;
}


static int tun_init(struct netif *netif, char *cfg)
{
	netif->name[0] = 't';
	netif->name[1] = 'u';
	netif->mtu = 1500;
	netif->flags = NETIF_FLAG_UP;
	netif->output = tun_output_cb;
	return _tuntap_init(netif, cfg);
}


static int tap_init(struct netif *netif, char *cfg)
{
	netif->name[0] = 't';
	netif->name[1] = 'a';
	netif->mtu = 1500;
	netif->hwaddr_len = ETH_HWADDR_LEN;
	netif->flags = NETIF_FLAG_UP | NETIF_FLAG_ETHARP | NETIF_FLAG_BROADCAST;
	netif->linkoutput = tap_output_cb;
	return _tuntap_init(netif, cfg);
}


static netif_driver_t tun_drv = {
	.init = tun_init,
	.state_sz = sizeof(tuntap_priv_t),
	.state_align = _Alignof(tuntap_priv_t),
	.name = "tun",
	.media = NULL,
};


static netif_driver_t tap_drv = {
	.init = tap_init,
	.state_sz = sizeof(tuntap_priv_t),
	.state_align = _Alignof(tuntap_priv_t),
	.name = "tap",
	.media = NULL,
};


__constructor__(1000)
void register_driver_tun(void)
{
	register_netif_driver(&tun_drv);
}


__constructor__(1000)
void register_driver_tap(void)
{
	register_netif_driver(&tap_drv);
}
