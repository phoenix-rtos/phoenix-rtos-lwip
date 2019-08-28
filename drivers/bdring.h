/*
 * Phoenix-RTOS --- networking stack
 *
 * Buffer descriptor ring handling
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * %LICENSE%
 */
#ifndef PHOENIX_NET_BDRING_H_
#define PHOENIX_NET_BDRING_H_

#include <sys/types.h>
#include <stdatomic.h>
#include "lwip/pbuf.h"


struct netif;
struct net_bufdesc_ring_;
typedef struct net_bufdesc_ring_ net_bufdesc_ring_t;


enum {
	BDRING_SEG_FIRST = 1,
	BDRING_SEG_LAST = 2,
};


typedef struct net_bufdesc_ops_
{
	size_t (*nextRxBufferSize)(const net_bufdesc_ring_t *ring, size_t i);
	int (*pktRxFinished)(const net_bufdesc_ring_t *ring, size_t i);
	void (*fillRxDesc)(const net_bufdesc_ring_t *ring, size_t i, addr_t pa, size_t sz, unsigned seg /* = zero */);
	int (*nextTxDone)(const net_bufdesc_ring_t *ring, size_t i);
	void (*fillTxDesc)(const net_bufdesc_ring_t *ring, size_t i, addr_t pa, size_t sz, unsigned seg);

	size_t desc_size;
	size_t ring_alignment;
	size_t pkt_buf_sz;
	size_t max_tx_frag;
} net_bufdesc_ops_t;


struct net_bufdesc_ring_
{
	volatile void *ring;
	struct pbuf **bufp;
	volatile unsigned head, tail;
	unsigned last;
	addr_t phys;
	const net_bufdesc_ops_t *ops;
	handle_t lock;
};


int net_initRings(net_bufdesc_ring_t *rings, const size_t *sizes, size_t nrings, const net_bufdesc_ops_t *ops);
size_t net_receivePackets(net_bufdesc_ring_t *ring, struct netif *ni, unsigned ethpad);
size_t net_refillRx(net_bufdesc_ring_t *ring, size_t ethpad);
size_t net_reapTxFinished(net_bufdesc_ring_t *ring);
size_t net_transmitPacket(net_bufdesc_ring_t *ring, struct pbuf *p);


static inline int net_rxFullyFilled(net_bufdesc_ring_t *ring)
{
	unsigned tail = atomic_load(&ring->tail);
	unsigned head = atomic_load(&ring->head);

	return ((head - tail) & ring->last) == 1;
}

#endif /* PHOENIX_NET_BDRING_H_ */
