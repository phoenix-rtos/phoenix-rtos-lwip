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

#include <sys/threads.h>

#include "bdring.h"
#include "physmmap.h"
#include "pktmem.h"
#include "lwip/netif.h"

#include LWIP_HOOK_FILENAME

#include <stdatomic.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>


#define MAX_TX_FRAGMENTS 8


/* A ring. To rule them all.
 *
 *       0    1           n-1  (wraps)
 *    +----+----+-     -+----+
 *    |    |    |  ...  |    |
 *    +----+----+-     -+----+
 *
 *      head = next entry to read (RX) or fill (TX)
 *      tail = next entry to fill (RX) or reap (TX)
 *      head == tail: ring empty to fill
 */


static inline bool net_isPowerOf2(size_t n)
{
	return (n & (n - 1)) == 0;
}


int net_initRings(net_bufdesc_ring_t *rings, const size_t *sizes, size_t nrings, const net_bufdesc_ops_t *ops)
{
	size_t i, nb, sz, alignMask;
	addr_t phys;
	struct pbuf **bufp;
	void *p;

	if (ops->ring_alignment == 0 || !net_isPowerOf2(ops->ring_alignment)) {
		return -EINVAL;
	}
	alignMask = ops->ring_alignment - 1;

	if (net_initPktMem(ops->pkt_buf_sz) < 0) {
		return -EINVAL;
	}

	// FIXME: check for overflows
	nb = 0;
	sz = 0;
	for (i = 0; i < nrings; ++i) {
		if (!net_isPowerOf2(sizes[i])) {
			return -EINVAL;
		}

		nb += sizes[i];
		sz += sizes[i] * ops->desc_size;
		sz = (sz + alignMask) & ~alignMask;
	}

	bufp = calloc(nb, sizeof(*bufp));
	if (bufp == NULL) {
		return -ENOMEM;
	}

	p = dmammap(sz);
	if (p == NULL) {
		free(bufp);
		return -ENOMEM;
	}

	phys = va2pa(p);
	if ((phys & alignMask) != 0) {
		printf("ERROR: got unaligned ring buffer (at 0x%zx, align mask: 0x%zx)\n", (size_t)phys, alignMask);
		munmap(p, sz);
		free(bufp);
		return -ENOMEM;
	}

	/* printf("descriptor rings: virt 0x%zx phys 0x%zx\n", (size_t)p, (size_t)phys); */

	memset(p, 0, sz);

	for (i = 0; i < nrings; ++i) {
		rings[i].ring = p;
		rings[i].bufp = bufp;
		atomic_init(&rings[i].head, 0);
		atomic_init(&rings[i].tail, 0);
		rings[i].last = sizes[i] - 1;
		rings[i].phys = phys;
		rings[i].ops = ops;

		sz = (sizes[i] * ops->desc_size + alignMask) & ~alignMask;
		p += sz;
		bufp += sizes[i];
		phys += sz;

		mutexCreate(&(rings[i].lock));
	}

	return 0;
}


size_t net_receivePackets(net_bufdesc_ring_t *ring, struct netif *ni)
{
	struct pbuf *p, *pkt;
	size_t n, i, sz;

	mutexLock(ring->lock);
	n = 0;
	i = atomic_load(&ring->head);
	pkt = NULL;

	for (;;) {
		if (i == atomic_load(&ring->tail)) {
			break;
		}

		sz = ring->ops->nextRxBufferSize(ring, i);
		if (sz == 0) {
			break;
		}

		p = ring->bufp[i];
		p->tot_len = p->len = sz;

		if (pkt == NULL) {
			pkt = p;
		}
		else {
			pbuf_cat(pkt, p);
		}

		if (ring->ops->pktRxFinished(ring, i)) {
#ifdef LWIP_HOOK_ETH_INPUT
			if (LWIP_HOOK_ETH_INPUT(p, ni)) {
				pbuf_free(p);
			}
			else
#endif
			{
				ni->input(pkt, ni);
			}
			pkt = NULL;
		}

		i = (i + 1) & ring->last; /* NOTE: 2^n ring size verified in net_initRings */
		++n;
	}

	atomic_store(&ring->head, i);
	mutexUnlock(ring->lock);
	return n;
}


size_t net_refillRx(net_bufdesc_ring_t *ring)
{
	struct pbuf *p;
	size_t n, i, nxt, sz;
	addr_t pa;
	mutexLock(ring->lock);

	n = 0;
	i = ring->tail;
	nxt = (i + 1) & ring->last; /* NOTE: 2^n ring size verified in net_initRings */
	sz = ring->ops->pkt_buf_sz;

	while (nxt != atomic_load(&ring->head)) {
		p = net_allocDMAPbuf(&pa, sz);
		if (p == NULL) {
			break;
		}

		ring->bufp[i] = p;
		ring->ops->fillRxDesc(ring, i, pa, sz, 0);

		i = nxt;
		nxt = (nxt + 1) & ring->last; /* NOTE: 2^n ring size verified in net_initRings */
		++n;
	}

	atomic_store(&ring->tail, i);
	mutexUnlock(ring->lock);
	return n;
}


size_t net_reapTxFinished(net_bufdesc_ring_t *ring)
{
	size_t n, i, head;
	mutexLock(ring->lock);

	n = 0;
	i = atomic_load(&ring->tail);
	head = atomic_load(&ring->head);
	while (i != head) {
		if (!ring->ops->nextTxDone(ring, i)) {
			break;
		}

		if (ring->bufp[i] != NULL) {
			pbuf_free(ring->bufp[i]);
			ring->bufp[i] = NULL;
		}

		i = (i + 1) & ring->last; /* NOTE: 2^n ring size verified in net_initRings */
		++n;
	}

	if (n > 0) {
		atomic_store(&ring->tail, i);
	}

	mutexUnlock(ring->lock);
	return n;
}


static size_t net_fillFragments(struct pbuf *p, addr_t *pa, size_t *psz, size_t max_n, size_t max_fragsz)
{
	size_t n, sz, fragsz;
	void *data = NULL;

	sz = p->tot_len;
	n = fragsz = 0;

	while (sz != 0) {
		if (++n >= max_n) {
			return 0;
		}

		if (fragsz == 0) {
			fragsz = p->len;
			data = p->payload;
		}

		*psz = fragsz <= max_fragsz ? fragsz : max_fragsz;
		*pa = va2pa(data);
		sz -= *psz;
		fragsz -= *psz;

		if (fragsz == 0) {
			p = p->next;
		}
		else {
			data += *psz;
		}

		++psz, ++pa;
	}

	return n;
}


size_t net_transmitPacket(net_bufdesc_ring_t *ring, struct pbuf *p)
{
	addr_t pa[MAX_TX_FRAGMENTS];
	size_t psz[MAX_TX_FRAGMENTS];
	size_t n, frags, i, ni;
	int last;

	p = net_makeDMAPbuf(p);
	if (p == NULL) {
		return 0;
	}

	mutexLock(ring->lock);
	/* NOTE: 2^n ring size verified in net_initRings */
	n = atomic_load(&ring->tail); /* access tail once - it may be advanced by tx_done thread */
	i = atomic_load(&ring->head);
	n = (n - i - 1) & ring->last;
	if (n > MAX_TX_FRAGMENTS) {
		n = MAX_TX_FRAGMENTS;
	}

	frags = n = net_fillFragments(p, pa, psz, n, ring->ops->max_tx_frag);
	if (frags == 0) {
		pbuf_free(p);
		mutexUnlock(ring->lock);
		return 0; /* dropped: too many fragments or empty packet */
	}

	/* fill fragments from last to avoid race against HW */
	i = ni = (i + n) & ring->last;
	ring->bufp[i] = p;
	last = BDRING_SEG_LAST;
	while (n-- > 0) {
		if (n == 0) {
			last |= BDRING_SEG_FIRST;
		}
		i = (i - 1) & ring->last;
		ring->ops->fillTxDesc(ring, i, pa[n], psz[n], last);
		last = 0;
	}

	atomic_store(&ring->head, ni);
	mutexUnlock(ring->lock);
	return frags;
}
