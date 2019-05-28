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
#include "bdring.h"
#include "physmmap.h"
#include "lwip/netif.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


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


static int is_power_of_2(size_t n)
{
	return !(n & (n - 1));
}


int net_initRings(net_bufdesc_ring_t *rings, const size_t *sizes, size_t nrings, const net_bufdesc_ops_t *ops)
{
	size_t i, nb, sz, psz, align;
	addr_t phys;
	struct pbuf **bufp;
	void *p;

	align = ops->ring_alignment;
	if (align) {
		if (!is_power_of_2(align))
			return -EINVAL;
		--align;
	}

	// FIXME: check for overflows
	nb = sz = 0;
	for (i = 0; i < nrings; ++i) {
		nb += sizes[i];
		sz += sizes[i] * ops->desc_size;
		sz = (sz + align) & ~align;

		if (!is_power_of_2(sizes[i]))
			return -EINVAL;
	}

	bufp = calloc(nb, sizeof(*bufp));
	if (!bufp)
		return -ENOMEM;

	p = dmammap(sz);
	if (!p) {
		free(bufp);
		return -ENOMEM;
	}

	psz = sz;
	phys = mphys(p, &psz);
	if ((psz != sz) || (phys & align)) {
		if (psz != sz)
			printf("ERROR: got non-contiguous ring buffer (%zu/%zu segment)\n", psz, sz);
		else
			printf("ERROR: got unaligned ring buffer (at 0x%zx, align mask: 0x%zx)\n", (size_t)phys, align);
		munmap(p, sz);
		free(bufp);
		return -ENODEV;
	}

	printf("descriptor rings: virt 0x%zx phys 0x%zx\n", (size_t)p, (size_t)phys);

	memset(p, 0, sz);

	for (i = 0; i < nrings; ++i) {
		rings[i].ring = p;
		rings[i].bufp = bufp;
		rings[i].head = rings[i].tail = 0;
		rings[i].last = sizes[i] - 1;
		rings[i].phys = phys;
		rings[i].ops = ops;

		sz = (sizes[i] * ops->desc_size + align) & ~align;
		p += sz;
		bufp += sizes[i];
		phys += sz;
	}

	return 0;
}


size_t net_receivePackets(net_bufdesc_ring_t *ring, struct netif *ni)
{
	struct pbuf *p, *pkt;
	size_t n, i, sz;

	n = 0;
	i = ring->head;
	pkt = NULL;

	for (;;) {
		if (i == ring->tail)
			break;

		sz = ring->ops->nextRxBufferSize(ring, i);
		if (!sz)
			break;

		p = ring->bufp[i];
		p->tot_len = p->len = sz;

		if (!pkt)
			pbuf_header((pkt = p), ETH_PAD_SIZE);
		else
			pbuf_cat(pkt, p);

		if (ring->ops->pktRxFinished(ring, i)) {
			ni->input(pkt, ni);
			pkt = NULL;
		}

		i = (i + 1) & ring->last;	// NOTE: 2^n ring size verified in net_initRings
		++n;
	}

	ring->head = i;
	return n;
}


size_t net_refillRx(net_bufdesc_ring_t *ring, size_t ethpad)
{
	struct pbuf *p;
	size_t n, i, nxt, sz;
	addr_t pa;

	n = 0;
	i = ring->tail;
	nxt = (i + 1) & ring->last;	// NOTE: 2^n ring size verified in net_initRings

	while (nxt != ring->head) {
		sz = ring->ops->pkt_buf_sz * 2;
		p = pbuf_alloc(PBUF_RAW, sz, PBUF_RAM);
		if (!p)
			break;

		if (ethpad != ETH_PAD_SIZE)
			pbuf_header(p, ethpad - ETH_PAD_SIZE);

		pa = mphys(p->payload, &sz);
		if (sz < ring->ops->pkt_buf_sz) {
			pbuf_header(p, -sz);
			sz = ring->ops->pkt_buf_sz * 2 - sz;
			pa = mphys(p->payload, &sz);
			LWIP_ASSERT("discontinuous va???", (sz >= ring->ops->pkt_buf_sz));
		}

		ring->bufp[i] = p;
		ring->ops->fillRxDesc(ring, i, pa, sz, 0);

		i = nxt;
		nxt = (nxt + 1) & ring->last;	// NOTE: 2^n ring size verified in net_initRings
		++n;
	}

	ring->tail = i;
	return n;
}


size_t net_reapTxFinished(net_bufdesc_ring_t *ring)
{
	size_t n, i, head;

	n = 0;
	i = ring->tail;
	head = *(volatile unsigned *)&ring->head;
	while (i != head) {
		if (!ring->ops->nextTxDone(ring, i))
			break;

		if (ring->bufp[i]) {
			pbuf_free(ring->bufp[i]);
			ring->bufp[i] = NULL;
		}

		i = (i + 1) & ring->last;	// NOTE: 2^n ring size verified in net_initRings
		++n;
	}

	if (n)
		*(volatile unsigned *)&ring->tail = i;
	return n;
}


static size_t net_fillFragments(struct pbuf *p, addr_t *pa, size_t *psz, size_t max_n, size_t max_fragsz)
{
	size_t n, sz, fragsz;
	void *data;

	sz = p->tot_len;
	n = fragsz = 0;

	while (sz) {
		if (++n >= max_n)
			return 0;

		if (!fragsz) {
			fragsz = p->len;
			data = p->payload;
		}

		*psz = fragsz <= max_fragsz ? fragsz : max_fragsz;
		*pa = mphys(data, psz);
		sz -= *psz;
		fragsz -= *psz;

		if (!fragsz)
			p = p->next;
		else
			data += *psz;

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

	// NOTE: 2^n ring size verified in net_initRings
	n = *(volatile unsigned *)&ring->tail;	// access tail once - it may be advanced by tx_done thread
	i = ring->head;
	n = (n - i - 1) & ring->last;
	if (n > MAX_TX_FRAGMENTS)
		n = MAX_TX_FRAGMENTS;

	frags = n = net_fillFragments(p, pa, psz, n, ring->ops->max_tx_frag);
	if (!frags)
		return 0;	/* dropped: too many fragments or empty packet */

	pbuf_ref(p);

	/* fill fragments from last to avoid race against HW */
	i = ni = (i + n) & ring->last;
	ring->bufp[i] = p;
	last = BDRING_SEG_LAST;
	while (n--) {
		if (!n)
			last |= BDRING_SEG_FIRST;
		i = (i - 1) & ring->last;
		ring->ops->fillTxDesc(ring, i, pa[n], psz[n], last);
		last = 0;
	}

	asm volatile ("" ::: "memory");
	*(volatile unsigned *)&ring->head = ni;	// sync with read in net_reapTxFinished() run in tx_done thread
	return frags;
}
