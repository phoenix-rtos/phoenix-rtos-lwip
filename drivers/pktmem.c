/*
 * Phoenix-RTOS --- networking stack
 *
 * Packet buffer handling
 *
 * Copyright 2017 Phoenix Systems
 * Author: Michał Mirosław
 *
 * %LICENSE%
 */
#include "physmmap.h"
#include "pktmem.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"

#include <stdio.h>
#include <string.h>


#define CACHE_LINE_SIZE 64
#define PAGE_SIZE 4096

#define TRUE_LRU 0


#define PKT_BUF_SIZE (2048 - CACHE_LINE_SIZE)
#define PKT_BUF_CNT	(size_t)((PAGE_SIZE - CACHE_LINE_SIZE) / PKT_BUF_SIZE)
#define PKT_BUF_IDX	11	// log2(PAGE_SIZE) - ceil(log2(PKT_BUF_CNT))


typedef struct _buf_page_head {
	unsigned free_mask;
	struct _buf_page_head *next;
	struct _buf_page_head *prev;
} buf_page_head_t;


static buf_page_head_t pkt_buf_lru = { .next = &pkt_buf_lru, .prev = &pkt_buf_lru };
static unsigned pkt_bufs_free;


static void net_listAdd(buf_page_head_t *ph, buf_page_head_t *after)
{
	buf_page_head_t *next;

	next = ph->next = after->next;
	ph->prev = after;
	next->prev = ph;
	after->next = ph;
}


static void net_listDel(buf_page_head_t *ph)
{
	buf_page_head_t *prev, *next;

	prev = ph->prev;
	next = ph->next;
	prev->next = next;
	next->prev = prev;
}


static void net_freePktBuf(void *p)
{
	buf_page_head_t *ph = (void *)((uintptr_t)p & ~(PAGE_SIZE - 1));
	unsigned which = ((size_t)p & (PAGE_SIZE - 1)) >> PKT_BUF_IDX;
	unsigned old_mask;

	old_mask = ph->free_mask;
	ph->free_mask |= 1 << which;

	if (old_mask) {
		if (!TRUE_LRU || pkt_buf_lru.next == ph)
			return;
		net_listDel(ph);
	}

	net_listAdd(ph, &pkt_buf_lru);
}


static void net_freeDMAPbuf(struct pbuf *p)
{
	net_freePktBuf(p->payload);
	mem_free(p);
}


static ssize_t net_allocPktBuf(void **bufp)
{
	buf_page_head_t *ph;
	unsigned i;

	if (!pkt_bufs_free) {
		ph = dmammap(PAGE_SIZE);
		if (ph == MAP_FAILED) {
			printf("mmap: no memory?\n");
			return 0;
		}

		memset(ph, 0, CACHE_LINE_SIZE);
		ph->free_mask = (1 << PKT_BUF_CNT) - 1;
		net_listAdd(ph, &pkt_buf_lru);
		pkt_bufs_free += PKT_BUF_CNT;
	} else {
		ph = pkt_buf_lru.next;
	}

	i = __builtin_ctz(ph->free_mask);
	*bufp = (void *)ph + CACHE_LINE_SIZE + i * PKT_BUF_SIZE;

	--pkt_bufs_free;
	if (!(ph->free_mask &= ~(1 << i)))
		net_listDel(ph);

	return PKT_BUF_SIZE;
}


struct pbuf *net_allocDMAPbuf(addr_t *pa, size_t sz)
{
	struct pbuf_custom *p;
	size_t bsz;

	p = (void *)pbuf_alloc(PBUF_RAW, sizeof(*p) - sizeof(struct pbuf), PBUF_RAM);
	if (!p)
		return NULL;

	bsz = net_allocPktBuf(&p->pbuf.payload);

	if (bsz) {
		p->pbuf.flags |= PBUF_FLAG_IS_CUSTOM;
		p->custom_free_function = net_freeDMAPbuf;
	}

	*pa = mphys(p->pbuf.payload, &bsz);

	if (bsz < sz) {
		pbuf_free(&p->pbuf);
		return NULL;
	}

	p->pbuf.len = p->pbuf.tot_len = sz;
	return &p->pbuf;
}


struct pbuf *net_makeDMAPbuf(struct pbuf *p)
{
	struct pbuf *q;
	addr_t pa;
	err_t err;

	if (p->flags & PBUF_FLAG_IS_CUSTOM)
		return p;

	q = net_allocDMAPbuf(&pa, p->tot_len + ETH_PAD_SIZE);
	if (!q) {
		pbuf_free(p);
		return q;
	}

	pbuf_header(q, -ETH_PAD_SIZE);
	err = pbuf_copy(q, p);

	pbuf_free(p);

	if (!err)
		return q;

	pbuf_free(q);

	return NULL;
}
