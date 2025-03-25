/*
 * Phoenix-RTOS --- networking stack
 *
 * Packet buffer handling
 *
 * Copyright 2017, 2025 Phoenix Systems
 * Author: Michał Mirosław, Julian Uziembło
 *
 * %LICENSE%
 */
#include "physmmap.h"
#include "pktmem.h"
#include "lwip/mem.h"
#include "lwip/sys.h"

#include <string.h>
#include <stdbool.h>


#define PKT_BUF_CACHE_SIZE (16) /* number of cached free packet buffers that can be reused without allocating new ones */


/*    pktmem memory layout:
 *    PAGE_SIZE < pkt_sz + sizeof(pktmem_info_t): 1 packet buffer on multiple pages
 *    PAGE_SIZE >= pkt_sz + sizeof(pktmem_info_t): 1 or more packet buffers on 1 page
 *
 *    META - pktmem metadata, sizeof(META) = sizeof(pktmem_info_t)
 *    PAGE - system memory page
 *    BUF  - packet buffer
 *    US   - unused space (could be empty)
 *
 *
 *    PAGE_SIZE < pkt_sz + sizeof(pktmem_info_t):
 *    +----+----+----+--     --+----+----+----+
 *    |     PAGE1    |   ...   |     PAGEn    |
 *    +----+----+----+--     --+----+----+----+
 *    |                           |    |      |
 *     --------------BUF---------- -US- -META-
 *
 *    PAGE_SIZE >= pkt_sz + sizeof(pktmem_info_t):
 *    +----+----+----+--     ----+----+----+----+----+----+
 *    |     BUF1     |   ...   |     BUFn     | US | META |
 *    +----+----+----+--     ----+----+----+----+----+----+
 *    |                                                   |
 *     -----------------------PAGE------------------------
 */
static struct {
	size_t alloc_sz;           /* total size of pktmem buffer (aligned to PAGE_SIZE) */
	size_t pkt_buf_sz;         /* sizeof space allocated for 1 packet buffer (DMA aligned) */
	size_t pkt_buf_cnt;        /* number of packet buffers in a single pktmem */
	size_t pktmem_info_offset; /* metadata offset from the pktmem start */
	unsigned free_mask_full;   /* bitmask representing all packet buffers in a single pktmem */
} pktmem_opts;


typedef struct _pktmem_info {
	unsigned free_mask;
	struct _pktmem_info *next;
	struct _pktmem_info *prev;
} pktmem_info_t;


typedef struct _pktmem_pbuf_custom {
	struct pbuf_custom pbuf_custom;
	/* keep a pointer to the start of pktmem to free it correctly
	 * this is necessary on targets with PAGE_SIZE < pkt_sz + sizeof(pktmem_info_t)
	 * as we cannot determine the start of pktmem from a given payload pointer
	 */
	void *pktmem_start;
} pktmem_pbuf_custom_t;


static pktmem_info_t pktmem_lru = { .next = &pktmem_lru, .prev = &pktmem_lru };
static unsigned pkt_bufs_free;


static void net_listAdd(pktmem_info_t *info, pktmem_info_t *after)
{
	pktmem_info_t *next;

	next = info->next = after->next;
	info->prev = after;
	next->prev = info;
	after->next = info;
}


static void net_listDel(pktmem_info_t *info)
{
	pktmem_info_t *prev, *next;

	prev = info->prev;
	next = info->next;
	prev->next = next;
	next->prev = prev;
}


static inline bool net_isPktMemInitialized(void)
{
	return pktmem_opts.alloc_sz != 0;
}


int net_initPktMem(size_t pkt_buf_max_sz)
{
	if (net_isPktMemInitialized()) {
		if (pkt_buf_max_sz == pktmem_opts.pkt_buf_sz) {
			return 0;
		}
		else {
			return -EINVAL;
		}
	}

	if (pkt_buf_max_sz == 0 || sizeof(pktmem_info_t) % __alignof__(pktmem_info_t) != 0) {
		return -EINVAL;
	}

	const size_t pktmem_info_sz = sizeof(pktmem_info_t);

	pktmem_opts.alloc_sz = PAGE_SIZE * ((pkt_buf_max_sz + pktmem_info_sz + PAGE_SIZE - 1) / PAGE_SIZE);
	pktmem_opts.pkt_buf_sz = pkt_buf_max_sz;
	pktmem_opts.pkt_buf_cnt = 1 + (pktmem_opts.alloc_sz - pkt_buf_max_sz - pktmem_info_sz) / pkt_buf_max_sz;
	if (pktmem_opts.pkt_buf_cnt > sizeof(pktmem_opts.free_mask_full) * 8) {
		return -EINVAL;
	}

	pktmem_opts.pktmem_info_offset = pktmem_opts.alloc_sz - pktmem_info_sz;
	pktmem_opts.free_mask_full = (1u << pktmem_opts.pkt_buf_cnt) - 1;

#if 0 /* debug */
	const size_t pages = pktmem_opts.alloc_sz / PAGE_SIZE;
	printf("lwip: net_initPktMem: pktmem_opts:\n"
		   "\talloc_sz=%zuB (%zu page%s)\n"
		   "\tpkt_buf_sz=%zuB\n"
		   "\tpkt_buf_cnt=%zu\n"
		   "\tpktmem_info_offset=%zuB\n"
		   "\tfree_mask_full=0x%x\n",
			pktmem_opts.alloc_sz, pages, pages > 1 ? "s" : "",
			pktmem_opts.pkt_buf_sz,
			pktmem_opts.pkt_buf_cnt,
			pktmem_opts.pktmem_info_offset,
			pktmem_opts.free_mask_full);
#endif

	return 0;
}


static void net_freePktBuf(void *bufp, void *pktmem_start)
{
	SYS_ARCH_DECL_PROTECT(old_level);
	pktmem_info_t *info = (void *)((uintptr_t)pktmem_start + pktmem_opts.pktmem_info_offset);
	unsigned which = ((size_t)bufp - (size_t)pktmem_start) / pktmem_opts.pkt_buf_sz;
	unsigned old_mask;

	old_mask = info->free_mask;
	info->free_mask |= 1u << which;

	SYS_ARCH_PROTECT(old_level);

	++pkt_bufs_free;

	if (pkt_bufs_free > PKT_BUF_CACHE_SIZE && info->free_mask == pktmem_opts.free_mask_full) {
		if (old_mask != 0) {
			net_listDel(info);
		}
		pkt_bufs_free -= pktmem_opts.pkt_buf_cnt;
		SYS_ARCH_UNPROTECT(old_level);
		munmap(pktmem_start, pktmem_opts.alloc_sz);
		return;
	}

	if (old_mask == 0) {
		net_listAdd(info, &pktmem_lru);
	}

	SYS_ARCH_UNPROTECT(old_level);
}


static void net_freeDMAPbuf(struct pbuf *p)
{
	pktmem_pbuf_custom_t *ppc = (void *)p;
	net_freePktBuf(p->payload, ppc->pktmem_start);
	mem_free(ppc);
}


static ssize_t net_allocPktBuf(void **bufp, void **pktmem_start)
{
	SYS_ARCH_DECL_PROTECT(old_level);
	void *pktmem;
	pktmem_info_t *info;
	unsigned i = 0;

	SYS_ARCH_PROTECT(old_level);
	if (pkt_bufs_free == 0 || pktmem_lru.next == &pktmem_lru) {
		SYS_ARCH_UNPROTECT(old_level);

		pktmem = dmammap(pktmem_opts.alloc_sz);
		if (pktmem == NULL) {
			printf("mmap: no memory?\n");
			return 0;
		}
		info = (void *)((uintptr_t)pktmem + pktmem_opts.pktmem_info_offset);

		memset(info, 0, sizeof(*info));
		info->free_mask = pktmem_opts.free_mask_full & ~(1u);

		SYS_ARCH_PROTECT(old_level);
		pkt_bufs_free += pktmem_opts.pkt_buf_cnt - 1;
		if (info->free_mask != 0) {
			net_listAdd(info, &pktmem_lru);
		}
	}
	else {
		info = pktmem_lru.next;
		pktmem = (void *)((uintptr_t)info - pktmem_opts.pktmem_info_offset);
		i = __builtin_ctz(info->free_mask);
		info->free_mask &= ~(1u << i);
		--pkt_bufs_free;
		if (info->free_mask == 0) {
			net_listDel(info);
		}
	}
	SYS_ARCH_UNPROTECT(old_level);

	*pktmem_start = pktmem;
	*bufp = (void *)((uintptr_t)pktmem + (i * pktmem_opts.pkt_buf_sz));

	return pktmem_opts.pkt_buf_sz;
}


struct pbuf *net_allocDMAPbuf(addr_t *pa, size_t sz)
{
	if (!net_isPktMemInitialized()) {
		return NULL;
	}

	pktmem_pbuf_custom_t *ppc;
	void *data;
	void *pktmem_start;
	size_t bsz;

	bsz = net_allocPktBuf(&data, &pktmem_start);
	if (bsz == 0) {
		return NULL;
	}
	if (bsz < sz) {
		net_freePktBuf(data, pktmem_start);
		return NULL;
	}

	*pa = va2pa(data);

	ppc = mem_malloc(sizeof(*ppc));
	if (ppc == NULL) {
		net_freePktBuf(data, pktmem_start);
		return NULL;
	}

	ppc->pbuf_custom.custom_free_function = net_freeDMAPbuf;
	ppc->pktmem_start = pktmem_start;
	return pbuf_alloced_custom(PBUF_RAW, sz, PBUF_REF, &ppc->pbuf_custom, data, bsz);
}


struct pbuf *net_makeDMAPbuf(struct pbuf *p)
{
	if (!net_isPktMemInitialized()) {
		return NULL;
	}

	struct pbuf *q;
	addr_t pa;
	err_t err;

	if ((p->flags & PBUF_FLAG_IS_CUSTOM) != 0) {
		pbuf_ref(p);
		return p;
	}

	q = net_allocDMAPbuf(&pa, p->tot_len + ETH_PAD_SIZE);
	if (q == NULL) {
		return NULL;
	}

	pbuf_header(q, -ETH_PAD_SIZE);
	err = pbuf_copy(q, p);

	if (err == 0) {
		return q;
	}

	pbuf_free(q);

	return NULL;
}
