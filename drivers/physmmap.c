/*
 * Phoenix-RTOS --- networking stack
 *
 * Utilities: mmap physical memory
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * %LICENSE%
 */
#include "physmmap.h"

#include <sys/mman.h>


void *dmammap(size_t sz)
{
	void *p;

	// NOTE: eh, apparently it's better to do this in every app than in one kernel.
	// cf. 06b66f4c73352a9e53c14d3f9861933d1acf18c3
	sz = (sz + _PAGE_SIZE - 1) & ~(_PAGE_SIZE - 1);

	if (!sz)
		return NULL;

	p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_UNCACHED, -1, 0);
	return p != MAP_FAILED ? p : NULL;
}


volatile void *physmmap(addr_t addr, size_t sz)
{
	volatile void *va;
	size_t offs;

	offs = addr & (_PAGE_SIZE - 1);
	sz += offs;
	addr &= ~(addr_t)(_PAGE_SIZE - 1);

	sz = (sz + _PAGE_SIZE - 1) & ~(_PAGE_SIZE - 1);  // NOTE

	va = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_DEVICE | MAP_UNCACHED | MAP_PHYSMEM | MAP_ANONYMOUS, -1, addr);
	return va != MAP_FAILED ? va + offs : va;
}


void physunmap(volatile void *va, size_t sz)
{
	size_t offs;

	offs = (size_t)va & (_PAGE_SIZE - 1);
	sz += offs;
	va -= offs;

	sz = (sz + _PAGE_SIZE - 1) & ~(_PAGE_SIZE - 1);  // NOTE

	munmap((void *)va, sz);
}


addr_t mphys(void *p, size_t *psz)
{
	size_t sz;
	addr_t pa;

	pa = va2pa(p);
	sz = _PAGE_SIZE - (pa & (_PAGE_SIZE - 1));

	while (sz < *psz) {
		addr_t npa = va2pa(p + sz);
		if (npa != pa + sz)
			break;

		sz += _PAGE_SIZE;
	}

	if (sz < *psz)
		*psz = sz;

	return pa;
}
