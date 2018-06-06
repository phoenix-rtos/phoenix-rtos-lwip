/*
 * Phoenix-RTOS --- networking stack
 *
 * Utilities: service loop
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * %LICENSE%
 */
#include <sys/mman.h>
#include "hw-debug.h"
#include "physmmap.h"


uint32_t hwdebug_read(addr_t addr)
{
	volatile uint32_t *va = physmmap(addr, sizeof(*va));
	uint32_t v;

	if (va == (void *)-1)
		return 0;

	v = *va;

	physunmap(va, sizeof(*va));

	return v;
}
