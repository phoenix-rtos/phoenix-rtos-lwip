/*
 * Phoenix-RTOS --- networking stack
 *
 * Utilities: HW debugging helpers
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * %LICENSE%
 */
#ifndef NETLIB_PHYSMMAP_H_
#define NETLIB_PHYSMMAP_H_

#include <stdint.h>
#include <sys/mman.h>


void *dmammap(size_t sz) __attribute__((malloc, alloc_size(1), assume_aligned(_PAGE_SIZE)));

volatile void *physmmap(addr_t addr, size_t sz);
void physunmap(volatile void *va, size_t sz);


#endif /* NETLIB_PHYSMMAP_H_ */
