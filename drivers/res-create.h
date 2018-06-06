/*
 * Phoenix-RTOS --- networking stack
 *
 * Utilities: cond/mutex bulk create
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * %LICENSE%
 */
#ifndef NETLIB_RES_CREATE_H_
#define NETLIB_RES_CREATE_H_

#include <stdint.h>
#include <sys/threads.h>


__attribute__((nonnull(1)))
int create_mutexcond_bulk(handle_t *out, size_t n, size_t cond_mask);


#endif /* NETLIB_RES_CREATE_H_ */
