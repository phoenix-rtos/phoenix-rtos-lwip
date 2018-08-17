/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer - mailboxes
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "arch/cc.h"
#include "arch/sys_arch.h"
#include "lwip/err.h"
#include "lwip/sys.h"

#include <sys/threads.h>
#include <sys/time.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>


err_t sys_mbox_new(sys_mbox_t *mbox, int size)
{
	if (!mbox)
		return ERR_ARG;

	if (mutexCreate(&mbox->lock))
		return ERR_MEM;

	if (condCreate(&mbox->push_cond)) {
		resourceDestroy(mbox->lock);
		return ERR_MEM;
	}

	if (condCreate(&mbox->pop_cond)) {
		resourceDestroy(mbox->push_cond);
		resourceDestroy(mbox->lock);
		return ERR_MEM;
	}

	mbox->ring = calloc(size, sizeof(*mbox->ring));
	if (!mbox->ring) {
		resourceDestroy(mbox->pop_cond);
		resourceDestroy(mbox->push_cond);
		resourceDestroy(mbox->lock);
		return ERR_MEM;
	}

	mbox->sz = size;
	mbox->head = mbox->tail = 0;

	return ERR_OK;
}


void sys_mbox_free(sys_mbox_t *mbox)
{
	free(mbox->ring);
	resourceDestroy(mbox->pop_cond);
	resourceDestroy(mbox->push_cond);
	resourceDestroy(mbox->lock);
}


#define WRAP(m,t) ((m)->t + 1 < (m)->sz ? (m)->t + 1 : 0)


static int mbox_is_empty(sys_mbox_t *mbox)
{
	return mbox->head == mbox->tail;
}


static int mbox_is_full(sys_mbox_t *mbox)
{
	return WRAP(mbox, tail) == mbox->head;
}


static int mbox_trypost(sys_mbox_t *mbox, void *msg)
{
	if (mbox_is_full(mbox))
		return 0;

	if (mbox_is_empty(mbox))
		condSignal(mbox->push_cond);

	mbox->ring[mbox->tail] = msg;
	mbox->tail = WRAP(mbox, tail);
	return 1;
}


err_t sys_mbox_trypost(sys_mbox_t *mbox, void *msg)
{
	int done;

	mutexLock(mbox->lock);
	done = mbox_trypost(mbox, msg);
	mutexUnlock(mbox->lock);

	return done ? ERR_OK : ERR_WOULDBLOCK;
}


void sys_mbox_post(sys_mbox_t *mbox, void *msg)
{
	mutexLock(mbox->lock);

	while (!mbox_trypost(mbox, msg))
		condWait(mbox->pop_cond, mbox->lock, 0);

	mutexUnlock(mbox->lock);
}


static int mbox_tryfetch(sys_mbox_t *mbox, void **msg)
{
	if (mbox_is_empty(mbox))
		return 0;

	if (mbox_is_full(mbox))
		condSignal(mbox->pop_cond);

	*msg = mbox->ring[mbox->head];
	mbox->head = WRAP(mbox, head);
	return 1;
}


u32_t sys_arch_mbox_tryfetch(sys_mbox_t *mbox, void **msg)
{
	int done;

	mutexLock(mbox->lock);
	done = mbox_tryfetch(mbox, msg);
	mutexUnlock(mbox->lock);

	return done ? 0 : SYS_MBOX_EMPTY;
}


u32_t sys_arch_mbox_fetch(sys_mbox_t *mbox, void **msg, u32_t timeout_ms)
{
	time_t since, now, when, timeout;
	int found = 1;

	timeout = timeout_ms * 1000;
	gettime(&now, NULL);
	since = now;
	when = now + timeout;

	mutexLock(mbox->lock);

	while (!mbox_tryfetch(mbox, msg)) {
		condWait(mbox->push_cond, mbox->lock, timeout);
		if (!timeout)
			continue;

		gettime(&now, NULL);
		if (now >= when) {
			found = 0;
			break;
		}
		timeout = when - now;
	}

	mutexUnlock(mbox->lock);

	if (!found)
		return SYS_ARCH_TIMEOUT;

	gettime(&now, NULL);
	return (now - since) / 1000;
}
