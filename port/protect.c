/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer - global lock
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "arch/cc.h"
#include "arch/sys_arch.h"

#include <sys/threads.h>


static handle_t global_mutex;
static volatile handle_t locked_thread;
static unsigned lock_recursion;


void sys_arch_global_lock(void)
{
	handle_t self = gettid();
	if (!self)
		self = ~self;

	if (locked_thread != self) {
		mutexLock(global_mutex);
		locked_thread = self;
	}

	++lock_recursion;
}


void sys_arch_global_unlock(void)
{
	if (--lock_recursion)
		return;

	locked_thread = 0;
	mutexUnlock(global_mutex);
}


void init_lwip_global_lock(void)
{
	int err = mutexCreate(&global_mutex);

	if (err)
		errout(err, "mutexCreate(global_lock)");
}
