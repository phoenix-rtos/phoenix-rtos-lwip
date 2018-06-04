/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer - thread support
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "arch/cc.h"
#include "arch/sys_arch.h"

#include <sys/threads.h>
#include <stdlib.h>
#include <string.h>


static struct {
	semaphore_t start_sem;
	void (*main)(void *arg);
} global;


static void thread_main(void *arg)
{
	void (*main)(void *arg);

	main = global.main;
	semaphoreUp(&global.start_sem);

	main(arg);

	endthread();
}


sys_thread_t sys_thread_new(const char *name, void (* thread)(void *arg), void *arg, int stacksize, int prio)
{
	handle_t id;
	void *stack;
	int err;

	stack = malloc(stacksize);
	if (!stack)
		bail("no memory for thread: %s\n", name);

	semaphoreDown(&global.start_sem, 0);
	global.main = thread;

	err = beginthreadex(thread_main, prio, stack, stacksize, arg, &id);
	if (err) {
		semaphoreUp(&global.start_sem);
		bail("beginthread error: %s\n", strerror(err));
	}

	return id;
}


void init_lwip_threads(void)
{
	int err;

	err = semaphoreCreate(&global.start_sem, 1);
	if (err)
		bail("semaphoreCreate(thread.start_sem) error: %s\n", strerror(err));
}
