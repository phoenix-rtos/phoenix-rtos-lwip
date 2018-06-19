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


static struct {
	semaphore_t start_sem;
	void (*th_main)(void *arg);
} global;


static void thread_main(void *arg)
{
	void (*th_main)(void *arg);

	th_main = global.th_main;
	semaphoreUp(&global.start_sem);

	th_main(arg);

	endthread();
}


int sys_thread_opt_new(const char *name, void (* thread)(void *arg), void *arg, int stacksize, int prio, handle_t *id)
{
	void *stack;
	int err;

	stack = malloc(stacksize);
	if (!stack)
		bail("no memory for thread: %s\n", name);

	semaphoreDown(&global.start_sem, 0);
	global.th_main = thread;

	err = beginthreadex(thread_main, prio, stack, stacksize, arg, id);
	if (err) {
		semaphoreUp(&global.start_sem);
		free(stack);
	}

	return err;
}


sys_thread_t sys_thread_new(const char *name, void (* thread)(void *arg), void *arg, int stacksize, int prio)
{
	handle_t id;
	int err;

	err = sys_thread_opt_new(name, thread, arg, stacksize, prio, &id);
	if (err)
		errout(err, "beginthread(%s)", name);

	return id;
}


void init_lwip_threads(void)
{
	int err;

	err = semaphoreCreate(&global.start_sem, 1);
	if (err)
		errout(err, "semaphoreCreate(thread.start_sem)");
}
