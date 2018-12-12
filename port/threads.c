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

#include <sys/rb.h>
#include <sys/wait.h>
#include <sys/threads.h>
#include <stdlib.h>

typedef struct {
	rbnode_t linkage;
	handle_t tid;
	void *stack;
} thread_stack_t;

static struct {
	semaphore_t start_sem;
	void (*th_main)(void *arg);

	char collector_stack[4096] __attribute__((aligned(8)));
	rbtree_t stacks;
} global;


static void thread_main(void *arg)
{
	void (*th_main)(void *arg);

	th_main = global.th_main;
	semaphoreUp(&global.start_sem);

	th_main(arg);

	endthread();
}


static int thread_stack_cmp(rbnode_t *n1, rbnode_t *n2)
{
	thread_stack_t *s1 = lib_treeof(thread_stack_t, linkage, n1);
	thread_stack_t *s2 = lib_treeof(thread_stack_t, linkage, n2);

	if (s1->tid == s2->tid)
		return 0;

	else if (s1->tid > s2->tid)
		return 1;

	else
		return -1;
}


static void thread_register_stack(handle_t tid, void *stack)
{
	thread_stack_t *ts = malloc(sizeof(*ts));
	ts->tid = tid;
	ts->stack = stack;

	lib_rbInsert(&global.stacks, &ts->linkage);
}


static void thread_waittid_thr(void *arg)
{
	handle_t tid;
	thread_stack_t *stack, s;

	for (;;) {
		s.tid = waittid(-1, 0);
		stack = lib_treeof(thread_stack_t, linkage, lib_rbFind(&global.stacks, &s.linkage));

		if (stack != NULL) {
			lib_rbRemove(&global.stacks, &stack->linkage);
			free(stack->stack);
			free(stack);
		}
	}
}


int sys_thread_opt_new(const char *name, void (* thread)(void *arg), void *arg, int stacksize, int prio, handle_t *id)
{
	void *stack;
	int err;
	handle_t threadid;

	stack = malloc(stacksize);
	if (!stack)
		bail("no memory for thread: %s\n", name);

	semaphoreDown(&global.start_sem, 0);
	global.th_main = thread;

	err = beginthreadex(thread_main, prio, stack, stacksize, arg, &threadid);
	if (err) {
		semaphoreUp(&global.start_sem);
		free(stack);
	}

	thread_register_stack(threadid, stack);

	if (id != NULL)
		*id = threadid;

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

	lib_rbInit(&global.stacks, thread_stack_cmp, NULL);
	beginthreadex(thread_waittid_thr, 4, global.collector_stack, sizeof(global.collector_stack), NULL, NULL);
}
