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

#include <sys/mman.h>
#include <sys/rb.h>
#include <sys/wait.h>
#include <sys/threads.h>
#include <stdlib.h>
#include <errno.h>

#define STACK_SIZE SIZE_PAGE

typedef struct {
	rbnode_t linkage;
	handle_t tid;
	void *stack;
} thread_stack_t;

static struct {
	semaphore_t start_sem;
	void (*th_main)(void *arg);

	rbtree_t stacks;
	handle_t lock;
} global;


static void *alloc_stack(void)
{
	void *stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, NULL, 0);

	return stack != MAP_FAILED ? stack : NULL;
}

static void free_stack(void *stack)
{
	munmap(stack, STACK_SIZE);
}

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

	mutexLock(global.lock);
	lib_rbInsert(&global.stacks, &ts->linkage);
	mutexUnlock(global.lock);
}


static void thread_waittid_thr(void *arg)
{
	thread_stack_t *stack, s;

	for (;;) {
		while ((s.tid = threadJoin(0)) == -EINTR)
			;

		mutexLock(global.lock);
		stack = lib_treeof(thread_stack_t, linkage, lib_rbFind(&global.stacks, &s.linkage));
		if (stack != NULL) {
			lib_rbRemove(&global.stacks, &stack->linkage);
			mutexUnlock(global.lock);

			free_stack(stack->stack);
			free(stack);
		}
		else {
			mutexUnlock(global.lock);
		}
	}
}

int sys_thread_opt_new(const char *name, void (* thread)(void *arg), void *arg, int ignored_stacksize, int prio, handle_t *id)
{
	void *stack;
	int err;
	handle_t threadid;

	if (!(stack = alloc_stack()))
		bail("no memory for thread: %s\n", name);

	semaphoreDown(&global.start_sem, 0);
	global.th_main = thread;

	err = beginthreadex(thread_main, prio, stack, STACK_SIZE, arg, &threadid);
	if (err) {
		semaphoreUp(&global.start_sem);
		free_stack(stack);
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
	void *stack;
	int err;

	err = mutexCreate(&global.lock);
	if (err)
		errout(err, "mutexCreate(thread.start_sem)");

	err = semaphoreCreate(&global.start_sem, 1);
	if (err)
		errout(err, "semaphoreCreate(thread.start_sem)");

	if (!(stack = alloc_stack()))
		bail("no memory for stack collector thread\n");

	lib_rbInit(&global.stacks, thread_stack_cmp, NULL);
	beginthreadex(thread_waittid_thr, 4, stack, STACK_SIZE, NULL, NULL);
}
