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
#include <errno.h>

#include <lwipopts.h>


typedef struct {
	rbnode_t linkage;
	handle_t tid;
	void *stack;
	void (*work)(void *arg);
	void *arg;

	struct __errno_t err;
} thread_data_t;


static struct {
	rbtree_t threads;
	handle_t lock;
} global;


static int thread_cmp(rbnode_t *n1, rbnode_t *n2)
{
	thread_data_t *s1 = lib_treeof(thread_data_t, linkage, n1);
	thread_data_t *s2 = lib_treeof(thread_data_t, linkage, n2);

	if (s1->tid == s2->tid) {
		return 0;
	}
	else if (s1->tid > s2->tid) {
		return 1;
	}
	else {
		return -1;
	}
}


static void thread_register(thread_data_t *ts)
{
	thread_data_t *old, s;

	s.tid = ts->tid;

	(void)mutexLock(global.lock);
	old = lib_treeof(thread_data_t, linkage, lib_rbFind(&global.threads, &s.linkage));
	if (old != NULL) {
		_errno_remove(&old->err);
		lib_rbRemove(&global.threads, &old->linkage);
	}

	(void)lib_rbInsert(&global.threads, &ts->linkage);
	(void)mutexUnlock(global.lock);
	_errno_new(&ts->err);

	if (old != NULL) {
		free(old->stack);
		free(old);
	}
}


static void thread_main(void *arg)
{
	thread_data_t *t = arg;
	thread_register(t);
	t->work(t->arg);
	endthread();
}


int sys_thread_opt_new(const char *name, void (*thread)(void *arg), void *arg, int stacksize, int prio, handle_t *id)
{
	void *stack;
	int err;
	thread_data_t *ts;

	stack = malloc(stacksize);
	if (stack == NULL) {
		bail("no memory for thread: %s\n", name);
	}

	ts = malloc(sizeof(*ts));
	if (ts == NULL) {
		free(stack);
		bail("no memory for thread: %s\n", name);
	}

	ts->work = thread;
	ts->stack = stack;
	ts->arg = arg;

	(void)mutexLock(global.lock);
	err = beginthreadex(thread_main, prio, stack, stacksize, ts, &ts->tid);

	if (err != 0) {
		free(stack);
		free(ts);
	}
	else if (id != NULL) {
		*id = ts->tid;
	}

	(void)mutexUnlock(global.lock);

	return err;
}


sys_thread_t sys_thread_new(const char *name, void (*thread)(void *arg), void *arg, int stacksize, int prio)
{
	handle_t id;
	int err;

	err = sys_thread_opt_new(name, thread, arg, stacksize, prio, &id);
	if (err != 0) {
		errout(err, "beginthread(%s)", name);
	}

	return id;
}


int sys_thread_join(handle_t id)
{
	thread_data_t *data, s;
	int res;

	if (id == gettid()) {
		return -1;
	}

	do {
		res = threadJoin(id, 0);
	} while (res == -EINTR);

	if (res < 0) {
		return -1;
	}

	s.tid = id;

	(void)mutexLock(global.lock);

	data = lib_treeof(thread_data_t, linkage, lib_rbFind(&global.threads, &s.linkage));
	if (data != NULL) {
		lib_rbRemove(&global.threads, &data->linkage);
		(void)mutexUnlock(global.lock);

		_errno_remove(&data->err);
		free(data->stack);
		free(data);
	}
	else {
		(void)mutexUnlock(global.lock);
	}

	return 0;
}


void init_lwip_threads(void)
{
	int err;

	err = mutexCreate(&global.lock);
	if (err != EOK) {
		errout(err, "mutexCreate(lock)");
	}

	lib_rbInit(&global.threads, thread_cmp, NULL);
}
