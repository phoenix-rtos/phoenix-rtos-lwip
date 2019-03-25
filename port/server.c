/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer - BSD sockets server
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "arch/cc.h"
#include "arch/sys_arch.h"

#include <lwip/sockets.h>

#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/threads.h>
#include <posix/utils.h>

#include "sockets.h"


//TODO// #define HAVE_EVENTFD
#define POLL_WAIT_INTERVAL_US 1000
#define SOCKTHREAD_PRIO 4
#define SOCK_TAB_INCREMENT 16


static struct {
	u32 port;
	size_t n_sock_fds;
	struct sock_info *sock_tab;
	id_t sock_last_free;
#ifdef HAVE_EVENTFD
	struct deferred_msg trigger;
#endif
	struct deferred_msg *pending_adds;
} global;


static void set_pending_adds(struct deferred_msg *list)
{
	// assumes global.pending_adds == NULL

#ifdef HAVE_BUILTIN_ATOMICS
	__atomic_store_n(&global.pending_adds, list, __ATOMIC_RELEASE);
#else
	__sync_fetch_and_or(&global.pending_adds, list);
#endif
}


static struct deferred_msg *take_pending_adds(void)
{
	struct deferred_msg *v, *ov;

#ifdef HAVE_BUILTIN_ATOMICS
	ov = NULL;
	__atomic_exchange(&global.pending_adds, &ov, &v, __ATOMIC_ACQUIRE);
#else
	(void)ov;
	v = __sync_fetch_and_and(&global.pending_adds, NULL);	// assumes NULL == 0
#endif

	return v;
}


#ifdef HAVE_EVENTFD

static int init_poll_trigger(struct deferred_msg *trigger)
{
	// lwip_socketpair() is missing...
	// eventfd is missing...

	trigger->type = mtRead;
	trigger->pid = getpid();
	trigger->buf = trigger->addr;
	trigger->buflen = sizeof(trigger->addr);

	return 0;
}


static int send_trigger(struct deferred_msg *trigger)
{
	return lwip_write((int)trigger->oid.id, trigger, 1);
}


static int process_trigger(struct deferred_msg *dm)
{
	struct deferred_msg *v;

	if (dm != &global.trigger)
		return 0;

	if ((v = take_pending_adds()))
		dm_set_next(&dm->next, v);

	poll_add(dm);

	return 1;
}

#endif /* HAVE_EVENTFD */


static int get_socket(const msg_t *msg, struct sock_info **out_sock)
{
	const sockport_msg_t *smi = (const void *)msg->i.raw;
	struct sock_info *sock;
	id_t id;

	switch (msg->type) {
	case mtRead:
	case mtWrite:
		id = msg->i.io.oid.id;
		break;
	case mtGetAttr:
		id = msg->i.attr.oid.id;
		break;
	case mtClose:
		id = msg->i.openclose.oid.id;
		break;
	case mtDevCtl:	/* ioctl */
		ioctl_unpack(msg, NULL, &id);
		break;
	case sockmConnect:
	case sockmBind:
	case sockmListen:
	case sockmAccept:
	case sockmSend:
	case sockmRecv:
	case sockmGetSockName:
	case sockmGetPeerName:
	case sockmGetFl:
	case sockmSetFl:
	case sockmGetOpt:
	case sockmSetOpt:
	case sockmShutdown:
		id = smi->send.sock_id;
		break;
	default:
		return -EINVAL;
	}

	if (id < 0 || id >= global.n_sock_fds)
		return -EBADF;

	sock = global.sock_tab + id;
	if (!sock->is_open)
		return -EBADF;

	if (sock->used.owner_pid != msg->pid)
		if (msg->type != mtClose)	/* FIXME: kernel bug */
			return -EBADF;

	if (out_sock)
		*out_sock = sock;

	return sock->used.lwip_fd;
}


int init_socket(oid_t *oid, int sock_fd, int flags, unsigned int pid)
{
	struct sock_info *sock;

	if (global.sock_last_free == global.n_sock_fds) {
		struct sock_info *tab;
		int i;

		// FIXME: check size overflow
		// FIXME: tree instead of table?

		tab = realloc(global.sock_tab, (global.n_sock_fds + SOCK_TAB_INCREMENT) * sizeof(*tab));
		if (!tab)
			return -ENOMEM;
		global.sock_tab = tab;

		memset(tab + global.n_sock_fds, 0, SOCK_TAB_INCREMENT * sizeof(*tab));
		for (i = 0; i < SOCK_TAB_INCREMENT; ++i)
			tab[global.n_sock_fds + i].free.next = global.n_sock_fds + i + 1;

		asm volatile ("" ::: "memory");
		global.n_sock_fds += SOCK_TAB_INCREMENT;
	}

	oid->port = global.port;
	oid->id = global.sock_last_free;

	sock = global.sock_tab + global.sock_last_free;
	global.sock_last_free = sock->free.next;

	sock->used.lwip_fd = sock_fd;
	sock->used.owner_pid = pid;
	sock->is_open = 1;
	sock->is_blocking = !(flags & SOCK_NONBLOCK);

	return EOK;
}


void remove_socket(struct sock_info *sock_info)
{
	sock_info->is_open = 0;
	sock_info->free.next = global.sock_last_free;
	global.sock_last_free = sock_info - global.sock_tab;

	// FIXME: realloc when lots of free entries at end of sock_tab?
}


static int defer_blocking_call(msg_t *msg, unsigned int respid, struct sock_info *sock_info, int err)
{
	const sockport_msg_t *smi = (const void *)msg->i.raw;
	struct deferred_msg *dm, *new_dm;

	if (!sock_info->is_blocking)
		return err;

	switch (msg->type) {
	case sockmSend:
	case sockmRecv:
		if (smi->send.flags & MSG_DONTWAIT)
			return err;
		break;
	}

	switch (msg->type) {
	case sockmConnect:
	case sockmAccept:
	case sockmSend:
	case sockmRecv:
	case mtRead:
	case mtWrite:
		dm = calloc(1, sizeof(*dm));
		if (!dm)
			return -ENOMEM;

		dm->type = msg->type;
		dm->pid = msg->pid;
		dm->respid = respid;
		dm->oid.port = smi->send.flags;
		dm->oid.id = sock_info->used.lwip_fd;
		break;
	default:
		return err;
	}

	switch (msg->type) {
	case sockmConnect:
	case sockmAccept:
	case sockmSend:
	case sockmRecv:
		dm->addrlen = MAX_SOCKNAME_LEN;
		break;
	}

	switch (msg->type) {
	case sockmSend:
	case mtWrite:
		dm->buf = (void *)msg->i.data;
		dm->buflen = msg->i.size;
		break;

	case sockmRecv:
	case mtRead:
		dm->buf = (void *)msg->o.data;
		dm->buflen = msg->o.size;
		break;
	}

	if ((new_dm = take_pending_adds()))
		dm_set_next(&dm->next, new_dm);
	set_pending_adds(dm);

#ifdef HAVE_EVENTFD
	send_trigger(&global.trigger);
#endif
	return EOK;
}


static void set_msg_status(msg_t *msg, ssize_t ret)
{
	sockport_resp_t *smo = (void *)msg->o.raw;

	switch (msg->type) {
	case mtRead:
	case mtWrite:
	case mtClose:
		msg->o.io.err = ret;
		break;
	case mtGetAttr:
		msg->o.attr.val = ret;
		break;
	case mtDevCtl:
		/* filled already */
		break;
	default:
		smo->ret = ret;
		break;
	}
}


void finish_deferred_call(struct deferred_msg *dm, ssize_t ret)
{
	msg_t msg = { 0, };
	sockport_resp_t *smo = (void *)msg.o.raw;

#ifdef HAVE_EVENTFD
	if (process_trigger(dm))
		return;
#endif
	msg.type = dm->type;
	msg.pid = dm->pid;

	switch (dm->type) {
	case sockmAccept:
	case sockmRecv:
		memcpy(smo->sockname.addr, dm->addr, dm->addrlen);
		smo->sockname.addrlen = dm->addrlen;
		break;
	}

	switch (dm->type) {
	case sockmRecv:
	case mtRead:
		msg.o.data = dm->buf;
		msg.o.size = dm->buflen;
		break;
	}

	set_msg_status(&msg, ret);
	msgRespond(global.port, &msg, dm->respid);

	free(dm);
}


static int wrap_socket_op(msg_t *msg, unsigned int respid)
{
	struct sock_info *sock_info = NULL /* silence gcc */;
	int err;

	do {
		err = get_socket(msg, &sock_info);
		/* mtDevCtl has its own different error handling - see do_socket_ioctl() */
		if (err < 0 && msg->type != mtDevCtl)
			break;

		err = socket_op(msg, err, sock_info);
		if (!sock_info)
			break;
		if (err != (msg->type == sockmConnect ? -EINPROGRESS : -EAGAIN))
			break;

		err = defer_blocking_call(msg, respid, sock_info, err);
		if (!err)
			return 1;
	} while (0);

	set_msg_status(msg, err);
	return 0;
}


static void socketpoll_thread(void *arg)
{
	ssize_t err;

#ifdef HAVE_EVENTFD
	if (poll_add(&global.trigger))
		errout(ENOMEM, "poll_add");
#endif

	do {
#ifdef HAVE_EVENTFD
		err = poll_wait(~(useconds_t)0);
#else
		struct deferred_msg *v;

		if ((v = take_pending_adds())) {
			struct deferred_msg *rejected = poll_add(v);
			for (; rejected; rejected = v) {
				v = rejected->next;
				finish_deferred_call(rejected, -ENOMEM);
			}
		}
		err = poll_wait(POLL_WAIT_INTERVAL_US);
#endif
	} while (!err);

	errout(err, "socketpoll");
}


static void socketsrv_thread(void *arg)
{
	msg_t msg;
	unsigned respid;
	u32 port = global.port;
	int err;

	while ((err = msgRecv(port, &msg, &respid)) >= 0) {
		if (!network_op(&msg) && wrap_socket_op(&msg, respid))
			continue;
		msgRespond(port, &msg, respid);
	}

	errout(err, "msgRecv(socketsrv)");
}


__constructor__(1001)
void init_lwip_sockets(void)
{
	oid_t oid = { 0, -1 };
	int err;
#ifdef HAVE_EVENTFD
	if ((err = init_poll_trigger(&global.trigger)) < 0)
		errout(err, "init_poll_trigger()");
#endif
	if ((err = portCreate(&oid.port)) < 0)
		errout(err, "portCreate(socketsrv)");

	// in case /dev doesn't exist yet (eg. on just dummyfs)
	mkdir("/dev", 0777);

	if ((err = create_dev(&oid, PATH_SOCKSRV)))
		errout(err, "create_dev(%s)", PATH_SOCKSRV);

	global.port = oid.port;

	if ((err = sys_thread_opt_new("socketsrv", socketsrv_thread, NULL, 0, SOCKTHREAD_PRIO, NULL)))
		errout(err, "thread(socketsrv)");

	if ((err = sys_thread_opt_new("socketpoll", socketpoll_thread, NULL, 0, SOCKTHREAD_PRIO, NULL)))
		errout(err, "thread(socketpoll)");
}
