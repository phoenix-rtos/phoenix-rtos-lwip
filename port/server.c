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
#include <lwip/netdb.h>
#include <lwip/sockets.h>
#include <lwip/sys.h>
#include <lwip/netif.h>

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/sockport.h>
#include <sys/sockios.h>
#include <net/if.h>
#include <net/route.h>
#include <net/if_arp.h>
#include <sys/threads.h>
#include <posix/utils.h>


#define SOCKTHREAD_PRIO 4
#define SOCKTHREAD_STACKSZ (2 * SIZE_PAGE)


struct sock_start {
	u32 port;
	int sock;
};


int socket_op(msg_t *msg, int sock);
void network_op(msg_t *msg);


static void socket_thread(void *arg)
{
	struct sock_start *ss = arg;
	unsigned respid;
	u32 port = ss->port;
	int sock = ss->sock, err;
	msg_t msg;

	free(ss);

	while ((err = msgRecv(port, &msg, &respid)) >= 0) {
		err = socket_op(&msg, sock);
		msgRespond(port, &msg, respid);
		if (err)
			break;
	}

	portDestroy(port);
	if (err >= 0)
		lwip_close(sock);
}


int wrap_socket(oid_t *oid, int sock, int flags)
{
	struct sock_start *ss;
	int err;

	if ((flags & SOCK_NONBLOCK) && (err = lwip_fcntl(sock, F_SETFL, O_NONBLOCK)) < 0) {
		lwip_close(sock);
		return err;
	}

	ss = malloc(sizeof(*ss));
	if (!ss) {
		lwip_close(sock);
		return -ENOMEM;
	}

	ss->sock = sock;

	if ((err = portCreate(&ss->port)) < 0) {
		lwip_close(ss->sock);
		free(ss);
		return err;
	}

	oid->port = ss->port;
	oid->id = 0;

	if ((err = sys_thread_opt_new("socket", socket_thread, ss, SOCKTHREAD_STACKSZ, SOCKTHREAD_PRIO, NULL))) {
		portDestroy(ss->port);
		lwip_close(ss->sock);
		free(ss);
		return err;
	}

	return EOK;
}


static void socketsrv_thread(void *arg)
{
	msg_t msg;
	unsigned respid;
	u32 port = (unsigned)arg;
	int err;

	while ((err = msgRecv(port, &msg, &respid)) >= 0) {
		network_op(&msg);
		msgRespond(port, &msg, respid);
	}

	errout(err, "msgRecv(socketsrv)");
}


__constructor__(1000)
void init_lwip_sockets(void)
{
	oid_t oid = { 0 };
	int err;

	if ((err = portCreate(&oid.port)) < 0)
		errout(err, "portCreate(socketsrv)");

	if ((err = create_dev(&oid, PATH_SOCKSRV))) {
		errout(err, "create_dev(%s)", PATH_SOCKSRV);
	}

	if ((err = sys_thread_opt_new("socketsrv", socketsrv_thread, (void *)oid.port, SOCKTHREAD_STACKSZ, SOCKTHREAD_PRIO, NULL))) {
		portDestroy(oid.port);
		errout(err, "thread(socketsrv)");
	}
}
