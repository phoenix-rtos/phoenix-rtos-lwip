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
#include <lwip/sockets.h>
#include <lwip/sys.h>

#include <errno.h>
#include <stdlib.h>
#include <sys/sockport.h>
#include <sys/threads.h>


#define SOCKTHREAD_PRIO 4
#define SOCKTHREAD_STACKSZ (SIZE_PAGE/4)


struct sock_start {
	u32 port;
	int sock;
};


static int wrap_socket(u32 *port, int sock, int flags);


static void socket_thread(void *arg)
{
	struct sock_start *ss = arg;
	unsigned respid;
	socklen_t salen;
	msg_t msg;
	u32 port = ss->port;
	int sock = ss->sock;
	int err;

	free(ss);

	while ((err = msgRecv(port, &msg, &respid)) >= 0) {
		const sockport_msg_t *smi = (const void *)msg.i.raw;
		sockport_resp_t *smo = (void *)msg.o.raw;
		u32 new_port;

		salen = sizeof(smo->sockname.addr);

		switch (msg.type) {
		case sockmConnect:
			smo->ret = lwip_connect(sock, (const void *)smi->send.addr, smi->send.addrlen) < 0 ? -errno : 0;
			break;
		case sockmBind:
			smo->ret = lwip_bind(sock, (const void *)smi->send.addr, smi->send.addrlen) < 0 ? -errno : 0;
			break;
		case sockmListen:
			smo->ret = lwip_listen(sock, smi->listen.backlog) < 0 ? -errno : 0;
			break;
		case sockmAccept:
			err = lwip_accept(sock, (void *)smo->sockname.addr, &salen);
			if (err >= 0) {
				err = wrap_socket(&new_port, smo->ret, smi->send.flags);
				smo->ret = err < 0 ? err : new_port;
			} else {
				smo->ret = -errno;
			}
			break;
		case sockmSend:
			smo->ret = lwip_sendto(sock, msg.i.data, msg.i.size, smi->send.flags, (const void *)smi->send.addr, smi->send.addrlen);
			if (smo->ret < 0)
				smo->ret = -errno;
			break;
		case sockmRecv:
			smo->ret = lwip_recvfrom(sock, msg.o.data, msg.o.size, smi->send.flags, (void *)smo->sockname.addr, &salen);
			if (smo->ret < 0)
				smo->ret = -errno;
			smo->sockname.addrlen = salen;
			break;
		case sockmGetSockName:
			smo->ret = lwip_getsockname(sock, (void *)smo->sockname.addr, &salen) < 0 ? -errno : 0;
			smo->sockname.addrlen = salen;
			break;
		case sockmGetPeerName:
			smo->ret = lwip_getpeername(sock, (void *)smo->sockname.addr, &salen) < 0 ? -errno : 0;
			smo->sockname.addrlen = salen;
			break;
		case sockmGetFl:
			smo->ret = lwip_fcntl(sock, F_GETFL, 0);
			break;
		case sockmSetFl:
			smo->ret = lwip_fcntl(sock, F_SETFL, smi->send.flags);
			break;
		case sockmGetOpt:
			salen = msg.o.size;
			smo->ret = lwip_getsockopt(sock, smi->opt.level, smi->opt.optname, msg.o.data, &salen) < 0 ? -errno : salen;
			break;
		case sockmSetOpt:
			smo->ret = lwip_setsockopt(sock, smi->opt.level, smi->opt.optname, msg.i.data, msg.i.size) < 0 ? -errno : 0;
			break;
		case sockmShutdown:
			smo->ret = lwip_shutdown(sock, smi->send.flags) < 0 ? -errno : 0;
			break;
		case mtRead:
			msg.o.io.err = lwip_read(sock, msg.o.data, msg.o.size);
			break;
		case mtWrite:
			msg.o.io.err = lwip_write(sock, msg.i.data, msg.i.size);
			break;
		case mtClose:
			msg.o.io.err = lwip_close(sock) < 0 ? -errno : 0;
			msgRespond(port, &msg, respid);
			return;
		default:
			smo->ret = -EINVAL;
		}
		msgRespond(port, &msg, respid);
	}

	errout(err, "msgRecv(socketsrv)");
}


static int wrap_socket(u32 *port, int sock, int flags)
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

	*port = ss->port;

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
	unsigned respid;
	msg_t msg;
	u32 port;
	int err, sock;

	port = (unsigned)arg;

	while ((err = msgRecv(port, &msg, &respid)) >= 0) {
		if (msg.type == sockmSocket) {
			const sockport_msg_t *smi = (const void *)msg.i.raw;

			if ((sock = lwip_socket(smi->socket.domain, smi->socket.type, smi->socket.protocol)) < 0)
				msg.o.lookup.err = -errno;
			else
				msg.o.lookup.err = wrap_socket(&msg.o.lookup.res.port, sock, smi->socket.type);
		} else {
			msg.o.io.err = -EINVAL;
		}

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

	if ((err = portRegister(oid.port, PATH_SOCKSRV, &oid))) {
		portDestroy(oid.port);
		errout(err, "portRegister(%s)", PATH_SOCKSRV);
	}

	if ((err = sys_thread_opt_new("socketsrv", socketsrv_thread, (void *)oid.port, SOCKTHREAD_STACKSZ, SOCKTHREAD_PRIO, NULL))) {
		portDestroy(oid.port);
		errout(err, "thread(socketsrv)");
	}
}
