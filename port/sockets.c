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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/sockport.h>
#include <sys/threads.h>


#define SOCKTHREAD_PRIO 4
#define SOCKTHREAD_STACKSZ (SIZE_PAGE/4)


struct sock_start {
	u32 port;
	int sock;
};


static int wrap_socket(u32 *port, int sock, int flags);


// oh crap, there is no lwip_poll() ...
static int poll_one(int socket, int events, time_t timeout)
{
	struct timeval to;
	fd_set rd, wr, ex;
	int err;

	FD_ZERO(&rd);
	FD_ZERO(&wr);
	FD_ZERO(&ex);

	if (events & POLLIN)
		FD_SET(socket, &rd);
	if (events & POLLOUT)
		FD_SET(socket, &wr);
	if (events & POLLPRI)
		FD_SET(socket, &ex);

	to.tv_sec = timeout / 1000000;
	to.tv_usec = timeout % 1000000;

	if ((err = lwip_select(socket + 1, &rd, &wr, &ex, timeout >= 0 ? &to : NULL)) < 0)
		return -errno;

	events = 0;
	if (FD_ISSET(socket, &rd))
		events |= POLLIN;
	if (FD_ISSET(socket, &wr))
		events |= POLLOUT;
	if (FD_ISSET(socket, &ex))
		events |= POLLPRI;

	return events;
}


static const struct sockaddr *sa_convert_lwip_to_sys(const void *sa)
{
	// hack warning
	*(uint16_t *)sa = ((uint8_t *)sa)[1];
	return sa;
}


static const struct sockaddr *sa_convert_sys_to_lwip(const void *sa, socklen_t salen)
{
	uint16_t fam = *(volatile uint16_t *)sa;
	struct sockaddr *lsa = (void *)sa;

	lsa->sa_len = (uint8_t)salen;
	lsa->sa_family = (sa_family_t)fam;

	return lsa;
}


static void socket_thread(void *arg)
{
	struct sock_start *ss = arg;
	unsigned respid;
	socklen_t salen;
	msg_t msg;
	u32 port = ss->port;
	int sock = ss->sock;
	int shutmode = 0;
	int err;

	free(ss);

	while ((err = msgRecv(port, &msg, &respid)) >= 0) {
		const sockport_msg_t *smi = (const void *)msg.i.raw;
		sockport_resp_t *smo = (void *)msg.o.raw;
		u32 new_port;

		salen = sizeof(smo->sockname.addr);

		switch (msg.type) {
		case sockmPoll:
			smo->ret = poll_one(sock, smi->poll.events, smi->poll.timeout);
			break;
		case sockmConnect:
			smo->ret = lwip_connect(sock, sa_convert_sys_to_lwip(smi->send.addr, smi->send.addrlen), smi->send.addrlen) < 0 ? -errno : 0;
			break;
		case sockmBind:
			smo->ret = lwip_bind(sock, sa_convert_sys_to_lwip(smi->send.addr, smi->send.addrlen), smi->send.addrlen) < 0 ? -errno : 0;
			break;
		case sockmListen:
			smo->ret = lwip_listen(sock, smi->listen.backlog) < 0 ? -errno : 0;
			break;
		case sockmAccept:
			err = lwip_accept(sock, (void *)smo->sockname.addr, &salen);
			if (err >= 0) {
				sa_convert_lwip_to_sys(smo->sockname.addr);
				err = wrap_socket(&new_port, smo->ret, smi->send.flags);
				smo->ret = err < 0 ? err : new_port;
			} else {
				smo->ret = -errno;
			}
			break;
		case sockmSend:
			smo->ret = lwip_sendto(sock, msg.i.data, msg.i.size, smi->send.flags,
				sa_convert_sys_to_lwip(smi->send.addr, smi->send.addrlen), smi->send.addrlen);
			if (smo->ret < 0)
				smo->ret = -errno;
			break;
		case sockmRecv:
			smo->ret = lwip_recvfrom(sock, msg.o.data, msg.o.size, smi->send.flags, (void *)smo->sockname.addr, &salen);
			if (smo->ret < 0)
				smo->ret = -errno;
			else
				sa_convert_lwip_to_sys(smo->sockname.addr);
			smo->sockname.addrlen = salen;
			break;
		case sockmGetSockName:
			smo->ret = lwip_getsockname(sock, (void *)smo->sockname.addr, &salen) < 0 ? -errno : 0;
			if (smo->ret >= 0)
				sa_convert_lwip_to_sys(smo->sockname.addr);
			smo->sockname.addrlen = salen;
			break;
		case sockmGetPeerName:
			smo->ret = lwip_getpeername(sock, (void *)smo->sockname.addr, &salen) < 0 ? -errno : 0;
			if (smo->ret >= 0)
				sa_convert_lwip_to_sys(smo->sockname.addr);
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
			if (smi->send.flags < 0 || smi->send.flags > SHUT_RDWR) {
				smo->ret = -EINVAL;
				break;
			}

			smo->ret = lwip_shutdown(sock, smi->send.flags) < 0 ? -errno : 0;
			shutmode |= smi->send.flags + 1;
			if (shutmode != 3)
				break;

			/* closed */
			msgRespond(port, &msg, respid);
			portDestroy(port);
			return;
		case mtRead:
			msg.o.io.err = lwip_read(sock, msg.o.data, msg.o.size);
			break;
		case mtWrite:
			msg.o.io.err = lwip_write(sock, msg.i.data, msg.i.size);
			break;
		case mtClose:
			msg.o.io.err = lwip_close(sock) < 0 ? -errno : 0;
			msgRespond(port, &msg, respid);
			portDestroy(port);
			return;
		default:
			smo->ret = -EINVAL;
		}
		msgRespond(port, &msg, respid);
	}
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


static int do_getnameinfo(const struct sockaddr *addr, socklen_t addrlen, char *host, socklen_t hostsz, char *serv, socklen_t servsz, int flags)
{
	errno = ENOSYS;
	return EAI_SYSTEM;
}


static int do_getaddrinfo(const char *name, const char *serv, const struct addrinfo *hints, void *buf, size_t *buflen)
{
	struct addrinfo *res, *ai, *dest;
	size_t n, addr_needed, str_needed;
	void *addrdest, *strdest;
	int err;

	if ((err = lwip_getaddrinfo(name, serv, hints, &res)))
		return err;

	n = addr_needed = str_needed = 0;
	for (ai = res; ai; ai = ai->ai_next) {
		++n;
		if (ai->ai_addrlen)
			addr_needed += (ai->ai_addrlen + sizeof(size_t) - 1) & ~(sizeof(size_t) - 1);
		if (ai->ai_canonname)
			str_needed += strlen(ai->ai_canonname) + 1;
	}

	str_needed += n * sizeof(*ai) + addr_needed;
	if (*buflen < str_needed) {
		*buflen = str_needed;
		if (res)
			lwip_freeaddrinfo(res);
		return EAI_OVERFLOW;
	}

	*buflen = str_needed;
	dest = buf;
	addrdest = buf + n * sizeof(*ai);
	strdest = addrdest + addr_needed;

	for (ai = res; ai; ai = ai->ai_next) {
		dest->ai_flags = ai->ai_flags;
		dest->ai_family = ai->ai_family;
		dest->ai_socktype = ai->ai_socktype;
		dest->ai_protocol = ai->ai_protocol;

		if ((dest->ai_addrlen = ai->ai_addrlen)) {
			memcpy(addrdest, ai->ai_addr, ai->ai_addrlen);
			sa_convert_lwip_to_sys(addrdest);
			dest->ai_addr = (void *)(addrdest - buf);
			addrdest += (ai->ai_addrlen + sizeof(size_t) - 1) & ~(sizeof(size_t) - 1);
		}

		if (ai->ai_canonname) {
			n = strlen(ai->ai_canonname) + 1;
			memcpy(strdest, ai->ai_canonname, n);
			dest->ai_canonname = (void *)(strdest - buf);
			strdest += n;
		} else
			dest->ai_canonname = NULL;

		dest->ai_next = ai->ai_next ? (void *)((void *)(dest + 1) - buf) : NULL;
		++dest;
	}

	if (res)
		lwip_freeaddrinfo(res);

	return 0;
}


static void socketsrv_thread(void *arg)
{
	struct addrinfo hint = { 0 };
	unsigned respid;
	char *node, *serv;
	size_t sz;
	msg_t msg;
	u32 port;
	int err, sock;

	port = (unsigned)arg;

	while ((err = msgRecv(port, &msg, &respid)) >= 0) {
		const sockport_msg_t *smi = (const void *)msg.i.raw;
		sockport_resp_t *smo = (void *)msg.o.raw;

		switch (msg.type) {
		case sockmSocket:
			if ((sock = lwip_socket(smi->socket.domain, smi->socket.type, smi->socket.protocol)) < 0)
				msg.o.lookup.err = -errno;
			else
				msg.o.lookup.err = wrap_socket(&msg.o.lookup.res.port, sock, smi->socket.type);
			break;

		case sockmGetNameInfo:
			if (msg.i.size != sizeof(size_t) || (sz = *(size_t *)msg.i.data) > msg.o.size) {
				smo->ret = EAI_SYSTEM;
				smo->sys.errno = -EINVAL;
				break;
			}

			smo->ret = do_getnameinfo(sa_convert_sys_to_lwip(smi->send.addr, smi->send.addrlen), smi->send.addrlen, msg.o.data, sz, msg.o.data + sz, msg.o.size - sz, smi->send.flags);
			smo->sys.errno = smo->ret == EAI_SYSTEM ? errno : 0;
			break;

		case sockmGetAddrInfo:
			node = smi->socket.ai_node_sz ? msg.i.data : NULL;
			serv = msg.i.size > smi->socket.ai_node_sz ? msg.i.data + smi->socket.ai_node_sz : NULL;

			if (smi->socket.ai_node_sz > msg.i.size || (node && node[smi->socket.ai_node_sz - 1]) || (serv && ((char *)msg.i.data)[msg.i.size - 1])) {
				smo->ret = EAI_SYSTEM;
				smo->sys.errno = -EINVAL;
				break;
			}

			hint.ai_flags = smi->socket.flags;
			hint.ai_family = smi->socket.domain;
			hint.ai_socktype = smi->socket.type;
			hint.ai_protocol = smi->socket.protocol;
			smo->sys.buflen = msg.o.size;
			smo->ret = do_getaddrinfo(node, serv, &hint, msg.o.data, &smo->sys.buflen);
			smo->sys.errno = smo->ret == EAI_SYSTEM ? errno : 0;
			break;

		default:
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
