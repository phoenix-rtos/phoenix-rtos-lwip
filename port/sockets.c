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

#include <sys/ioctl.h>

#define ifreq lwip_ifreq
#include <lwip/netdb.h>
#include <lwip/sockets.h>
#include <lwip/sys.h>
#include <lwip/netif.h>
#include <lwip/netifapi.h>
#include <lwip/dhcp.h>
#include <lwip/prot/dhcp.h>
#undef ifreq
#undef IFNAMSIZ

#include <errno.h>
#include <poll.h>
#include <stdint.h>
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

#include "netif.h"
#include "route.h"

#define SOCKTHREAD_PRIO 4
#define SOCKTHREAD_STACKSZ (4 * _PAGE_SIZE)


struct sock_start {
	uint32_t port;
	int sock;
};


struct poll_state {
	int socket;
	fd_set rd, wr, ex;
};


static int wrap_socket(uint32_t *port, int sock, int flags);


static ssize_t map_errno(ssize_t ret)
{
	return ret < 0 ? -errno : ret;
}


// oh crap, there is no lwip_poll() ...
static int poll_one(struct poll_state *p, int events, time_t timeout)
{
	struct timeval to;
	int err;

	if (events & POLLIN)
		FD_SET(p->socket, &p->rd);
	else
		FD_CLR(p->socket, &p->rd);
	if (events & POLLOUT)
		FD_SET(p->socket, &p->wr);
	else
		FD_CLR(p->socket, &p->wr);
	if (events & POLLPRI)
		FD_SET(p->socket, &p->ex);
	else
		FD_CLR(p->socket, &p->ex);

	to.tv_sec = timeout / 1000000;
	to.tv_usec = timeout % 1000000;

	if ((err = lwip_select(p->socket + 1, &p->rd, &p->wr, &p->ex, timeout >= 0 ? &to : NULL)) <= 0)
		return err ? -errno : 0;

	events = 0;
	if (FD_ISSET(p->socket, &p->rd))
		events |= POLLIN;
	if (FD_ISSET(p->socket, &p->wr))
		events |= POLLOUT;
	if (FD_ISSET(p->socket, &p->ex))
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


static int socket_ioctl(int sock, unsigned long request, const void* in_data, void* out_data)
{

#if 0
	printf("ioctl(type=0x%02x, cmd=0x%02x, size=%u, dev=%s)\n", (uint8_t)(request >> 8) & 0xFF, (uint8_t)request & 0xFF,
			IOCPARM_LEN(request), ((struct ifreq *) out_data)->ifr_name);
#endif
	switch (request) {
	case FIONREAD:
	case FIONBIO:
		/* implemented in LWiP socket layer */
		return map_errno(lwip_ioctl(sock, request, out_data));

	case SIOCGIFNAME: {
		struct ifreq *ifreq = (struct ifreq *) out_data;
		struct netif *it;
		for (it = netif_list; it != NULL; it = it->next) {
			if (it->num == ifreq->ifr_ifindex) {
				strncpy(ifreq->ifr_name, it->name, IFNAMSIZ);
				return EOK;
			}
		}

		return -ENXIO;
	}

	case SIOCGIFINDEX: {
			struct ifreq *ifreq = (struct ifreq *) out_data;
			struct netif *interface = netif_find(ifreq->ifr_name);
			if (interface == NULL)
				return -ENXIO;

			ifreq->ifr_ifindex = interface->num;
		}

		return EOK;

	case SIOCGIFFLAGS: {
		/*
		These flags are not supported yet:
		IFF_DEBUG         Internal debugging flag.
		IFF_RUNNING       Resources allocated.
		IFF_NOARP         No arp protocol, L2 destination address not set.
		IFF_PROMISC       Interface is in promiscuous mode.
		IFF_NOTRAILERS    Avoid use of trailers.
		IFF_ALLMULTI      Receive all multicast packets.
		IFF_MASTER        Master of a load balancing bundle.
		IFF_SLAVE         Slave of a load balancing bundle.
		IFF_PORTSEL       Is able to select media type via ifmap.
		IFF_AUTOMEDIA     Auto media selection active.
		IFF_DYNAMIC       The addresses are lost when the interface goes down.
		IFF_LOWER_UP      Driver signals L1 up (since Linux 2.6.17)
		IFF_DORMANT       Driver signals dormant (since Linux 2.6.17)
		IFF_ECHO          Echo sent packets (since Linux 2.6.25)
		*/

		struct ifreq *ifreq = (struct ifreq *) out_data;
		struct netif *interface = netif_find(ifreq->ifr_name);
		if (interface == NULL)
			return -ENXIO;

		ifreq->ifr_flags = 0;
		ifreq->ifr_flags |= netif_is_up(interface) ? IFF_UP : 0;
		ifreq->ifr_flags |= netif_is_link_up(interface) ? IFF_RUNNING : 0;
		ifreq->ifr_flags |= ip_addr_isloopback(&interface->ip_addr) ? IFF_LOOPBACK : 0;
		ifreq->ifr_flags |= (interface->flags & NETIF_FLAG_IGMP) ? IFF_MULTICAST : 0;
		if (netif_is_ppp(interface) || netif_is_tun(interface)) {
			ifreq->ifr_flags |= IFF_POINTOPOINT;
		} else {
			ifreq->ifr_flags |= IFF_BROADCAST;
		}

#if LWIP_DHCP
		if (netif_is_dhcp(interface))
			ifreq->ifr_flags |= IFF_DYNAMIC;
#endif
		return EOK;
	}
	case SIOCSIFFLAGS: {
		struct ifreq *ifreq = (struct ifreq *) in_data;
		struct netif *interface = netif_find(ifreq->ifr_name);
		if (interface == NULL)
			return -ENXIO;

		// only IFF_UP flag supported
		if ((ifreq->ifr_flags & IFF_UP) && !netif_is_up(interface)) {
			netif_set_up(interface);
#if LWIP_DHCP
			if (netif_is_dhcp(interface))
				netifapi_dhcp_start(interface);
#endif
		}
		if (!(ifreq->ifr_flags & IFF_UP) && netif_is_up(interface)) {
#if LWIP_DHCP
			if (netif_is_dhcp(interface))
				netifapi_dhcp_release(interface);
#endif
			netif_set_down(interface);
		}

#if LWIP_DHCP
		if (!netif_is_ppp(interface) && !netif_is_tun(interface)) {
			/* can't start dhcp when interface is down and since we do not keep
			 * any information about dynamic flag it is not possible to 'set' interface
			 * as dynamic when it is downfc */
			if (netif_is_up(interface) && (ifreq->ifr_flags & IFF_DYNAMIC) && !netif_is_dhcp(interface))
				netifapi_dhcp_start(interface);

			if (!(ifreq->ifr_flags & IFF_DYNAMIC) && netif_is_dhcp(interface)) {
				netifapi_dhcp_release(interface);
				netifapi_dhcp_stop(interface);
			}
		}
#endif
		return EOK;
	}

	case SIOCGIFADDR:
	case SIOCGIFNETMASK:
	case SIOCGIFBRDADDR:
	case SIOCGIFDSTADDR: {
		struct ifreq *ifreq = (struct ifreq *) out_data;
		struct netif *interface = netif_find(ifreq->ifr_name);
		if (interface == NULL)
			return -ENXIO;

		struct sockaddr_in *sin = NULL;
		switch (request) {
		case SIOCGIFADDR:
			sin = (struct sockaddr_in *) &ifreq->ifr_addr;
			inet_addr_from_ip4addr(&sin->sin_addr, netif_ip4_addr(interface));
			break;
		case SIOCGIFNETMASK:
			sin = (struct sockaddr_in *) &ifreq->ifr_netmask;
			inet_addr_from_ip4addr(&sin->sin_addr, netif_ip4_netmask(interface));
			break;
		case SIOCGIFBRDADDR:
			if (!netif_is_ppp(interface)) {
				sin = (struct sockaddr_in *) &ifreq->ifr_broadaddr;
				sin->sin_addr.s_addr = ip4_addr_get_u32(netif_ip4_addr(interface)) |
									   ~ip4_addr_get_u32(netif_ip4_netmask(interface));
			} else {
				return -EOPNOTSUPP;
			}
			break;
		case SIOCGIFDSTADDR:
			if (netif_is_ppp(interface) || netif_is_tun(interface)) {
				sin = (struct sockaddr_in *) &ifreq->ifr_dstaddr;
				inet_addr_from_ip4addr(&sin->sin_addr, netif_ip4_gw(interface));
			} else {
				return -EOPNOTSUPP;
			}
			break;
		}

		return EOK;
	}

	case SIOCSIFADDR:
	case SIOCSIFNETMASK:
	case SIOCSIFBRDADDR:
	case SIOCSIFDSTADDR: {
		struct ifreq *ifreq = (struct ifreq *) in_data;
		struct netif *interface = netif_find(ifreq->ifr_name);
		ip4_addr_t ip4addr;
		if (interface == NULL)
			return -ENXIO;

		struct sockaddr_in *sin;
		switch (request) {
		case SIOCSIFADDR:
			sin = (struct sockaddr_in *) &ifreq->ifr_addr;
			inet_addr_to_ip4addr(&ip4addr, &sin->sin_addr);
			netif_set_ipaddr(interface, &ip4addr);
			break;
		case SIOCSIFNETMASK:
			sin = (struct sockaddr_in *) &ifreq->ifr_netmask;
			inet_addr_to_ip4addr(&ip4addr, &sin->sin_addr);
			netif_set_netmask(interface, &ip4addr);
			break;
		case SIOCSIFBRDADDR:
			return -EOPNOTSUPP;
		case SIOCSIFDSTADDR:
			if (netif_is_tun(interface)) {
				sin = (struct sockaddr_in *) &ifreq->ifr_dstaddr;
				inet_addr_to_ip4addr(&ip4addr, &sin->sin_addr);
				netif_set_gw(interface, &ip4addr);
				break;
			}
			return -EOPNOTSUPP;
		}

#if LWIP_DHCP
		netifapi_dhcp_inform(interface);
#endif
		return EOK;
	}

	case SIOCGIFHWADDR: {
		struct ifreq *ifreq = (struct ifreq *) out_data;
		struct netif *interface = netif_find(ifreq->ifr_name);
		if (interface == NULL)
			return -ENXIO;

		if (ip_addr_isloopback(&interface->ip_addr)) {
			ifreq->ifr_hwaddr.sa_family = ARPHRD_LOOPBACK;
		} else if (netif_is_ppp(interface)) {
			ifreq->ifr_hwaddr.sa_family = ARPHRD_PPP;
		} else if (netif_is_tun(interface)) {
			/* encap: UNSPEC that's what we want */
			ifreq->ifr_hwaddr.sa_family = -1;
		} else {
			ifreq->ifr_hwaddr.sa_family = ARPHRD_ETHER;
			ifreq->ifr_hwaddr.sa_len = interface->hwaddr_len;
			memcpy(ifreq->ifr_hwaddr.sa_data, interface->hwaddr, interface->hwaddr_len);
		}

		sa_convert_lwip_to_sys(&ifreq->ifr_hwaddr);
		return EOK;
	}

	case SIOCSIFHWADDR: {
		struct ifreq *ifreq = (struct ifreq *) in_data;
		struct netif *interface = netif_find(ifreq->ifr_name);
		if (interface == NULL)
			return -ENXIO;

		/* TODO: support changing HW address */
		return -EOPNOTSUPP;
	}

#if 0

	case SIOCADDMULTI:
	case SIOCDELMULTI: {
		struct ifreq *ifreq = (struct ifreq *) arg;
		struct netif *interface = netif_find(ifreq->ifr_name);
		ip_addr_t group_ip;
		group_ip.addr = net_multicastMacToIp(ifreq->ifr_hwaddr.sa_data);
		group_ip.addr = lwip_ntohl(group_ip.addr);

		if (cmd == SIOCADDMULTI)
			igmp_joingroup(&interface->ip_addr, &group_ip);
		else
			igmp_leavegroup(&interface->ip_addr, &group_ip);

		return EOK;
	}
#endif
	case SIOCGIFMTU: {
		struct ifreq *ifreq = (struct ifreq *) out_data;
		struct netif *interface = netif_find(ifreq->ifr_name);
		if (interface == NULL)
			return -ENXIO;

		ifreq->ifr_mtu = interface->mtu;
		return EOK;
	}
	case SIOCSIFMTU: {
		struct ifreq *ifreq = (struct ifreq *) in_data;
		struct netif *interface = netif_find(ifreq->ifr_name);
		if (interface == NULL)
			return -ENXIO;

		//TODO: check MAC constraints
		if (ifreq->ifr_mtu < 64 || ifreq->ifr_mtu > 32768)
			return -EINVAL;

		interface->mtu = ifreq->ifr_mtu;
		return EOK;
	}
	case SIOCGIFMETRIC: {
		struct ifreq *ifreq = (struct ifreq *) out_data;
		struct netif *interface = netif_find(ifreq->ifr_name);
		if (interface == NULL)
			return -ENXIO;

		ifreq->ifr_metric = 0;
		return EOK;
	}
	case SIOCSIFMETRIC:
		return -EOPNOTSUPP;

	case SIOCGIFTXQLEN:
		return -EOPNOTSUPP;

	case SIOCSIFTXQLEN:
		return -EOPNOTSUPP;

	case SIOCGIFCONF: {
		struct ifconf *ifconf = (struct ifconf *) out_data;
		int maxlen = ifconf->ifc_len;
		struct ifreq* ifreq = ifconf->ifc_req;
		struct netif *netif;

		ifconf->ifc_len = 0;
		if (!ifreq)  // WARN: it is legal to pass NULL here (we should return the lenght sufficient for whole response)
			return -EFAULT;

		memset(ifreq, 0, maxlen);

		for (netif = netif_list; netif != NULL; netif = netif->next) {
			if (ifconf->ifc_len + sizeof(struct ifreq) > maxlen) {
				break;
			}
			/* LWiP name is only 2 chars, we have to manually add the number */
			snprintf(ifreq->ifr_name, IFNAMSIZ, "%c%c%d", netif->name[0], netif->name[1], netif->num);

			struct sockaddr_in* sin = (struct sockaddr_in *) &ifreq->ifr_addr;
			inet_addr_from_ip4addr(&sin->sin_addr, netif_ip4_addr(netif));

			ifconf->ifc_len += sizeof(struct ifreq);
			ifreq += 1;
		}

		return EOK;
	}
	/** ROUTING
	 * net and host routing is supported and multiple gateways with ethernet interfaces
	 * TODO: support metric
	 */
	case SIOCADDRT:
	case SIOCDELRT: {
		struct rtentry *rt = (struct rtentry *) in_data;
		struct netif *interface = netif_find(rt->rt_dev);

		if (interface == NULL) {
			free(rt->rt_dev);
			free(rt);
			return -ENXIO;
		}

		switch (request) {

		case SIOCADDRT:
			route_add(interface, rt);
			break;
		case SIOCDELRT:
			route_del(interface, rt);
			break;
		}

		free(rt->rt_dev);
		free(rt);

		return EOK;
	}
	}

	return -EINVAL;
}


static void do_socket_ioctl(msg_t *msg, int sock)
{
	unsigned long request;
	void *out_data = NULL;
	const void *in_data = ioctl_unpackEx(msg, &request, NULL, &out_data);

	int err = socket_ioctl(sock, request, in_data, out_data);
	ioctl_setResponseErr(msg, request, err);
}


static int socket_op(msg_t *msg, int sock)
{
	const sockport_msg_t *smi = (const void *)msg->i.raw;
	sockport_resp_t *smo = (void *)msg->o.raw;
	struct poll_state polls = {0};
	uint32_t new_port;
	socklen_t salen;
	int err;

	polls.socket = sock;
	salen = sizeof(smo->sockname.addr);

	switch (msg->type) {
	case sockmConnect:
		smo->ret = map_errno(lwip_connect(sock, sa_convert_sys_to_lwip(smi->send.addr, smi->send.addrlen), smi->send.addrlen));
		break;
	case sockmBind:
		smo->ret = map_errno(lwip_bind(sock, sa_convert_sys_to_lwip(smi->send.addr, smi->send.addrlen), smi->send.addrlen));
		break;
	case sockmListen:
		smo->ret = map_errno(lwip_listen(sock, smi->listen.backlog));
		break;
	case sockmAccept:
		err = lwip_accept(sock, (void *)smo->sockname.addr, &salen);
		if (err >= 0) {
			sa_convert_lwip_to_sys(smo->sockname.addr);
			smo->sockname.addrlen = salen;
			err = wrap_socket(&new_port, err, smi->send.flags);
			smo->ret = err < 0 ? err : new_port;
		} else {
			smo->ret = -errno;
		}
		break;
	case sockmSend:
		smo->ret = map_errno(lwip_sendto(sock, msg->i.data, msg->i.size, smi->send.flags,
			sa_convert_sys_to_lwip(smi->send.addr, smi->send.addrlen), smi->send.addrlen));
		break;
	case sockmRecv:
		smo->ret = map_errno(lwip_recvfrom(sock, msg->o.data, msg->o.size, smi->send.flags, (void *)smo->sockname.addr, &salen));
		if (smo->ret >= 0)
			sa_convert_lwip_to_sys(smo->sockname.addr);
		smo->sockname.addrlen = salen;
		break;
	case sockmGetSockName:
		smo->ret = map_errno(lwip_getsockname(sock, (void *)smo->sockname.addr, &salen));
		if (smo->ret >= 0)
			sa_convert_lwip_to_sys(smo->sockname.addr);
		smo->sockname.addrlen = salen;
		break;
	case sockmGetPeerName:
		smo->ret = map_errno(lwip_getpeername(sock, (void *)smo->sockname.addr, &salen));
		if (smo->ret >= 0)
			sa_convert_lwip_to_sys(smo->sockname.addr);
		smo->sockname.addrlen = salen;
		break;
	case sockmGetFl:
		smo->ret = map_errno(lwip_fcntl(sock, F_GETFL, 0));
		break;
	case sockmSetFl:
		smo->ret = map_errno(lwip_fcntl(sock, F_SETFL, smi->send.flags));
		break;
	case sockmGetOpt:
		salen = msg->o.size;
		smo->ret = lwip_getsockopt(sock, smi->opt.level, smi->opt.optname, msg->o.data, &salen) < 0 ? -errno : salen;
		break;
	case sockmSetOpt:
		smo->ret = map_errno(lwip_setsockopt(sock, smi->opt.level, smi->opt.optname, msg->i.data, msg->i.size));
		break;
	case sockmShutdown:
		smo->ret = map_errno(lwip_shutdown(sock, smi->send.flags));
		break;
	case mtRead:
		if (msg->o.size < 1ull << (8 * sizeof(int) - 1))
			msg->o.io.err = map_errno(lwip_read(sock, msg->o.data, msg->o.size));
		else
			msg->o.io.err = -EINVAL;
		break;
	case mtWrite:
		if (msg->o.size < 1ull << (8 * sizeof(int) - 1))
			msg->o.io.err = map_errno(lwip_write(sock, msg->i.data, msg->i.size));
		else
			msg->o.io.err = -EINVAL;
		break;
	case mtGetAttr:
		if (msg->i.attr.type == atPollStatus)
			msg->o.attr.val = poll_one(&polls, msg->i.attr.val, 0);
		else
			msg->o.attr.val = -EINVAL;
		break;
	case mtClose:
		msg->o.io.err = map_errno(lwip_close(sock));
		return 1;
	case mtDevCtl:
		do_socket_ioctl(msg, sock);
		break;
	default:
		smo->ret = -EINVAL;
		break;
	}

	return 0;
}


static void socket_thread(void *arg)
{
	struct sock_start *ss = arg;
	unsigned long respid;
	uint32_t port = ss->port;
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
	if (err < 0)
		lwip_close(sock);
}


static int wrap_socket(uint32_t *port, int sock, int flags)
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

static int do_getnameinfo(const struct sockaddr *sa, socklen_t addrlen, char *host, socklen_t hostsz, char *serv, socklen_t servsz, int flags)
{

	// TODO: implement real netdb (for now always return the IP representation)
	if (sa == NULL)
		return EAI_FAIL;

	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sa_in = (struct sockaddr_in *)sa;

		if (host != NULL) {
			snprintf(host, hostsz, "%u.%u.%u.%u", (unsigned char)sa->sa_data[2], (unsigned char)sa->sa_data[3],
				(unsigned char)sa->sa_data[4], (unsigned char)sa->sa_data[5]);
			host[hostsz - 1] = '\0';
		}

		if (serv != NULL) {
			snprintf(serv, servsz, "%u", ntohs(sa_in->sin_port));
			serv[servsz - 1] = '\0';
		}

		return 0;
	}

	return EAI_FAMILY;
}


#if LWIP_DNS
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
#endif


static void socketsrv_thread(void *arg)
{
	unsigned long respid;
	size_t sz;
	msg_t msg;
	uint32_t port;
	int err, sock;
#if LWIP_DNS
	struct addrinfo hint = { 0 };
	char *node, *serv;
#endif

	port = (unsigned)arg;

	while ((err = msgRecv(port, &msg, &respid)) >= 0) {
		const sockport_msg_t *smi = (const void *)msg.i.raw;
		sockport_resp_t *smo = (void *)msg.o.raw;

		switch (msg.type) {
		case sockmSocket:
			sock = smi->socket.type & ~(SOCK_NONBLOCK|SOCK_CLOEXEC);
			if ((sock = lwip_socket(smi->socket.domain, sock, smi->socket.protocol)) < 0)
				msg.o.lookup.err = -errno;
			else {
				msg.o.lookup.err = wrap_socket(&msg.o.lookup.dev.port, sock, smi->socket.type);
				msg.o.lookup.fil = msg.o.lookup.dev;
			}
			break;

		case sockmGetNameInfo:
			if (msg.i.size != sizeof(size_t) || (sz = *(size_t *)msg.i.data) > msg.o.size) {
				smo->ret = EAI_SYSTEM;
				smo->sys.err = -EINVAL;
				break;
			}

			smo->ret = do_getnameinfo(sa_convert_sys_to_lwip(smi->send.addr, smi->send.addrlen), smi->send.addrlen, msg.o.data, sz, msg.o.data + sz, msg.o.size - sz, smi->send.flags);
			smo->sys.err = smo->ret == EAI_SYSTEM ? errno : 0;
			smo->nameinfo.hostlen = sz > 0 ? strlen(msg.o.data) + 1  : 0;
			smo->nameinfo.servlen = msg.o.size - sz > 0 ? strlen(msg.o.data + sz) + 1 : 0;
			break;

#if LWIP_DNS
		case sockmGetAddrInfo:
			node = smi->socket.ai_node_sz ? msg.i.data : NULL;
			serv = msg.i.size > smi->socket.ai_node_sz ? msg.i.data + smi->socket.ai_node_sz : NULL;

			if (smi->socket.ai_node_sz > msg.i.size || (node && node[smi->socket.ai_node_sz - 1]) || (serv && ((char *)msg.i.data)[msg.i.size - 1])) {
				smo->ret = EAI_SYSTEM;
				smo->sys.err = -EINVAL;
				break;
			}

			hint.ai_flags = smi->socket.flags;
			hint.ai_family = smi->socket.domain;
			hint.ai_socktype = smi->socket.type;
			hint.ai_protocol = smi->socket.protocol;
			smo->sys.buflen = msg.o.size;
			smo->ret = do_getaddrinfo(node, serv, &hint, msg.o.data, &smo->sys.buflen);
			smo->sys.err = smo->ret == EAI_SYSTEM ? errno : 0;
			break;
#endif

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

	if ((err = create_dev(&oid, PATH_SOCKSRV))) {
		errout(err, "create_dev(%s)", PATH_SOCKSRV);
	}

	if ((err = sys_thread_opt_new("socketsrv", socketsrv_thread, (void *)oid.port, SOCKTHREAD_STACKSZ, SOCKTHREAD_PRIO, NULL))) {
		portDestroy(oid.port);
		errout(err, "thread(socketsrv)");
	}
}
