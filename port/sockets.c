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
#define ifreq lwip_ifreq
#include <lwip/netdb.h>
#include <lwip/sockets.h>
#include <lwip/sys.h>
#include <lwip/netif.h>
#include <lwip/netifapi.h>
#include <lwip/dhcp.h>
#include <lwip/prot/dhcp.h>
#undef ifreq

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/sockios.h>
#include <net/if.h>
#include <net/route.h>
#include <net/if_arp.h>
#include <posix/utils.h>

#include "route.h"
#include "sockets.h"


struct poll_state {
	fd_set rd, wr, ex;
};


static struct {
	/* polling thread */
	struct poll_state poll[2];
	int poll_flip;
	int max_watched_fd;
	struct deferred_msg *watch_list;

	/* server thread */
	struct poll_state poll_one; // FIXME: cache-aligned for SMP
} sglobal;


static ssize_t map_errno(ssize_t ret)
{
	return ret < 0 ? -errno : ret;
}


// oh crap, there is no lwip_poll() ...
static int do_poll_status(int fd, int events)
{
	struct timeval to = { 0, 0 };
	int err;

	if (events & POLLIN)
		FD_SET(fd, &sglobal.poll_one.rd);
	else
		FD_CLR(fd, &sglobal.poll_one.rd);
	if (events & POLLOUT)
		FD_SET(fd, &sglobal.poll_one.wr);
	else
		FD_CLR(fd, &sglobal.poll_one.wr);
	if (events & POLLPRI)
		FD_SET(fd, &sglobal.poll_one.ex);
	else
		FD_CLR(fd, &sglobal.poll_one.ex);

	if ((err = lwip_select(fd + 1, &sglobal.poll_one.rd, &sglobal.poll_one.wr, &sglobal.poll_one.ex, &to)) <= 0)
		return err ? -errno : 0;

	events = 0;
	if (FD_ISSET(fd, &sglobal.poll_one.rd)) {
		FD_CLR(fd, &sglobal.poll_one.rd);
		events |= POLLIN;
	}
	if (FD_ISSET(fd, &sglobal.poll_one.wr)) {
		FD_CLR(fd, &sglobal.poll_one.wr);
		events |= POLLOUT;
	}
	if (FD_ISSET(fd, &sglobal.poll_one.ex)) {
		FD_CLR(fd, &sglobal.poll_one.ex);
		events |= POLLPRI;
	}

	return events;
}


static int do_init_socket(oid_t *oid, int sock_fd, int flags, unsigned int pid)
{
	if (sock_fd >= FD_SETSIZE)
		return -ENOMEM;

	if (lwip_fcntl(sock_fd, F_SETFL, O_NONBLOCK) < 0)
		return -errno;

	return init_socket(oid, sock_fd, flags, pid);
}


static int wrap_socket(oid_t *oid, int sock_fd, int flags, unsigned int pid)
{
	int err = do_init_socket(oid, sock_fd, flags, pid);
	if (err)
		lwip_close(sock_fd);
	return err;
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


#define netif_is_ppp(_netif) (((_netif)->name[0] == 'p') && ((_netif)->name[1] == 'p'))
#define netif_is_tun(_netif) (((_netif)->name[0] == 't') && ((_netif)->name[1] == 'u'))

#ifdef LWIP_DHCP
static inline int netif_is_dhcp(struct netif *netif)
{
		struct dhcp *dhcp;
		dhcp = netif_dhcp_data(netif);
		if (dhcp != NULL && dhcp->pcb_allocated != 0)
			return 1;
		else
			return 0;
}
#endif

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

#ifdef LWIP_DHCP
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
#ifdef LWIP_DHCP
			if (netif_is_dhcp(interface))
				netifapi_dhcp_start(interface);
#endif
		}
		if (!(ifreq->ifr_flags & IFF_UP) && netif_is_up(interface)) {
#ifdef LWIP_DHCP
			if (netif_is_dhcp(interface))
				netifapi_dhcp_release(interface);
#endif
			netif_set_down(interface);
		}

#ifdef LWIP_DHCP
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
			sin->sin_addr.s_addr = interface->ip_addr.addr;
			break;
		case SIOCGIFNETMASK:
			sin = (struct sockaddr_in *) &ifreq->ifr_netmask;
			sin->sin_addr.s_addr = interface->netmask.addr;
			break;
		case SIOCGIFBRDADDR:
			if (!netif_is_ppp(interface)) {
				sin = (struct sockaddr_in *) &ifreq->ifr_broadaddr;
				sin->sin_addr.s_addr = interface->ip_addr.addr | ~(interface->netmask.addr);
			} else {
				return -EOPNOTSUPP;
			}
			break;
		case SIOCGIFDSTADDR:
			if (netif_is_ppp(interface) || netif_is_tun(interface)) {
				sin = (struct sockaddr_in *) &ifreq->ifr_dstaddr;
				sin->sin_addr.s_addr = netif_ip4_gw(interface)->addr;
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
		ip_addr_t ipaddr;
		if (interface == NULL)
			return -ENXIO;

		struct sockaddr_in *sin;
		switch (request) {
		case SIOCSIFADDR:
			sin = (struct sockaddr_in *) &ifreq->ifr_addr;
			ipaddr.addr = sin->sin_addr.s_addr;
			netif_set_ipaddr(interface, &ipaddr);
			break;
		case SIOCSIFNETMASK:
			sin = (struct sockaddr_in *) &ifreq->ifr_netmask;
			ipaddr.addr = sin->sin_addr.s_addr;
			netif_set_netmask(interface, &ipaddr);
			break;
		case SIOCSIFBRDADDR:
			return -EOPNOTSUPP;
		case SIOCSIFDSTADDR:
			if (netif_is_tun(interface)) {
				sin = (struct sockaddr_in *) &ifreq->ifr_dstaddr;
				ipaddr.addr = sin->sin_addr.s_addr;
				netif_set_gw(interface, &ipaddr);
				break;
			}
			return -EOPNOTSUPP;
		}

#ifdef LWIP_DHCP
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
			sin->sin_addr.s_addr = netif->ip_addr.addr;

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
	int err;

	if (sock >= 0)
		err = socket_ioctl(sock, request, in_data, out_data);
	else
		err = sock;

	ioctl_setResponseErr(msg, request, err);
}


static int do_accept(int sock, oid_t *oid, void *addr, size_t *addrlen, int flags, unsigned int pid)
{
	socklen_t salen = *addrlen;
	int err;

	err = map_errno(lwip_accept(sock, addr, &salen));
	if (err < 0)
		return err;

	sa_convert_lwip_to_sys(addr);
	*addrlen = salen;
	return wrap_socket(oid, err, flags, pid);
}


ssize_t socket_op(msg_t *msg, int sock, struct sock_info *sock_info)
{
	const sockport_msg_t *smi = (const void *)msg->i.raw;
	sockport_resp_t *smo = (void *)msg->o.raw;
	socklen_t salen;
	int err;

	switch (msg->type) {
	case sockmConnect:
		return map_errno(lwip_connect(sock, sa_convert_sys_to_lwip(smi->send.addr, smi->send.addrlen), smi->send.addrlen));
	case sockmBind:
		return map_errno(lwip_bind(sock, sa_convert_sys_to_lwip(smi->send.addr, smi->send.addrlen), smi->send.addrlen));
	case sockmListen:
		return map_errno(lwip_listen(sock, smi->listen.backlog));
	case sockmAccept:
		return do_accept(sock, &smo->sockname.socket, smo->sockname.addr, &smo->sockname.addrlen, smi->send.flags, msg->pid);
	case sockmSend:
		return map_errno(lwip_sendto(sock, msg->i.data, msg->i.size, smi->send.flags,
			sa_convert_sys_to_lwip(smi->send.addr, smi->send.addrlen), smi->send.addrlen));
	case sockmRecv:
		smo->ret = map_errno(lwip_recvfrom(sock, msg->o.data, msg->o.size, smi->send.flags, (void *)smo->sockname.addr, &salen));
		if (smo->ret >= 0)
			sa_convert_lwip_to_sys(smo->sockname.addr);
		smo->sockname.addrlen = salen;
		return smo->ret;
	case sockmGetSockName:
		smo->ret = map_errno(lwip_getsockname(sock, (void *)smo->sockname.addr, &salen));
		if (smo->ret >= 0)
			sa_convert_lwip_to_sys(smo->sockname.addr);
		smo->sockname.addrlen = salen;
		return smo->ret;
	case sockmGetPeerName:
		smo->ret = map_errno(lwip_getpeername(sock, (void *)smo->sockname.addr, &salen));
		if (smo->ret >= 0)
			sa_convert_lwip_to_sys(smo->sockname.addr);
		smo->sockname.addrlen = salen;
		return smo->ret;
	case sockmGetFl:
		err = map_errno(lwip_fcntl(sock, F_GETFL, 0));
		if (err >= 0 && sock_info->is_blocking)
			err &= ~O_NONBLOCK;
		return err;
	case sockmSetFl:
		err = map_errno(lwip_fcntl(sock, F_SETFL, smi->send.flags | O_NONBLOCK));
		if (err >= 0)
			sock_info->is_blocking = !(smi->send.flags & O_NONBLOCK);
		return err;
	case sockmGetOpt:
		salen = msg->o.size;
		return lwip_getsockopt(sock, smi->opt.level, smi->opt.optname, msg->o.data, &salen) < 0 ? -errno : salen;
	case sockmSetOpt:
		return map_errno(lwip_setsockopt(sock, smi->opt.level, smi->opt.optname, msg->i.data, msg->i.size));
	case sockmShutdown:
		return map_errno(lwip_shutdown(sock, smi->send.flags));
	case mtRead:
		if (msg->o.size >= 1ull << (8 * sizeof(msg->o.io.err) - 1))
			return -EINVAL;
		return map_errno(lwip_read(sock, msg->o.data, msg->o.size));
	case mtWrite:
		if (msg->i.size >= 1ull << (8 * sizeof(msg->o.io.err) - 1))
			return -EINVAL;
		return map_errno(lwip_write(sock, msg->i.data, msg->i.size));
	case mtGetAttr:
		if (msg->i.attr.type != atPollStatus)
			return -EINVAL;
		return do_poll_status(sock, msg->i.attr.val);
	case mtClose:
		err = map_errno(lwip_close(sock));
		remove_socket(sock_info);
		return err;
	case mtDevCtl:
		do_socket_ioctl(msg, sock);
		return /* ignored */ 0;
	}

	return -EINVAL;
}


static void poll_mark(struct poll_state *poll, int fd, int type)
{
	FD_SET(fd, &poll->ex);

	switch (type) {
	case sockmConnect:
	case sockmSend:
	case mtWrite:
		FD_SET(fd, &poll->wr);
		break;

	case sockmAccept:
	case sockmRecv:
	case mtRead:
		FD_SET(fd, &poll->rd);
		break;

	default:
		__builtin_unreachable();
		break;
	}
}


static int may_retry_op(const struct poll_state *poll, int fd, int type)
{
	if (FD_ISSET(fd, &poll->ex))
		return 1;

	switch (type) {
	case sockmConnect:
	case sockmSend:
	case mtWrite:
		return FD_ISSET(fd, &poll->wr);

	case sockmAccept:
	case sockmRecv:
	case mtRead:
		return FD_ISSET(fd, &poll->rd);

	default:
		__builtin_unreachable();
		return 0;
	}
}


static ssize_t exec_deferred_call(struct deferred_msg *dm)
{
	socklen_t salen;
	ssize_t err;
	int flags = dm->oid.port;
	int sock = dm->oid.id;

	switch (dm->type) {
	case sockmConnect:
		salen = sizeof(flags);
		err = map_errno(lwip_getsockopt(sock, SOL_SOCKET, SO_ERROR, &flags, &salen));
		return err ? err : flags;
	case sockmAccept:
		return do_accept(sock, &dm->oid, dm->addr, &dm->addrlen, flags, dm->pid);
	case sockmSend:
		return map_errno(lwip_sendto(sock, dm->buf, dm->buflen, flags, (void *)dm->addr, dm->addrlen));
	case sockmRecv:
		salen = dm->addrlen;
		err = map_errno(lwip_recvfrom(sock, dm->buf, dm->buflen, flags, (void *)dm->addr, &salen));
		if (err >= 0) {
			sa_convert_lwip_to_sys(dm->addr);
			dm->addrlen = salen;
		}
		return err;
	case mtRead:
		return map_errno(lwip_read(sock, dm->buf, dm->buflen));
	case mtWrite:
		return map_errno(lwip_write(sock, dm->buf, dm->buflen));
	default:
		__builtin_unreachable();
		return -EINVAL;
	}
}


void dm_set_next(struct deferred_msg **where, struct deferred_msg *next)
{
	*where = next;
	if (next)
		next->prevnp = where;
}


static struct deferred_msg *dm_move(struct deferred_msg **where, struct deferred_msg *what)
{
	struct deferred_msg *next = what->next;

	what->next = *where;
	dm_set_next(what->prevnp, next);
	dm_set_next(where, what);

	return next;
}


struct deferred_msg *poll_add(struct deferred_msg *list)
{
	struct deferred_msg *dm, *last = NULL, *rejected = NULL;
	struct poll_state *poll = sglobal.poll + sglobal.poll_flip;

	list->prevnp = &list;
	dm = list;
	while (dm) {
		int sock = dm->oid.id;

		if (sock >= FD_SETSIZE) {
			dm = dm_move(&rejected, dm);
			continue;
		}

		if (sglobal.max_watched_fd < sock)
			sglobal.max_watched_fd = sock;

		poll_mark(poll, sock, dm->type);

		last = dm;
		dm = dm->next;
	}

	if (!last)
		return rejected;

	dm_set_next(&last->next, sglobal.watch_list);
	dm_set_next(&sglobal.watch_list, list);

	return rejected;
}


// oh crap, there is no lwip_epoll() either ...
ssize_t poll_wait(useconds_t timeout_us)
{
	struct deferred_msg *completed, *dm;
	struct poll_state *poll = sglobal.poll + sglobal.poll_flip;
	struct poll_state *new_poll = sglobal.poll + !sglobal.poll_flip;
	struct timeval tv, *timeout;
	ssize_t err;

	timeout = ~timeout_us ? &tv : NULL;
	if (timeout) {
		tv.tv_usec = timeout_us % 1000000;
		tv.tv_sec = timeout_us / 1000000;
	}

	do {
		// FIXME: has no bound on sleep time if not using Linux semantics for non-NULL timeout
		err = sglobal.watch_list ? sglobal.max_watched_fd + 1 : 0;
		err = map_errno(lwip_select(err, &poll->rd, &poll->wr, &poll->ex, timeout));
	} while (err == -EINTR);

	if (err < 0)
		return err;	// FIXME: handle EBADF

	sglobal.poll_flip = !sglobal.poll_flip;
	FD_ZERO(&new_poll->rd);
	FD_ZERO(&new_poll->wr);
	FD_ZERO(&new_poll->ex);

	dm = sglobal.watch_list;
	while (dm) {
		int sock = dm->oid.id;

		if (may_retry_op(poll, sock, dm->type))
			err = exec_deferred_call(dm);
		else
			err = -EAGAIN;

		// FIXME: blocking vs partial read

		if (err == -EAGAIN) {
			poll_mark(new_poll, sock, dm->type);
			dm = dm->next;
			continue;
		}

		completed = NULL;
		dm = dm_move(&completed, dm);
		finish_deferred_call(completed, err);
	}

	return 0;
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


int network_op(msg_t *msg)
{
	const sockport_msg_t *smi = (const void *)msg->i.raw;
	sockport_resp_t *smo = (void *)msg->o.raw;
	struct addrinfo hint = { 0 };
	char *node, *serv;
	size_t sz;
	int sock;

	switch (msg->type) {
	case sockmSocket:
		sock = smi->socket.type & ~(SOCK_NONBLOCK|SOCK_CLOEXEC);
		if ((sock = lwip_socket(smi->socket.domain, sock, smi->socket.protocol)) < 0)
			msg->o.lookup.err = -errno;
		else {
			msg->o.lookup.err = wrap_socket(&msg->o.lookup.dev, sock, smi->socket.type, msg->pid);
			msg->o.lookup.fil = msg->o.lookup.dev;
		}
		break;

	case sockmGetNameInfo:
		if (msg->i.size != sizeof(size_t) || (sz = *(size_t *)msg->i.data) > msg->o.size) {
			smo->ret = EAI_SYSTEM;
			smo->sys.error = -EINVAL;
			break;
		}

		smo->ret = do_getnameinfo(sa_convert_sys_to_lwip(smi->send.addr, smi->send.addrlen), smi->send.addrlen,
			msg->o.data, sz, msg->o.data + sz, msg->o.size - sz, smi->send.flags);
		smo->sys.error = smo->ret == EAI_SYSTEM ? errno : 0;
		smo->nameinfo.hostlen = sz > 0 ? strlen(msg->o.data) + 1  : 0;
		smo->nameinfo.servlen = msg->o.size - sz > 0 ? strlen(msg->o.data + sz) + 1 : 0;
		break;

	case sockmGetAddrInfo:
		node = smi->socket.ai_node_sz ? msg->i.data : NULL;
		serv = msg->i.size > smi->socket.ai_node_sz ? msg->i.data + smi->socket.ai_node_sz : NULL;

		if (smi->socket.ai_node_sz > msg->i.size || (node && node[smi->socket.ai_node_sz - 1]) || (serv && ((char *)msg->i.data)[msg->i.size - 1])) {
			smo->ret = EAI_SYSTEM;
			smo->sys.error = -EINVAL;
			break;
		}

		hint.ai_flags = smi->socket.flags;
		hint.ai_family = smi->socket.domain;
		hint.ai_socktype = smi->socket.type;
		hint.ai_protocol = smi->socket.protocol;
		smo->sys.buflen = msg->o.size;
		smo->ret = do_getaddrinfo(node, serv, &hint, msg->o.data, &smo->sys.buflen);
		smo->sys.error = smo->ret == EAI_SYSTEM ? errno : 0;
		break;

	default:
		return 0;
	}

	return 1;
}
