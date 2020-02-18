/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP network stack OS interface
 *
 * Copyright 2018, 2019 Phoenix Systems
 * Author: Jan Sikorski, Michal Miroslaw
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <lwip/tcpip.h>
#include <lwip/tcp.h>

#include "netif.h"

#define LOG_INFO(fmt, ...) // printf("%s:%d  %s(): " fmt "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) printf("%s:%d  %s(): " fmt "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)


#define MAX_SOCKETS 4096
#define SOCKET_INDEX(id) ((id) & (MAX_SOCKETS - 1))

#define SOCK_BOUND (1 << 0)
#define SOCK_LISTENING (1 << 1)
#define SOCK_CONNECTING (1 << 2)
#define SOCK_CONNECTED (1 << 3)

enum { socket_tcp, socket_udp };

typedef struct {
	id_t id;
	int refs;
	uint16_t inoffs;
	struct pbuf *inbufs;

	unsigned char type;
	unsigned char state;

	err_t error;

	int backlog;
	void **connections;

	union {
		struct tcp_pcb *tpcb;
	};
} socket_t;


static struct {
	int portfd;

	socket_t *sockets[MAX_SOCKETS];
	uint64_t stack[2048];
} socket_common;


static socket_t *socket_get(id_t id)
{
	int index = SOCKET_INDEX(id);
	socket_t *socket;

	if (index < MAX_SOCKETS && (socket = socket_common.sockets[index]) != NULL && socket->id == id)
		return socket;

	return NULL;
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
		}

		if (serv != NULL) {
			snprintf(serv, servsz, "%u", ntohs(sa_in->sin_port));
		}

		return 0;
	}

	return EAI_FAMILY;
}


static int socket_create(id_t *id, struct tcp_pcb *pcb)
{
	LOG_INFO("entered");

	int i;
	socket_t *socket;

	if ((socket = calloc(1, sizeof(*socket))) == NULL)
		return -ENOMEM;

	socket->type = socket_tcp;
	socket->error = ERR_OK;

	if (pcb == NULL && (pcb = tcp_new()) == NULL) {
		free(socket);
		return -ENOMEM;
	}

	socket->tpcb = pcb;

	for (i = 0; i < MAX_SOCKETS; ++i) {
		if (socket_common.sockets[i] == NULL) {
			socket->id = i;
			*id = (id_t)i;
			socket_common.sockets[i] = socket;
			break;
		}
	}

	if (i == MAX_SOCKETS) {
		tcp_free(socket->tpcb);
		free(socket);
		return -ENOMEM;
	}

	LOG_INFO("produced %llu", *id);
	tcp_arg(socket->tpcb, socket);
	return EOK;
}


/* Callbacks */

static err_t socket_received(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
	socket_t *socket = arg;
	LOG_INFO("entered id=%llu", socket->id);
	int event;

	if (err) {
		LOG_ERROR("error: %d", err);
		return err;
	}

	if (p != NULL) {
		event = POLLIN;
		LOG_INFO("got data (%d) :)", p->tot_len);
		if (socket->inbufs == NULL) {
			socket->inbufs = p;
		}
		else {
			LOG_INFO("i'll cat");
			pbuf_cat(socket->inbufs, p);
			LOG_INFO("i catted");
		}
	}
	else {
		event = POLLHUP;
		LOG_INFO("received empty pbuf");
		/* TODO: mark as closed? */
		socket->state &= ~SOCK_CONNECTED;
		socket->error = ERR_CONN;
	}

	portEvent(socket_common.portfd, socket->id, event);
	return ERR_OK;
}


static err_t socket_transmitted(void *arg, struct tcp_pcb *tpcb, uint16_t len)
{
	socket_t *socket = arg;
	LOG_INFO("entered id=%llu", socket->id);
	portEvent(socket_common.portfd, socket->id, POLLOUT);
	return ERR_OK;
}


static void socket_error(void *arg, err_t err)
{
	socket_t *socket = arg;
	LOG_ERROR("socket %llu: %s (%d)", socket->id, lwip_strerr(err), err);
	socket->error = err;
	socket->state &= ~SOCK_CONNECTED;
	socket->tpcb = NULL;
	portEvent(socket_common.portfd, socket->id, POLLHUP|POLLERR);
}


static err_t socket_accepted(void *arg, struct tcp_pcb *new, err_t err)
{
	socket_t *socket = arg, *newsocket;
	id_t newsockid;
	int i;

	LOG_INFO("entered id=%llu", socket->id);

	if (err) {
		LOG_ERROR("error: %d", err);
	}

	for (i = 0; i < socket->backlog; ++i) {
		if (socket->connections[i] == NULL) {
			if (socket_create(&newsockid, new) != EOK)
				break;

			newsocket = socket_get(newsockid);
			newsocket->state |= SOCK_CONNECTED;

			tcp_recv(new, socket_received);
			tcp_sent(new, socket_transmitted);
			tcp_err(new, socket_error);

			socket->connections[i] = newsocket;

			tcp_backlog_delayed(new);
			portEvent(socket_common.portfd, socket->id, POLLIN);
			LOG_INFO("registered new connection :)");
			return ERR_OK;
		}
	}

	LOG_ERROR("rejected :(");
	tcp_abort(new);
	return ERR_ABRT;
}


static err_t socket_connected(void *arg, struct tcp_pcb *tpcb, err_t err)
{
	socket_t *socket = arg;
	LOG_INFO("entered id=%llu, err = %s", socket->id, lwip_strerr(err));

	if (err) {
		LOG_ERROR("error: %d", err);
	}

	if (!(socket->state & SOCK_CONNECTING)) {
		LOG_ERROR("socket was not connecting");
	}

	tcp_recv(tpcb, socket_received);
	tcp_sent(tpcb, socket_transmitted);
	tcp_err(tpcb, socket_error);
	socket->state &= ~SOCK_CONNECTING;
	socket->state |= SOCK_CONNECTED;
	portEvent(socket_common.portfd, socket->id, POLLOUT);
	return ERR_OK;
}


/* Handlers */

static int socket_read(socket_t *socket, void *data, int size)
{
	LOG_INFO("entered id=%llu", socket->id);

	int bytes = 0;
	struct pbuf *p, *head;

	if (socket->inbufs != NULL) {
		bytes = pbuf_copy_partial(socket->inbufs, data, size, socket->inoffs);
		p = pbuf_skip(socket->inbufs, bytes + socket->inoffs, &socket->inoffs);

		LOG_INFO("p after skipping is %p", p);

		while (p != (head = socket->inbufs) && head != NULL) {
			LOG_INFO("dechaining %p", head);
			socket->inbufs = pbuf_dechain(socket->inbufs);
			pbuf_free(head);
		}

		LOG_INFO("got %d data :)", bytes);
		tcp_recved(socket->tpcb, bytes);
	}

	return bytes;
}


static int socket_write(socket_t *socket, const void *data, int size)
{
	LOG_INFO("entered id=%llu, size: %d", socket->id, size);

	err_t result;
	int writesz = tcp_sndbuf(socket->tpcb);

	if (writesz > size)
		writesz = size;

	/* TODO: no need to copy if we're not responding before data is acked! */
	result = tcp_write(socket->tpcb, data, writesz, TCP_WRITE_FLAG_COPY);

	if (result != ERR_OK) {
		LOG_ERROR("%s (%d)\n", lwip_strerr(result), result);
	}
	else {
		result = tcp_output(socket->tpcb);
		if (result != ERR_OK)
			LOG_ERROR("%s (%d)\n", lwip_strerr(result), result);
	}

	return result == ERR_OK ? writesz : -err_to_errno(result);
}


static int socket_close(socket_t *socket)
{
	LOG_INFO("entered id=%llu", socket->id);

	err_t result = ERR_OK;

	if (socket->tpcb != NULL)
		result = tcp_close(socket->tpcb);

	if (result != ERR_OK)
		LOG_ERROR("%s (%d)\n", lwip_strerr(result), result);

	return -err_to_errno(result);
}


static int socket_shutdown(socket_t *socket, int how)
{
	return EOK;
}


static int socket_bind(socket_t *socket, struct sockaddr *address, socklen_t len)
{
	LOG_INFO("entered id=%llu", socket->id);

	err_t result;
	struct sockaddr_in *ain = address;
	ip_addr_t ipaddr = IPADDR4_INIT(ain->sin_addr.s_addr);

	LOG_INFO("binding to ip addr: %x port %d", ipaddr.addr, (int)ntohs(ain->sin_port));

	result = tcp_bind(socket->tpcb, &ipaddr, ntohs(ain->sin_port));
	if (result != ERR_OK)
		LOG_ERROR("%s (%d)\n", lwip_strerr(result), result);

	return -err_to_errno(result);
}


static int socket_listen(socket_t *socket, int backlog)
{
	LOG_INFO("entered id=%llu", socket->id);

	if (socket->state & SOCK_CONNECTED)
		return -EINVAL;

	/* TODO: adjust backlog if different? */
	if (socket->state & SOCK_LISTENING)
		return EOK;

	if ((socket->tpcb = tcp_listen_with_backlog(socket->tpcb, backlog)) == NULL) {
		LOG_ERROR("tcp_listen_with_backlog");
		return -ENOBUFS;
	}

	if ((socket->connections = calloc(backlog, sizeof(void *))) == NULL) {
		LOG_ERROR("calloc");
		return -ENOBUFS;
	}

	socket->state |= SOCK_LISTENING;
	socket->backlog = backlog;
	tcp_accept(socket->tpcb, socket_accepted);

	return EOK;
}


static int socket_accept(socket_t *socket, id_t *newsock, struct sockaddr *address, socklen_t addresslen, socklen_t *length)
{
	LOG_INFO("entered id=%llu", socket->id);

	int i, retval = -EAGAIN;
	socket_t *new;

	if (!(socket->state & SOCK_LISTENING))
		return -EINVAL;

	if ((new = socket->connections[0]) != NULL) {
		LOG_INFO("got connection :)");
		retval = EOK;

		*newsock = new->id;
		tcp_backlog_accepted(new->tpcb);

		for (i = 0; i < socket->backlog - 1; ++i)
			socket->connections[i] = socket->connections[i + 1];

		socket->connections[i] = NULL;
	}

	return retval;
}


static int socket_connect(socket_t *socket, struct sockaddr *address, socklen_t len)
{
	LOG_INFO("entered id=%llu", socket->id);

	err_t result;
	struct sockaddr_in *ain = address;
	ip_addr_t ipaddr = IPADDR4_INIT(ain->sin_addr.s_addr);

	if (socket->state & SOCK_LISTENING)
		return -EOPNOTSUPP;

	if (socket->state & SOCK_CONNECTED)
		return -EALREADY;

	if (socket->state & SOCK_CONNECTING)
		return -EINPROGRESS;

	/* TODO: check error in common code? clear it after reporting? */
	if (socket->error != ERR_OK)
		return -err_to_errno(socket->error);

	tcp_err(socket->tpcb, socket_error);
	result = tcp_connect(socket->tpcb, &ipaddr, ntohs(ain->sin_port), socket_connected);
	if (result != ERR_OK)
		LOG_ERROR("%s (%d)\n", lwip_strerr(result), result);
	else
		socket->state |= SOCK_CONNECTING;

	return result == ERR_OK ? -EINPROGRESS : -err_to_errno(result);
}


static int socket_poll(socket_t *socket, int *events)
{
	LOG_INFO("entered id=%llu", socket->id);
	*events = 0;

	if (socket->connections != NULL && socket->connections[0] != NULL)
		*events |= POLLIN;

	if (socket->inbufs != NULL)
		*events |= POLLIN;

	/* TODO: check if we're connected? */
	if (socket->state & SOCK_CONNECTED)
		*events |= POLLOUT;
	return EOK;
}


static int socket_ioctl(socket_t *socket, long request, void *buffer, size_t size)
{
	int error;

	switch (request) {
	case FIONREAD:
//	case FIONBIO: legacy way to set nonblocking mode: should we support this anyway?
		error = -ENOSYS;
		break;

	case SIOCGIFNAME: {
		struct ifreq *ifreq = (struct ifreq *)buffer;
		struct netif *it;

		error = -ENXIO;
		for (it = netif_list; it != NULL; it = it->next) {
			if (it->num == ifreq->ifr_ifindex) {
				strncpy(ifreq->ifr_name, it->name, IFNAMSIZ);
				error = EOK;
			}
		}
		break;
	}

	case SIOCGIFINDEX: {
		struct ifreq *ifreq = (struct ifreq *) buffer;
		struct netif *interface = netif_find(ifreq->ifr_name);
		if (interface == NULL) {
			error = -ENXIO;
			break;
		}
		ifreq->ifr_ifindex = interface->num;
		error = EOK;
		break;
	}

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

		struct ifreq *ifreq = (struct ifreq *)buffer;
		struct netif *interface = netif_find(ifreq->ifr_name);
		if (interface == NULL) {
			error = -ENXIO;
			break;
		}

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
		error = EOK;
		break;
	}

	case SIOCSIFFLAGS: {
		struct ifreq *ifreq = (struct ifreq *)buffer;
		struct netif *interface = netif_find(ifreq->ifr_name);
		if (interface == NULL) {
			error = -ENXIO;
			break;
		}

		// only IFF_UP flag supported
		if ((ifreq->ifr_flags & IFF_UP) && !netif_is_up(interface)) {
			netif_set_up(interface);
#ifdef LWIP_DHCP
			if (netif_is_dhcp(interface))
				dhcp_start(interface);
#endif
		}
		if (!(ifreq->ifr_flags & IFF_UP) && netif_is_up(interface)) {
#ifdef LWIP_DHCP
			if (netif_is_dhcp(interface))
				dhcp_release(interface);
#endif
			netif_set_down(interface);
		}

#ifdef LWIP_DHCP
		if (!netif_is_ppp(interface) && !netif_is_tun(interface)) {
			/* can't start dhcp when interface is down and since we do not keep
			 * any information about dynamic flag it is not possible to 'set' interface
			 * as dynamic when it is downfc */
			if (netif_is_up(interface) && (ifreq->ifr_flags & IFF_DYNAMIC) && !netif_is_dhcp(interface))
				dhcp_start(interface);

			if (!(ifreq->ifr_flags & IFF_DYNAMIC) && netif_is_dhcp(interface)) {
				dhcp_release(interface);
				dhcp_stop(interface);
			}
		}
#endif
		error = EOK;
		break;
	}

	case SIOCGIFADDR:
	case SIOCGIFNETMASK:
	case SIOCGIFBRDADDR:
	case SIOCGIFDSTADDR: {
		struct ifreq *ifreq = (struct ifreq *)buffer;
		struct sockaddr_in *sin = NULL;
		struct netif *interface = netif_find(ifreq->ifr_name);
		if (interface == NULL) {
			error = -ENXIO;
			break;
		}
		error = EOK;
		switch (request) {
		case SIOCGIFADDR:
			sin = (struct sockaddr_in *) &ifreq->ifr_addr;
			sin->sin_family = AF_INET; /* FIXME */
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
				error = -EOPNOTSUPP;
			}
			break;
		case SIOCGIFDSTADDR:
			if (netif_is_ppp(interface) || netif_is_tun(interface)) {
				sin = (struct sockaddr_in *) &ifreq->ifr_dstaddr;
				sin->sin_addr.s_addr = netif_ip4_gw(interface)->addr;
			} else {
				error = -EOPNOTSUPP;
			}
			break;
		}
		break;
	}

	case SIOCSIFADDR:
	case SIOCSIFNETMASK:
	case SIOCSIFBRDADDR:
	case SIOCSIFDSTADDR: {
		struct ifreq *ifreq = (struct ifreq *)buffer;
		struct sockaddr_in *sin;
		struct netif *interface = netif_find(ifreq->ifr_name);
		ip_addr_t ipaddr;

		if (interface == NULL) {
			error = -ENXIO;
			break;
		}
		error = EOK;
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
			error = -EOPNOTSUPP;
			break;
		case SIOCSIFDSTADDR:
			if (netif_is_tun(interface)) {
				sin = (struct sockaddr_in *) &ifreq->ifr_dstaddr;
				ipaddr.addr = sin->sin_addr.s_addr;
				netif_set_gw(interface, &ipaddr);
			}
			else {
				error = -EOPNOTSUPP;
			}
			break;
		}

#ifdef LWIP_DHCP
		dhcp_inform(interface);
#endif
		break;
	}

	case SIOCGIFHWADDR: {
		struct ifreq *ifreq = (struct ifreq *)buffer;
		struct netif *interface = netif_find(ifreq->ifr_name);
		if (interface == NULL) {
			error = -ENXIO;
			break;
		}

		if (ip_addr_isloopback(&interface->ip_addr)) {
			ifreq->ifr_hwaddr.sa_family = ARPHRD_LOOPBACK;
		} else if (netif_is_ppp(interface)) {
			ifreq->ifr_hwaddr.sa_family = ARPHRD_PPP;
		} else if (netif_is_tun(interface)) {
			/* encap: UNSPEC that's what we want */
			ifreq->ifr_hwaddr.sa_family = -1;
		} else {
			ifreq->ifr_hwaddr.sa_family = ARPHRD_ETHER;
//			ifreq->ifr_hwaddr.sa_len = interface->hwaddr_len; TODO: add sa_len field to struct sockaddr?
			memcpy(ifreq->ifr_hwaddr.sa_data, interface->hwaddr, interface->hwaddr_len);
		}

		error = EOK;
		break;
	}

	case SIOCSIFHWADDR: {
		struct ifreq *ifreq = (struct ifreq *)buffer;
		struct netif *interface = netif_find(ifreq->ifr_name);
		if (interface == NULL) {
			error = -ENXIO;
			break;
		}

		/* TODO: support changing HW address */
		error = -EOPNOTSUPP;
		break;
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
		struct ifreq *ifreq = (struct ifreq *)buffer;
		struct netif *interface = netif_find(ifreq->ifr_name);
		if (interface == NULL) {
			error = -ENXIO;
			break;
		}

		ifreq->ifr_mtu = interface->mtu;
		error = EOK;
		break;
	}
	case SIOCSIFMTU: {
		struct ifreq *ifreq = (struct ifreq *)buffer;
		struct netif *interface = netif_find(ifreq->ifr_name);
		if (interface == NULL) {
			error = -ENXIO;
			break;
		}

		/* TODO: check MAC constraints */
		if (ifreq->ifr_mtu < 64 || ifreq->ifr_mtu > 32768) {
			LOG_ERROR("invalid mtu: %d", (int)ifreq->ifr_mtu);
			error = -EINVAL;
		}
		else {
			interface->mtu = ifreq->ifr_mtu;
			error = EOK;
		}
		break;
	}
	case SIOCGIFMETRIC: {
		struct ifreq *ifreq = (struct ifreq *)buffer;
		struct netif *interface = netif_find(ifreq->ifr_name);
		if (interface == NULL) {
			error = -ENXIO;
			break;
		}

		ifreq->ifr_metric = 0;
		error = EOK;
		break;
	}
	case SIOCSIFMETRIC:
		error = -EOPNOTSUPP;
		break;

	case SIOCGIFTXQLEN:
		error = -EOPNOTSUPP;
		break;

	case SIOCSIFTXQLEN:
		error = -EOPNOTSUPP;
		break;

	case SIOCGIFCONF: {
		struct ifreq *ifreq = buffer;
		struct netif *netif;
		int len = 0;

		if (ifreq != NULL)
			memset(ifreq, 0, size);

		for (netif = netif_list; netif != NULL; netif = netif->next) {
			if (len + sizeof(struct ifreq) < size) {
				/* LWiP name is only 2 chars, we have to manually add the number */
				snprintf(ifreq->ifr_name, IFNAMSIZ, "%c%c%d", netif->name[0], netif->name[1], netif->num);

				struct sockaddr_in* sin = (struct sockaddr_in *)&ifreq->ifr_addr;
				sin->sin_addr.s_addr = netif->ip_addr.addr;

				ifreq += 1;
			}

			len += sizeof(struct ifreq);
		}

		error = len;
		break;
	}

	/** ROUTING
	 * net and host routing is supported and multiple gateways with ethernet interfaces
	 */
	case SIOCADDRT:
	case SIOCDELRT: {
		struct rtentry *rt = (struct rtentry *)buffer;
		struct netif *interface = netif_find(rt->rt_dev);

		if (interface == NULL) {
			error = -ENXIO;
			break;
		}

		if (request == SIOCADDRT) {
			route_add(interface, rt);
		}
		else {
			route_del(interface, rt);
		}

		error = EOK;
		break;
	}

	default:
		LOG_ERROR("unrecognized ioctl: %x", request);
		error = -EINVAL;
		break;
	}
	return error;
}


static void socket_thread(void *arg)
{
	LOG_INFO("entered");

	msg_t msg;
	socket_t *socket;
	unsigned int rid;
	int error = EOK;

	for (;;) {
		if (msgRecv(socket_common.portfd, &msg, &rid) < 0)
			continue;

		error = EOK;

		LOCK_TCPIP_CORE();
		if (msg.object == (id_t)-1) {
			switch (msg.type) {
			case mtOpen:
				error = socket_create(&msg.o.open, NULL);
				break;
			case mtClose:
				LOG_ERROR("invalid close", msg.type);
				break;
			default:
				LOG_ERROR("invalid message: %d", msg.type);
				error = -EINVAL;
				break;
			}
		}
		else if ((socket = socket_get(msg.object)) == NULL) {
			error = -ENOENT;
		}
		else {
			switch (msg.type) {
			case mtBind:
				error = socket_bind(socket, msg.i.data, msg.i.size);
				break;
			case mtAccept:
				error = socket_accept(socket, &msg.o.accept.id, msg.o.data, msg.o.size, &msg.o.accept.length);
				break;
			case mtListen:
				error = socket_listen(socket, msg.i.listen);
				break;
			case mtConnect:
				error = socket_connect(socket, msg.i.data, msg.i.size);
				break;
			case mtRead:
				/* TODO: handle closed socket */
				if (socket->error) {
					error = -err_to_errno(socket->error);
					msg.o.io = 0;
				}
				else if (!(socket->state & SOCK_CONNECTED)) {
					error = -ENOTCONN;
					msg.o.io = 0;
				}
				else if ((error = socket_read(socket, msg.o.data, msg.o.size)) > 0) {
					msg.o.io = error;
					error = EOK;
				}
				else if (!error) {
					msg.o.io = 0;
					error = -EAGAIN;
				}
				break;
			case mtWrite:
				/* TODO: handle closed socket */
				if (socket->error) {
					error = -err_to_errno(socket->error);
					msg.o.io = 0;
				}
				else if (!(socket->state & SOCK_CONNECTED)) {
					error = -ENOTCONN;
					msg.o.io = 0;
				}
				else if ((error = socket_write(socket, msg.i.data, msg.i.size)) > 0) {
					msg.o.io = error;
					error = EOK;
				}
				else if (!error) {
					msg.o.io = 0;
					error = -EAGAIN;
				}
				break;
			case mtClose:
				error = socket_close(socket);
				break;
			case mtShutdown:
				error = socket_shutdown(socket, msg.i.shutdown);
				break;
			case mtGetAttr:
				switch (msg.i.attr) {
				case atEvents:
					*(int *)msg.o.data = 0;
					socket_poll(socket, msg.o.data);
					/* TODO: distinguish hang up from error */
					if (socket->error)
						*(int *)msg.o.data |= POLLHUP|POLLERR;
					error = sizeof(int);
					break;
				case atLocalAddr: {
					if (socket->tpcb != NULL) {
						struct sockaddr_in *sin = msg.o.data;
						sin->sin_family = AF_INET;
						sin->sin_port = htons(socket->tpcb->local_port);
						sin->sin_addr.s_addr = socket->tpcb->local_ip.addr;
						error = sizeof(*sin);
					}
					else {
						error = -ENOTCONN;
					}
					break;
				}
				case atRemoteAddr: {
					if (socket->tpcb != NULL) {
						struct sockaddr_in *sin = msg.o.data;
						sin->sin_family = AF_INET;
						sin->sin_port = htons(socket->tpcb->remote_port);
						sin->sin_addr.s_addr = socket->tpcb->remote_ip.addr;
						error = sizeof(*sin);
					}
					else {
						error = -ENOTCONN;
					}
					break;
				}
				default:
					LOG_ERROR("invalid getattr: %d", msg.i.attr);
					error = -EINVAL;
					break;
				}
				break;
			case mtSetAttr:
				switch (msg.i.attr) {
				case atEvents:
					error = EOK;
					break;
				default:
					LOG_ERROR("invalid setattr: %d", msg.i.attr);
					error = -EINVAL;
					break;
				}
				break;
			case mtDevCtl: {
				void *buffer;
				size_t size;

				switch (msg.i.devctl & IOC_DIRMASK) {
				case IOC_IN:
					buffer = msg.i.data;
					size = msg.i.size;
					break;
				case IOC_INOUT:
					memcpy(msg.o.data, msg.i.data, msg.i.size < msg.o.size ? msg.i.size : msg.o.size);
					/* fallthrough */
				case IOC_OUT:
					buffer = msg.o.data;
					size = msg.o.size;
					break;
				case IOC_VOID:
				default:
					size = 0;
					buffer = NULL;
					break;
				}

				msg.o.io = error = socket_ioctl(socket, msg.i.devctl, buffer, size);

				if (error > 0)
					error = EOK;

				break;
			}
			default:
				LOG_ERROR("invalid message: %d", msg.type);
				error = -EINVAL;
				break;
			}
		}
		UNLOCK_TCPIP_CORE();

		msgRespond(socket_common.portfd, error, &msg, rid);
	}
}

extern int deviceCreate(int cwd, const char *, int portfd, id_t id, mode_t mode);

void init_lwip_sockets(void)
{
	memset(socket_common.sockets, 0, sizeof(socket_common.sockets));
	socket_common.portfd = 3; /* set up in pinit */
	beginthread(socket_thread, 3, socket_common.stack, sizeof(socket_common.stack), NULL);
	deviceCreate(AT_FDCWD, "/dev/net", socket_common.portfd, (id_t)-1, S_IFCHR | 0777);
}
