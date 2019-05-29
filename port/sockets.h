/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer - BSD sockets server
 *
 * Copyright 2019 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef PHOENIX_NET_PORT_SOCKETS_H_
#define PHOENIX_NET_PORT_SOCKETS_H_

#include <sys/sockport.h>


struct sock_info {
	union {
		struct {
			int lwip_fd;
			unsigned int owner_pid;
		} used;
		struct {
			id_t next;
		} free;
	};
	unsigned is_open:1;
	unsigned is_blocking:1;
};


struct deferred_msg {
	struct deferred_msg *next, **prevnp;	// FIXME: rbtree?
	int type;
	unsigned int pid;
	unsigned int respid;
	oid_t oid;	/* input: fd + flags */
	void *buf;
	size_t buflen;
	size_t addrlen;
	char addr[MAX_SOCKNAME_LEN];
};


int init_socket(oid_t *oid, int sock_fd, int flags, unsigned int pid);
void remove_socket(struct sock_info *sock_info);
void dm_set_next(struct deferred_msg **where, struct deferred_msg *next);
struct deferred_msg *poll_add(struct deferred_msg *list);
ssize_t poll_wait(useconds_t timeout_us);


ssize_t socket_op(msg_t *msg, int sock, struct sock_info *sock_info);
int network_op(msg_t *msg);
void finish_deferred_call(struct deferred_msg *dm, ssize_t ret);


#endif /* PHOENIX_NET_PORT_SOCKETS_H_ */
