/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP key sockets
 *
 * Copyright 2021 Phoenix Systems
 * Author: Ziemowit Leszczynski
 *
 * %LICENSE%
 */

#ifndef _KEY_SOCKETS_H_
#define _KEY_SOCKETS_H_

#include <sys/types.h>

void key_sockets_init(void);
int is_key_sockets_fd(int sockfd);
int key_sockets_socket(int domain, int type, int protocol);
int key_sockets_close(int sockfd);
ssize_t key_sockets_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t key_sockets_recv(int sockfd, void *buf, size_t len, int flags);
int key_sockets_poll(int sockfd, int events, time_t timeout);
int key_sockets_notify(const void *buf);

#endif /* _KEY_SOCKETS_H_ */
