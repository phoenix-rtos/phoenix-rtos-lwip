/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP IPsec API
 *
 * Copyright 2021 Phoenix Systems
 *
 * %LICENSE%
 */

#ifndef PHOENIX_IPSEC_API_H_
#define PHOENIX_IPSEC_API_H_

#include "lwip/opt.h"


#define AF_KEY 15

#if LWIP_IPSEC

int ipsecdev_attach(const char *dev);
void key_sockets_init(void);
int is_key_sockets_fd(int sockfd);
int key_sockets_socket(int domain, int type, int protocol);
int key_sockets_close(int sockfd);
ssize_t key_sockets_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t key_sockets_recv(int sockfd, void *buf, size_t len, int flags);
int key_sockets_poll(int sockfd, int events, time_t timeout);

#endif /* LWIP_IPSEC */

#endif /* PHOENIX_IPSEC_API_H_ */
