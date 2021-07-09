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

#include "key_sockets.h"

#include "mbuff.h"
#include "sadb.h"

#include "lwip/opt.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/threads.h>


#define NUM_SOCKETS            MEMP_NUM_NETCONN
#define NUM_KEY_SOCKETS        64
#define LWIP_KEY_SOCKET_OFFSET (LWIP_SOCKET_OFFSET + NUM_SOCKETS)


typedef struct {
	mbuff_t *mbuff;
	handle_t mutex;
	semaphore_t semaphore;
} key_socket_t;


static handle_t key_sockets_mutex;
static key_socket_t *key_sockets[NUM_KEY_SOCKETS];


static key_socket_t **tryget_key_socket(int fd)
{
	int i = fd - LWIP_KEY_SOCKET_OFFSET;

	if (i < 0 || i >= NUM_KEY_SOCKETS)
		return NULL;

	return &key_sockets[i];
}


static key_socket_t **get_key_socket(int fd)
{
	key_socket_t **sock_ptr = tryget_key_socket(fd);

	if (sock_ptr == NULL) {
		errno = EBADF;
		return NULL;
	}

	return sock_ptr;
}


static int alloc_key_socket(key_socket_t *sock)
{
	unsigned int i;

	mutexLock(key_sockets_mutex);
	for (i = 0; i < NUM_KEY_SOCKETS; ++i) {
		if (!key_sockets[i]) {
			key_sockets[i] = sock;
			mutexUnlock(key_sockets_mutex);
			return i + LWIP_KEY_SOCKET_OFFSET;
		}
	}
	mutexUnlock(key_sockets_mutex);

	return -1;
}


static void free_key_socket(key_socket_t **sock_ptr)
{
	mutexLock(key_sockets_mutex);
	*sock_ptr = NULL;
	mutexUnlock(key_sockets_mutex);
}


static key_socket_t *create_key_socket(void)
{
	key_socket_t *sock = malloc(sizeof(key_socket_t));
	if (sock == NULL)
		return NULL;

	sock->mbuff = mbuff_alloc();
	if (sock->mbuff == NULL) {
		free(sock);
		return NULL;
	}

	if (mutexCreate(&sock->mutex) < 0) {
		mbuff_free(sock->mbuff);
		free(sock);
		return NULL;
	}

	if (semaphoreCreate(&sock->semaphore, 0) < 0) {
		resourceDestroy(sock->mutex);
		mbuff_free(sock->mbuff);
		free(sock);
		return NULL;
	}

	return sock;
}


static void destroy_key_socket(key_socket_t *sock)
{
	if (sock == NULL)
		return;

	semaphoreDone(&sock->semaphore);
	resourceDestroy(sock->mutex);
	mbuff_free(sock->mbuff);
	free(sock);
}


void key_sockets_init(void)
{
	memset(key_sockets, 0, sizeof(key_sockets));
	mutexCreate(&key_sockets_mutex);
}


int is_key_sockets_fd(int sockfd)
{
	key_socket_t **sock_ptr = tryget_key_socket(sockfd);
	return (sock_ptr != NULL);
}


int key_sockets_socket(int domain, int type, int protocol)
{
	int fd;
	key_socket_t *sock;

	if (domain != AF_KEY) {
		errno = EINVAL;
		return -1;
	}

	if (type != SOCK_RAW) {
		errno = EPROTOTYPE;
		return -1;
	}

	sock = create_key_socket();
	if (sock == NULL) {
		errno = ENOMEM;
		return -1;
	}

	fd = alloc_key_socket(sock);
	if (fd < 0) {
		destroy_key_socket(sock);
		errno = ENOMEM;
		return -1;
	}

	return fd;
}


int key_sockets_close(int fd)
{
	key_socket_t **sock_ptr = get_key_socket(fd);
	if (sock_ptr == NULL)
		return -1;

	destroy_key_socket(*sock_ptr);
	free_key_socket(sock_ptr);

	return 0;
}


int key_sockets_send(int sockfd, const void *buf, size_t len, int flags)
{
	key_socket_t **sock_ptr;
	void *buf_cpy;
	void *reply;
	int ret;
	size_t reply_len;
	unsigned int i;

	sock_ptr = tryget_key_socket(sockfd);
	if (sock_ptr == NULL || *sock_ptr == NULL) {
		errno = EBADF;
		return -1;
	}

	/* FIXME: copy needed because there is some memory access issue on buf - investigate */
	buf_cpy = malloc(len);
	if (buf_cpy == NULL) {
		errno = ENOMEM;
		return -1;
	}

	/* FIXME: how to limit reply length? */
	reply = malloc(512);
	if (reply == NULL) {
		free(buf_cpy);
		errno = ENOMEM;
		return -1;
	}

	memcpy(buf_cpy, buf, len);

	ret = ipsec_sadbDispatch(buf_cpy, reply, 512);
	if (ret < 0) {
		free(reply);
		free(buf_cpy);
		errno = -ret;
		return -1;
	}

	reply_len = ((struct sadb_msg *)reply)->sadb_msg_len * sizeof(uint64_t);

	mutexLock(key_sockets_mutex);

	/* AF_KEY socket requires sending response to all clients */
	for (i = 0; i < NUM_KEY_SOCKETS; ++i) {
		if (key_sockets[i]) {
			mutexLock(key_sockets[i]->mutex);
			mbuff_feed(key_sockets[i]->mbuff, reply, reply_len);
			semaphoreUp(&key_sockets[i]->semaphore);
			mutexUnlock(key_sockets[i]->mutex);
		}
	}

	mutexUnlock(key_sockets_mutex);

	free(reply);
	free(buf_cpy);

	return len;
}


ssize_t key_sockets_recv(int sockfd, void *buf, size_t len, int flags)
{
	key_socket_t **sock_ptr;
	key_socket_t *sock;
	ssize_t ret;

	sock_ptr = tryget_key_socket(sockfd);
	if (sock_ptr == NULL || *sock_ptr == NULL) {
		errno = EBADF;
		return -1;
	}

	sock = *sock_ptr;

	int nonblock = (flags & MSG_DONTWAIT) || (flags & O_NONBLOCK);
	if (nonblock && mbuff_size(sock->mbuff) == 0) {
		errno = EWOULDBLOCK;
		return -1;
	}

	/* Wait for incoming data */
	semaphoreDown(&sock->semaphore, 0);

	mutexLock(sock->mutex);

	if (flags & MSG_PEEK) {
		ret = mbuff_peek(sock->mbuff, buf, len);
		semaphoreUp(&sock->semaphore);
	}
	else {
		ret = mbuff_take(&sock->mbuff, buf, len);
	}

	mutexUnlock(sock->mutex);

	return ret;
}


int key_sockets_poll(int sockfd, int events, time_t timeout)
{
	key_socket_t **sock_ptr;
	key_socket_t *sock;
	int revents;

	sock_ptr = tryget_key_socket(sockfd);
	if (sock_ptr == NULL || *sock_ptr == NULL) {
		return POLLNVAL;
	}

	sock = *sock_ptr;
	revents = 0;

	if (mbuff_size(sock->mbuff) > 0)
		revents |= POLLIN;

	revents |= POLLOUT;

	return (revents & events);
}


int key_sockets_notify(const void *buf)
{
	size_t notify_len;
	unsigned int i;

	notify_len = ((const struct sadb_msg *)buf)->sadb_msg_len * sizeof(uint64_t);

	mutexLock(key_sockets_mutex);

	/* AF_KEY socket requires sending response to all clients */
	for (i = 0; i < NUM_KEY_SOCKETS; ++i) {
		if (key_sockets[i]) {
			mutexLock(key_sockets[i]->mutex);
			mbuff_feed(key_sockets[i]->mbuff, buf, notify_len);
			semaphoreUp(&key_sockets[i]->semaphore);
			mutexUnlock(key_sockets[i]->mutex);
		}
	}

	mutexUnlock(key_sockets_mutex);

	return 0;
}
