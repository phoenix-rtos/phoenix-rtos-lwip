/*
 * Phoenix-RTOS
 * Copyright Phoenix Systems
 *
 * This file is a part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include "socket_key.h"

#include <fs/socketfs/socketfs_priv.h>
#include <net/ipsec/sadb.h>
#include <phoenix/errno.h>

static mutex_t socks_mutex;
static LIST_HEAD(sockkey) active_socks = LIST_HEAD_INITIALIZER;

void socketKey_init(void)
{
	proc_mutexCreate(&socks_mutex);
}

void socketKey_release(void)
{
	proc_mutexTerminate(&socks_mutex);
}

void *socketKey_socket(void)
{
	sockkey_t *sock = vm_kmalloc(sizeof(sockkey_t));
	if (sock == NULL)
		return NULL;

	LIST_ELEM_INIT(sock, list);
	sock->mbuff = mbuff_alloc();

	proc_mutexCreate(&sock->mutex);
	proc_semaphoreCreate(&sock->semaphore, 0);

	proc_mutexLock(&socks_mutex);
	LIST_ADD(&active_socks, sock, list);
	proc_mutexUnlock(&socks_mutex);

	return sock;
}

void socketKey_destroy(sockkey_t *sock)
{
	if (sock == NULL)
		return;

	proc_mutexLock(&socks_mutex);
	LIST_REMOVE(&active_socks, sock, list);
	proc_mutexUnlock(&socks_mutex);

	mbuff_free(sock->mbuff);

	proc_mutexTerminate(&sock->mutex);
	proc_semaphoreTerminate(&sock->semaphore);
	vm_kfree(sock);
}

int socketKey_send(file_t *file, const void *buff, size_t len)
{
	char reply[512];
	ipsec_sadbDispatch((void *)buff, (struct sadb_msg *)reply, sizeof(reply));

	struct sadb_msg *sadb_reply = (struct sadb_msg *)reply;
	size_t reply_size = sadb_reply->sadb_msg_len * sizeof(u64);

	proc_mutexLock(&socks_mutex);

	/* AF_KEY socket requires sending response to all clients. */
	sockkey_t *iter;
	LIST_FOR_EACH(&active_socks, iter, list)
	{
		proc_mutexLock(&iter->mutex);
		mbuff_feed(iter->mbuff, reply, reply_size);
		proc_semaphoreUp(&iter->semaphore);
		proc_mutexUnlock(&iter->mutex);
	}

	proc_mutexUnlock(&socks_mutex);

	return len;
}

int socketKey_recv(file_t *file, void *buff, size_t len, int flags)
{
	sock_t *sock = (sock_t *)file->vnode->dev_priv;
	sockkey_t *keysock = sock->priv;
	if (keysock == NULL || buff == NULL)
		return -EINVAL;

	int nonblock = (flags & MSG_DONTWAIT) || (file->flags & O_NONBLOCK);
	if (nonblock && mbuff_size(keysock->mbuff) == 0)
		return -EWOULDBLOCK;

	/* Wait for incoming data. */
	proc_mutexUnlock(&file->vnode->mutex);
	proc_semaphoreDown(&keysock->semaphore);
	proc_mutexLock(&file->vnode->mutex);

	int ret = 0;
	proc_mutexLock(&keysock->mutex);
	if (flags & MSG_PEEK) {
		ret = mbuff_peek(keysock->mbuff, buff, len);
		proc_semaphoreUp(&keysock->semaphore);
	}
	else
		ret = mbuff_take(&keysock->mbuff, buff, len);
	proc_mutexUnlock(&keysock->mutex);

	return ret;
}

int socketKey_selectPoll(file_t *file, unsigned int *ready)
{
	sock_t *sock = (sock_t *)file->vnode->dev_priv;
	sockkey_t *keysock = sock->priv;

	if (mbuff_size(keysock->mbuff) > 0)
		*ready |= FS_READY_READ;

	*ready |= FS_READY_WRITE;
	return EOK;
}

int socketKey_notify(const struct sadb_msg *notify)
{
	size_t notify_size = notify->sadb_msg_len * sizeof(u64);

	proc_mutexLock(&socks_mutex);

	/* AF_KEY socket requires sending response to all clients. */
	sockkey_t *iter;
	LIST_FOR_EACH(&active_socks, iter, list)
	{
		proc_mutexLock(&iter->mutex);
		mbuff_feed(iter->mbuff, (const char *)notify, notify_size);
		proc_semaphoreUp(&iter->semaphore);
		proc_mutexUnlock(&iter->mutex);
	}

	proc_mutexUnlock(&socks_mutex);

	return EOK;
}
