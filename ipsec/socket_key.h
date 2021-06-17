/*
 * Phoenix-RTOS
 * Copyright Phoenix Systems
 *
 * This file is a part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#ifndef SOCKET_KEY_H
#define SOCKET_KEY_H

#include <fs/vnode.h>
#include <lib/list.h>
#include <lib/mbuff.h>
#include <net/ipsec/sadb.h>
#include <proc/if.h>

typedef struct sockkey {
	LIST_ENTRY(sockkey)
	list;
	mbuff_t *mbuff;

	mutex_t mutex;
	semaphore_t semaphore;
} sockkey_t;

void socketKey_init(void);
void socketKey_release(void);

void *socketKey_socket(void);
void socketKey_destroy(sockkey_t *sock);
int socketKey_send(file_t *file, const void *buff, size_t len);
int socketKey_recv(file_t *file, void *buff, size_t len, int flags);
int socketKey_selectPoll(file_t *file, unsigned int *ready);

// send notification to all active sockets
int socketKey_notify(const struct sadb_msg *notify);

#endif
