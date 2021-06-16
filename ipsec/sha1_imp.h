/*
 * Phoenix-RTOS
 *
 * Operating system kernel
 *
 * SHA-1 hash function (adopted from Libgcrypt sha1.c)
 *
 * Copyright 2012 Phoenix Systems
 * Copyright 2004, 2006 Pawel Pisarczyk
 * Author: Pawel Pisarczyk
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#ifndef _MAIN_SHA1_H_
#define _MAIN_SHA1_H_

#include <hal/if.h>

typedef struct _sha1_context_t {
	u32 h0, h1, h2, h3, h4;
	u32 nblocks;
	u8 buf[64];
	int count;
} sha1_context_t;

/*
 * Shortcut function which puts the hash value of supplied buffer
 * into outbuf which must have a size of 20 bytes
 */
extern void sha1_hash(char *outbuf, const char *buffer, size_t length);

void sha1_init(void *context);

void sha1_transform(sha1_context_t *hd, u8 *data);

void sha1_write(void *context, u8 *inbuf, size_t inlen);

void sha1_final(void *context);

#endif
