/*
 * Phoenix-RTOS --- LwIP port
 *
 * SHA-1 hash function (adopted from Libgcrypt sha1.c)
 *
 * Copyright 2012 Phoenix Systems
 * Author: Pawel Pisarczyk
 *
 * %LICENSE%
 */

#ifndef _SHA1_IMP_H_
#define _SHA1_IMP_H_

#include <stdint.h>
#include <stddef.h>


typedef struct {
	uint32_t h0, h1, h2, h3, h4;
	uint32_t nblocks;
	uint8_t buf[64];
	int count;
} sha1_context_t;

/*
 * Shortcut function which puts the hash value of supplied buffer
 * into outbuf which must have a size of 20 bytes
 */
void sha1_hash(uint8_t *outbuf, const uint8_t *buffer, size_t length);

void sha1_init(sha1_context_t *hd);

void sha1_transform(sha1_context_t *hd, uint8_t *data);

void sha1_write(sha1_context_t *hd, uint8_t *inbuf, size_t inlen);

void sha1_final(sha1_context_t *hd);

#endif
