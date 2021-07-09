/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security, Inc.
 * MD5 Message-Digest Algorithm (RFC 1321).
 *
 * Homepage:
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5
 *
 * Author:
 * Alexander Peslyak, better known as Solar Designer <solar at openwall.com>
 *
 * This software was written by Alexander Peslyak in 2001.  No copyright is
 * claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2001 Alexander Peslyak and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * See md5.c for more information.
 */

#ifndef _MD5_IMP_H_
#define _MD5_IMP_H_

#include <stdint.h>
#include <stddef.h>

typedef struct {
	uint32_t lo, hi;
	uint32_t a, b, c, d;
	uint8_t buffer[64];
	uint32_t block[16];
} md5_context_t;

extern void ipsec_md5_init(md5_context_t *ctx);
extern void ipsec_md5_update(md5_context_t *ctx, const void *data, size_t size);
extern void ipsec_md5_final(uint8_t *result, md5_context_t *ctx);

#endif
