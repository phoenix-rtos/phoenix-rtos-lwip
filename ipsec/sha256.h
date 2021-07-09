/*
 * Phoenix-RTOS --- LwIP port
 *
 * Copyright 2016 Phoenix Systems
 * Author: Jacek Popko
 *
 * %LICENSE%
 */

#ifndef _IPSEC_SHA256_H_
#define _IPSEC_SHA256_H_

extern void hmac_sha256(const unsigned char *, int, const unsigned char *, int, unsigned char *);

#endif
