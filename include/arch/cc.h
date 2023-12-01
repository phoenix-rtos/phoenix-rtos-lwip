/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef PHOENIX_LWIP_CC_H_
#define PHOENIX_LWIP_CC_H_


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <endian.h>
#include <fcntl.h>
#include <features.h>
#include <netdb.h>
#include <poll.h>
#include <sys/time.h>

/* types used by LwIP */

#define X8_F  "02x"
#define U16_F "u"
#define S16_F "d"
#define X16_F "x"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"
#define SZT_F "zu"
#define SOCKLEN_T_DEFINED 1


/* host endianness */

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define BYTE_ORDER LITTLE_ENDIAN
#define lwip_htonl(x) __builtin_bswap32(x)
#define lwip_htons(x) __builtin_bswap16(x)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define BYTE_ORDER BIG_ENDIAN
#else
#error "Unsupported byte order"
#endif


#define LWIP_CHKSUM_ALGORITHM 2


/* diagnostics */

__attribute__((cold,noreturn,format(printf,1,2)))
void bail(const char *format, ...);
__attribute__((cold,noreturn,format(printf,2,3)))
void errout(int err, const char *format, ...);

#define LWIP_PLATFORM_DIAG(x)	printf x
#define LWIP_PLATFORM_ASSERT	bail


/* initialization */

#ifndef HAVE_WORKING_INIT_ARRAY
#define __constructor__(o)
#else
#define __constructor__(o) static __attribute__((constructor(o)))
#endif


/* randomness */

#define LWIP_RAND() ((u32_t)rand())


#endif /* PHOENIX_LWIP_CC_H_ */
