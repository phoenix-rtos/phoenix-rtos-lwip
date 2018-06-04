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


#include <arch.h>
#include <endian.h>


/* types used by LwIP */

typedef addr_t mem_ptr_t;

#define U16_F "hu"
#define S16_F "hd"
#define X16_F "hx"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"
#define SZT_F "zu"


/* host endianness */

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define BYTE_ORDER LITTLE_ENDIAN
#define lwip_htonl(x) __builtin_bswap32(x)
#define lwip_htons(x) __builtin_bswap16(x)
#else
#define BYTE_ORDER BIG_ENDIAN
#endif


#define LWIP_CHKSUM_ALGORITHM 2


/* diagnostics */

__attribute__((cold,noreturn,format(printf,1,2)))
void bail(const char *format, ...);

#define LWIP_PLATFORM_DIAG	printf
#define LWIP_PLATFORM_ASSERT	bail


/* initialization */

#ifndef HAVE_WORKING_INIT_ARRAY
#define __constructor__(o)
#else
#define __constructor__(o) static __attribute__((constructor(o)))
#endif


#endif /* PHOENIX_LWIP_CC_H_ */
