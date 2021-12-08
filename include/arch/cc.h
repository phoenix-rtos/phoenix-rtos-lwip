/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer
 *
 * Copyright 2018, 2021 Phoenix Systems
 * Author: Michał Mirosław, Lukasz Kosinski
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _LWIP_PHOENIX_CC_H_
#define _LWIP_PHOENIX_CC_H_

#include <errno.h>
#include <endian.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/ioctl.h>
#include <sys/select.h>
//#include <sys/socket.h>
//#include <sys/time.h>
#include <arpa/inet.h>


/* Types used by LwIP for (sn)printf formatters */
#define LWIP_NO_INTTYPES_H 1
#define X8_F  "02x"
#define U16_F "u"
#define S16_F "d"
#define X16_F "x"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"
#define SZT_F "zu"


/* Byte order functions, use <arpa/inet.h> */
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS
#define lwip_htons htons
#define lwip_htonl htonl


/* Checksum functions */
#define LWIP_CHKSUM_ALGORITHM 2


/* Diagnostics functions  */
extern void bail(const char *format, ...) __attribute__((cold,noreturn,format(printf,1,2)));


extern void errout(int err, const char *format, ...) __attribute__((cold,noreturn,format(printf,2,3)));


#define LWIP_PLATFORM_DIAG(x) printf x
#define LWIP_PLATFORM_ASSERT  bail


/* Initialization */
#ifndef HAVE_WORKING_INIT_ARRAY
#define __constructor__(o)
#else
#define __constructor__(o) static __attribute__((constructor(o)))
#endif


/* Randomness */
#define LWIP_RAND() ((u32_t)rand())


#endif
