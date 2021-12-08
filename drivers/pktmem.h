/*
 * Phoenix-RTOS --- networking stack
 *
 * Packet buffer handling
 *
 * Copyright 2017 Phoenix Systems
 * Author: Michał Mirosław
 *
 * %LICENSE%
 */
#ifndef _LWIP_PHOENIX_PKTMEM_H_
#define _LWIP_PHOENIX_PKTMEM_H_

#include <stdint.h>
#include <lwip/pbuf.h>
#include <sys/types.h>


extern struct pbuf *net_allocDMAPbuf(addr_t *pa, size_t sz);


extern struct pbuf *net_makeDMAPbuf(struct pbuf *p);


#endif
