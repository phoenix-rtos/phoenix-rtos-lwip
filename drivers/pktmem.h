/*
 * Phoenix-RTOS --- networking stack
 *
 * Packet buffer handling
 *
 * Copyright 2017, 2025 Phoenix Systems
 * Author: Michał Mirosław, Julian Uziembło
 *
 * %LICENSE%
 */
#ifndef NET_PKTMEM_H_
#define NET_PKTMEM_H_

#include <stdint.h>
#include <unistd.h>

#include "lwip/pbuf.h"


int net_initPktMem(size_t pkt_buf_max_sz);
struct pbuf *net_allocDMAPbuf(addr_t *pa, size_t sz);
struct pbuf *net_makeDMAPbuf(struct pbuf *p);


#endif /* NET_PKTMEM_H_ */
