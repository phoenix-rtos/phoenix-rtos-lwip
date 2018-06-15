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
#ifndef NET_PKTMEM_H_
#define NET_PKTMEM_H_

#include <stdint.h>


struct pbuf;


struct pbuf *net_allocDMAPbuf(addr_t *pa, size_t sz);
struct pbuf *net_makeDMAPbuf(struct pbuf *p);


#endif /* NET_PKTMEM_H_ */
