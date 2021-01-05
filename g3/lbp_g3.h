/*
 * Phoenix-RTOS --- networking stack
 *
 * G3-PLC Adaptation Layer - LoWPAN Bootstrapping Protocol
 *
 * Copyright 2021 Phoenix Systems
 * Author: Maciej Purski
 *
 * %LICENSE%
 */

#ifndef LWIP_HDR_LBP_H
#define LWIP_HDR_LBP_H

#include "lowpan6_g3.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"


err_t lbp_g3_input(struct netif *netif, struct pbuf *p, struct lowpan6_link_addr *src);

void lbp_g3_set_connected(struct netif *netif);

void lbp_g3_init(struct netif *netif, const u8_t *psk, const u8_t *rand, const u8_t *id, u8_t id_len);

#endif
