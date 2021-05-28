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
void lbp_g3_discovery_confirm(struct netif *netif, u8_t status);

void lbp_set_lba(u8_t is_lba);
void lbp_g3_set_connected(struct netif *netif);

err_t lbp_g3_leave(struct netif *netif);
err_t lbp_g3_discovery(struct netif *netif, u8_t duration);
err_t lbp_g3_join(struct netif *netif, u16_t pan_id, u16_t lba);
err_t lbp_g3_start(struct netif *netif, u8_t scan_duration);

void lbp_g3_tmr(void *arg);

err_t lbp_g3_lbs_blacklist_add(const u8_t *addr);
err_t lbp_g3_lbs_kick(struct netif *netif, const struct lowpan6_link_addr *addr);
err_t lbp_g3_lbs_rekey(struct netif *netif, u8_t gmk_id);
err_t lbp_g3_lbs_dev_add(struct netif *netif, u16_t short_addr, const u8_t *ext_addr, int idx);
err_t lbp_g3_lbs_pan_start(struct netif *netif, u8_t scan_duration, u16_t pan_id, u16_t short_address);

#endif
