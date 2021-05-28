/*
 * Phoenix-RTOS --- networking stack
 *
 * G3-PLC Adaptation Layer - LoadNG routing protocol
 *
 * Copyright 2021 Phoenix Systems
 * Author: Maciej Purski
 *
 * %LICENSE%
 */

#ifndef LWIP_HDR_LOADNG_G3_H
#define LWIP_HDR_LOADNG_G3_H

#include "lowpan6_g3.h"

enum loadng_g3_metric_type {
  LOADNG_G3_METRIC_COMPOSITE = 0xF,
  LOADNG_G3_METRIC_HOPCOUNT = 0
};

void loadng_g3_tmr(void);
err_t loadng_g3_input(struct netif *netif, struct pbuf *p, struct lowpan6_link_addr *src, struct g3_mcps_data_indication *indication);
err_t loadng_g3_route_disc(struct netif *netif, struct pbuf *p, struct lowpan6_link_addr *frame_originator, struct lowpan6_link_addr *dst, u8_t route_repair, u8_t max_hops);
err_t adpm_route_discovery(struct netif *netif, struct lowpan6_link_addr *dest_addr, u8_t max_hops);
err_t loadng_g3_path_discovery(struct netif *netif, struct lowpan6_link_addr *dest_addr, u8_t metric_type);
err_t loadng_g3_status_handle(struct netif *netif, struct pbuf *p, struct lowpan6_link_addr *dest, u8_t status);
err_t loadng_g3_rerr_issue(struct netif *netif, struct lowpan6_link_addr *unreachable_address, struct lowpan6_link_addr *dst, u8_t error_code);
err_t loadng_g3_route_repair_status(struct netif *netif, struct lowpan6_link_addr *final_dest);

#endif
