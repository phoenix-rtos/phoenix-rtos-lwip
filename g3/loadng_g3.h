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

err_t loadng_g3_input(struct netif *netif, struct pbuf *p, struct lowpan6_link_addr *src, struct g3_mcps_data_indication *indication);

#endif
