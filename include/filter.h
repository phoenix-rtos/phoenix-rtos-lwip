/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP ip/mac filter
 *
 * Copyright 2019 Phoenix Systems
 * Author: Kamil Amanowicz
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PHOENIX_FILTER_H_
#define PHOENIX_FILTER_H_

#include "lwip/ip.h"


void init_filters(void);


int ip_filter(struct pbuf *pbuf, struct netif *netif);


int mac_filter(struct pbuf *pbuf, struct netif *netif);

#endif
