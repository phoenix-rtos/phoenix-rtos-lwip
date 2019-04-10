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

void ip_filter_init(void);


void ip_filter_reload(void);


int ip_filter(struct pbuf *pbuf, struct netif *netif);


#endif
