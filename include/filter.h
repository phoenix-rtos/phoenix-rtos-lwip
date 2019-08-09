/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP packet filter
 *
 * Copyright 2019 Phoenix Systems
 * Author: Kamil Amanowicz, Jan Sikorski, Aleksander Kaminski
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PHOENIX_FILTER_H_
#define PHOENIX_FILTER_H_


#include "filter-api.h"
#include "lwip/ip.h"


int pf_filterIn(struct pbuf *pbuf, struct netif *netif);


int pf_filterOut(struct pbuf *pbuf, struct netif *netif);


void pf_rulesUpdate(pfrule_t *list);


int _pf_processRule(pfrule_t *rule);


void _pf_listDestroy(pfrule_t **list);


void init_filters(void);


#endif
