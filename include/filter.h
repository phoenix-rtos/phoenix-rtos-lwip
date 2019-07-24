/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP ip/mac filter
 *
 * Copyright 2019 Phoenix Systems
 * Author: Kamil Amanowicz, Jan Sikorski
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PHOENIX_FILTER_H_
#define PHOENIX_FILTER_H_

#include "lwip/ip.h"

enum { pf_direction_in, pf_direction_out };
enum { pf_action_pass, pf_action_block };


typedef struct _pf_rule_t {
	struct _pf_rule_t *next, *prev;

	struct netif *netif;

	unsigned action : 1;
	unsigned direction : 1;
	unsigned log : 1;
	unsigned quick : 1;
	unsigned src_port_set : 1;
	unsigned dst_port_set : 1;

	unsigned char proto[8];

	ip4_addr_t src_addr, dst_addr;
	ip4_addr_t src_mask, dst_mask;
	unsigned short src_port, dst_port;
	unsigned char tcp_flags, tcp_flags_mask;
	const char *label;
} pf_rule_t;


typedef struct _if_rule_t {
	struct _if_rule_t *next;

	unsigned action : 1;
	unsigned direction : 1;
	unsigned src_set : 1;
	unsigned dst_set : 1;
	char src[6];
	char dst[6];
} if_rule_t;


int pf_apply(struct pbuf *pbuf, struct netif *netif);


int pf_ruleAdd(const pf_rule_t *rule);


int pf_ruleRemove(const char *label);


void init_filters(void);


int ip_filter(struct pbuf *pbuf, struct netif *netif);


int mac_filter(struct pbuf *pbuf, struct netif *netif);

#endif
