/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP packet filter API
 *
 * Copyright 2019 Phoenix Systems
 * Author: Aleksander Kaminski
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PHOENIX_FILTER_API_H_
#define PHOENIX_FILTER_API_H_


enum { pfin = 1, pfout = 2 };
enum { pfpass = 0, pfblock };


typedef struct pfrule_s {
	struct pfrule_s *prev;
	struct pfrule_s *next;

	unsigned int action:1;
	unsigned int direction:2;
	unsigned int log:1;
	unsigned int quick:1;
	unsigned int filter_mac:1;
	unsigned int src_port_set:1;
	unsigned int dst_port_set:1;
	unsigned int src_addr;
	unsigned int dst_addr;
	unsigned short src_port;
	unsigned short dst_port;
	unsigned char tcp_flags;
	unsigned char tcp_flags_mask;
	unsigned char src_mask;
	unsigned char dst_mask;
	unsigned char protocol[8];
	unsigned char mac[6];
	union {
		char interface[16];
		struct netif *netif;
	};
} pfrule_t;


typedef struct pfrule_array_s {
	size_t len;
	pfrule_t array[];
} pfrule_array_t;

#endif
