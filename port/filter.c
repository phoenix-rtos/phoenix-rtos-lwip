/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP packet filter
 *
 * Copyright 2019 Phoenix Systems
 * Author: Aleksander Kaminiski, Kamil Amanowicz, Jan Sikorski
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/threads.h>
#include <sys/msg.h>
#include <sys/rb.h>
#include <sys/list.h>
#include <posix/utils.h>

#include <errno.h>

#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/prot/tcp.h"
#include "lwip/prot/udp.h"
#include "lwip/prot/ethernet.h"
#include "filter.h"

#define DEFAULT_ACTION pfpass


enum { packet_dir_in = 0, packet_dir_out };


static struct {
	handle_t pf_lock;
	pfrule_t *rules;
	pfrule_t *puremac_rules;
} filter_common;


static int pf_ruleMatchPureMac(pfrule_t *rule, struct pbuf *pbuf, struct netif *netif)
{
	struct eth_hdr *ethhdr = (struct eth_hdr *)pbuf->payload;

	if (rule->filter_mac && !memcmp(ethhdr->src.addr, rule->mac, sizeof(ethhdr->src.addr)))
		return 1;

	return 0;
}


static inline int pf_matchProtocol(pfrule_t *rule, unsigned char proto)
{
	int i;

	if (rule->protocol[0] == 0xff)
		return 1;

	for (i = 0; i < sizeof(rule->protocol) / sizeof(rule->protocol[0]) && rule->protocol[i] != 0xff; ++i) {
		if (rule->protocol[i] == proto)
			return 1;
	}

	return 0;
}


static int pf_ruleMatch(pfrule_t *rule, struct pbuf *pbuf, struct netif *netif, int pdir)
{
	struct eth_hdr *ethhdr = (struct eth_hdr *)pbuf->payload;
	struct ip_hdr *iphdr = (struct ip_hdr *)((char *)pbuf->payload + SIZEOF_ETH_HDR);
	struct udp_hdr *udphdr;
	struct tcp_hdr *tcphdr;

	if (rule->netif != NULL && rule->netif != netif)
		return 0;

	if (pdir == packet_dir_in && !(rule->direction & pfin))
		return 0;

	if (pdir == packet_dir_out && !(rule->direction & pfout))
		return 0;

	if (rule->dst_addr != (iphdr->dest.addr & (0xffffffffUL << (32 - rule->dst_mask))))
		return 0;

	if (rule->src_addr != (iphdr->src.addr & (0xffffffffUL << (32 - rule->src_mask))))
		return 0;

	if (!pf_matchProtocol(rule, IPH_PROTO(iphdr)))
		return 0;

	if (rule->filter_mac && memcmp(ethhdr->src.addr, rule->mac, sizeof(ethhdr->src.addr)))
		return 0;

	if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
		udphdr = (struct udp_hdr *)((u8_t *)iphdr + 4 * IPH_HL(iphdr));

		if (rule->src_port_set && udphdr->src != rule->src_port)
			return 0;
		if (rule->dst_port_set && udphdr->dest != rule->dst_port)
			return 0;
	}
	else if (IPH_PROTO(iphdr) == IP_PROTO_TCP) {
		tcphdr = (struct tcp_hdr *)((u8_t *)iphdr + 4 * IPH_HL(iphdr));

		if (rule->src_port_set && tcphdr->src != rule->src_port)
			return 0;
		if (rule->dst_port_set && tcphdr->dest != rule->dst_port)
			return 0;
		if (rule->tcp_flags != (TCPH_FLAGS(tcphdr) & rule->tcp_flags_mask))
			return 0;
	}
	else if (rule->src_port_set || rule->dst_port_set) {
		return 0;
	}

	return 1;
}


static int pf_filter(struct pbuf *pbuf, struct netif *netif, int pdir)
{
	struct eth_hdr *ethhdr = (struct eth_hdr *)pbuf->payload;
	pfrule_t *rule, *winner = NULL;
	unsigned int action = DEFAULT_ACTION;

	if (pbuf->len < SIZEOF_ETH_HDR)
		return 1; /* Packet would be dropped anyway */

	mutexLock(filter_common.pf_lock);

	if (ethhdr->type != PP_HTONS(ETHTYPE_IP)) {
		for (rule = filter_common.puremac_rules; rule != NULL; rule = rule->next) {
			if (pf_ruleMatchPureMac(rule, pbuf, netif)) {
				winner = rule;
				if (winner->quick)
					break;
			}
		}
	}
	else {
		if (pbuf->len < SIZEOF_ETH_HDR + sizeof(struct ip_hdr))
			return 1; /* Packet would be dropped anyway */

		for (rule = filter_common.rules; rule != NULL; rule = rule->next) {
			if (pf_ruleMatch(rule, pbuf, netif, pdir)) {
				winner = rule;
				if (winner->quick)
					break;
			}
		}
	}

	if (winner != NULL)
		action = winner->action;

	mutexUnlock(filter_common.pf_lock);

	if (action == pfblock)
		return 1;

	return 0;
}


int pf_filterIn(struct pbuf *pbuf, struct netif *netif)
{
	return pf_filter(pbuf, netif, packet_dir_in);
}


int pf_filterOut(struct pbuf *pbuf, struct netif *netif)
{
	return pf_filter(pbuf, netif, packet_dir_out);
}


static void pf_ruleAdd(pfrule_t **list, pfrule_t **head, pfrule_t *n)
{
	pfrule_t *t;

	if (*list == NULL) {
		*list = n;
	}
	else if (head != NULL && *head != NULL) {
		(*head)->next = n;
		n->prev = (*head);
		*head = n;
	}
	else {
		t = *list;
		while (t->next != NULL)
			t = t->next;

		t->next = n;
		n->prev = t;

		if (head != NULL)
			*head = t;
	}
}


void pf_rulesUpdate(pfrule_t *list)
{
	pfrule_t *rule, *purehead = NULL;

	mutexLock(filter_common.pf_lock);

	if (filter_common.rules != NULL)
		_pf_listDestroy(&filter_common.rules);

	if (filter_common.puremac_rules != NULL)
		_pf_listDestroy(&filter_common.puremac_rules);

	filter_common.rules = list;

	for (rule = filter_common.rules; rule != NULL; rule = rule->next) {
		if (!rule->filter_mac || !(rule->direction & pfin))
			continue;

		if (rule->src_mask != 0 || rule->dst_mask != 0 || rule->src_port != 0 || rule->dst_port != 0)
			continue;

		if (rule->tcp_flags_mask != 0 || rule->protocol[0] != 0xff)
			continue;

		rule->prev->next = rule->next;
		rule->next->prev = rule->prev;
		rule->prev = NULL;
		rule->next = NULL;

		pf_ruleAdd(&filter_common.puremac_rules, &purehead, rule);
	}

	mutexUnlock(filter_common.pf_lock);
}


int _pf_processRule(pfrule_t *rule)
{
	struct netif *netif;
	char name[2];
	unsigned char num;

	if ((rule->tcp_flags | rule->tcp_flags_mask) != rule->tcp_flags_mask)
		return -EINVAL;

	if (rule->interface[0] != '\0') {
		name[0] = rule->interface[0];
		name[1] = rule->interface[1];
		num = atoi(&rule->interface[2]);

		for (rule->netif = NULL, netif = netif_list; netif != NULL; netif = netif->next) {
			if (netif->name[0] == name[0] && netif->name[1] == name[1] && netif->num == num) {
				rule->netif = netif;
				break;
			}
		}

		if (rule->netif == NULL)
			return -ENOENT;
	}
	else {
		rule->netif = NULL;
	}

	rule->src_port = PP_HTONS(rule->src_port);
	rule->dst_port = PP_HTONS(rule->dst_port);

	rule->src_addr &= 0xffffffff << (32 - rule->src_mask);
	rule->dst_addr &= 0xffffffff << (32 - rule->dst_mask);

	return EOK;
}


void _pf_listDestroy(pfrule_t **list)
{
	pfrule_t *victim;

	if (*list != NULL) {
		while ((*list)->prev != NULL) {
			victim = (*list)->prev;
			(*list)->prev = victim->prev;
			free(victim);
		}

		while ((*list)->next != NULL) {
			victim = (*list)->next;
			(*list)->next = victim->next;
			free(victim);
		}

		free(*list);
		*list = NULL;
	}
}


void init_filters(void)
{
#ifdef HAVE_PF
	mutexCreate(&filter_common.pf_lock);
	filter_common.rules = NULL;
	filter_common.puremac_rules = NULL;
#endif
}
