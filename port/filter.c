/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP ip and mac filtering
 *
 * Copyright 2019 Phoenix Systems
 * Author: Aleksander Kaminiski, Kamil Amanowicz, Jan Sikorski
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <sys/threads.h>
#include <sys/msg.h>
#include <sys/rb.h>
#include <sys/list.h>
#include <posix/utils.h>

#include <errno.h>

#include "lwip/ip_addr.h"
#include "lwip/prot/tcp.h"
#include "lwip/prot/udp.h"
#include "lwip/prot/ethernet.h"
#include "filter.h"


static struct {
	handle_t pf_lock;
	pf_rule_t *pf_rules;
} filter_common;


static int pf_rule_match(pf_rule_t *rule, struct pbuf *pbuf, struct netif *netif)
{
	struct ip_hdr *iphdr = (struct ip_hdr *)pbuf->payload;
	int i, hlen;

	if (rule->netif != NULL && rule->netif != netif)
		return 0;

	if (rule->dst_addr.addr != (iphdr->dest.addr & rule->dst_mask.addr))
		return 0;

	if (rule->src_addr.addr != (iphdr->src.addr & rule->src_mask.addr))
		return 0;

	if (rule->proto[0] != 0xff) {
		for (i = 0; i < sizeof(rule->proto) && rule->proto[i] != 0xff; ++i) {
			if (rule->proto[i] == IPH_PROTO(iphdr))
				goto proto_match;
		}

		return 0;
	}

proto_match:
	hlen = 4 * IPH_HL(iphdr);

	if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
		struct udp_hdr *udphdr = (struct udp_hdr *)((u8_t *)iphdr + hlen);

		if (rule->src_port_set && udphdr->src != rule->src_port)
			return 0;
		if (rule->dst_port_set && udphdr->dest != rule->dst_port)
			return 0;
	}
	else if (IPH_PROTO(iphdr) == IP_PROTO_TCP) {
		struct tcp_hdr *tcphdr = (struct tcp_hdr *)((u8_t *)iphdr + hlen);

		if (rule->src_port_set && tcphdr->src != rule->src_port)
			return 0;
		if (rule->dst_port_set && tcphdr->dest != rule->dst_port)
			return 0;
		if (rule->tcp_flags != (TCPH_FLAGS(tcphdr) & rule->tcp_flags_mask))
			return 0;
	}

	return 1;
}


static int pf_rule_apply(pf_rule_t *rule, struct pbuf *pbuf, struct netif *netif)
{
	return rule->action;
}


int pf_apply(struct pbuf *pbuf, struct netif *netif)
{
	pf_rule_t *rule, *match;
	int rv;

	mutexLock(filter_common.pf_lock);
	if ((rule = filter_common.pf_rules) == NULL) {
		mutexUnlock(filter_common.pf_lock);
		return 0;
	}

	while (rule != NULL) {
		if (pf_rule_match(rule, pbuf, netif)) {
			match = rule;

			if (rule->quick)
				break;
		}
	}

	rv = pf_rule_apply(match, pbuf, netif);
	mutexUnlock(filter_common.pf_lock);
	return rv;
}


int pf_ruleAdd(const pf_rule_t *rule)
{
	pf_rule_t *new_rule = malloc(sizeof(*rule));

	if (new_rule == NULL)
		return -ENOMEM;

	memcpy(new_rule, rule, sizeof(*rule));

	mutexLock(filter_common.pf_lock);
	LIST_ADD(&filter_common.pf_rules, new_rule);
	mutexUnlock(filter_common.pf_lock);

	return EOK;
}


int pf_ruleRemove(const char *label)
{
	pf_rule_t *rule;

	mutexLock(filter_common.pf_lock);
	if ((rule = filter_common.pf_rules) != NULL) {
		do {
			if (!strcmp(label, rule->label)) {
				LIST_REMOVE(&filter_common.pf_rules, rule);
				mutexUnlock(filter_common.pf_lock);
				free(rule);
				return EOK;
			}
		} while (rule != filter_common.pf_rules);
	}
	mutexUnlock(filter_common.pf_lock);
	return -ENOENT;
}


int if_filter(struct pbuf *pbuf, struct netif *netif)
{
	return 0;
}



#define IP_FILTER_PATH "/local/ip_whitelist"
#define IP_FILTER_FORMAT "%u.%u.%u.%u/%u"

#define MAC_FILTER_PATH "/local/mac_whitelist"
#define MAC_FILTER_FORMAT "%02x:%02x:%02x:%02x:%02x:%02x"

#define FILTER_STACKSZ 4096


struct ip_tree_node {
	struct ip_tree_node *parent;
	struct ip_tree_node *child[2];
	unsigned short valid;
};


struct {
	struct ip_tree_node root;
	handle_t lock;
	int init;
} ip_tree = { 0 };


struct mac_node {
	u64 mac;
	rbnode_t node;
};


struct {
	rbtree_t rb_tree;
	handle_t lock;
	int init;
} mac_tree = { 0 };


static char ip_filter_stack[FILTER_STACKSZ];


static int mac_node_cmp(rbnode_t *n1, rbnode_t *n2)
{
	struct mac_node *mc1 = lib_treeof(struct mac_node, node, n1);
	struct mac_node *mc2 = lib_treeof(struct mac_node, node, n2);

	if (mc1->mac == mc2->mac)
		return 0;

	return mc1->mac > mc2->mac ? 1 : -1;
}


static void ip_tree_add(unsigned int addr, unsigned char mask)
{
    struct ip_tree_node *node = &ip_tree.root;
    struct ip_tree_node *child;
    unsigned int bit = 1 << 31;
    int i, id;

    if ((mask < 0) || (mask > 32))
        return;

    if ((addr & ((~0) << (32 - mask))) != addr)
		return;

	for (i = 0; i < mask; i++) {

		id = !!(addr & bit);
        child = node->child[id];

        if (child == NULL) {
            child = calloc(1, sizeof(struct ip_tree_node));
			node->child[id] = child;
			child->parent = node;
		}

        bit >>= 1;

        node = child;
    }

    node->valid = 1;

    return;
}


static int ip_tree_find(unsigned int addr)
{
    struct ip_tree_node *node = &ip_tree.root;
    struct ip_tree_node *child;
    unsigned int bit = 1 << 31;
    int i;

	if (addr == IPADDR_ANY || addr == IPADDR_LOOPBACK)
		return 0;

    for(i = 0; i <= 32; i++) {

		child = node->child[!!(addr & bit)];

        if (node->valid)
			return 0;

        if (child == NULL)
            break;

        bit >>= 1;
		node = child;
    }

	return 1;
}


int mac_filter(struct pbuf *pbuf, struct netif *netif)
{
	struct eth_hdr *ethhdr = (struct eth_hdr *)pbuf->payload;
	struct mac_node node;

	memcpy(&node.mac, ethhdr->src.addr, sizeof(ethhdr->src.addr));

	mutexLock(mac_tree.lock);
	if (!mac_tree.init || lib_rbFind(&mac_tree.rb_tree, &node.node) != NULL) {
		mutexUnlock(mac_tree.lock);
		return 0;
	}
	mutexUnlock(mac_tree.lock);
	return 1;
}


int ip_filter(struct pbuf *pbuf, struct netif *netif)
{
	struct ip_hdr *iphdr = (struct ip_hdr *)pbuf->payload;

	mutexLock(ip_tree.lock);
	if (!ip_tree.init || !ip_tree_find(htonl(iphdr->src.addr))) {
		mutexUnlock(ip_tree.lock);
		return 0;
	}

	mutexUnlock(ip_tree.lock);
	pbuf_free(pbuf);
	return 1;
}


static void mac_filter_remove_downward(void)
{
	struct mac_node *root_node;

	while (mac_tree.rb_tree.root != NULL) {
		root_node = lib_treeof(struct mac_node, node, mac_tree.rb_tree.root);
		lib_rbRemove(&mac_tree.rb_tree, mac_tree.rb_tree.root);
		free(root_node);
	}
}


static void ip_filter_remove_downward(struct ip_tree_node *node)
{
	if (node == NULL)
		return;

	ip_filter_remove_downward(node->child[0]);
	ip_filter_remove_downward(node->child[1]);
	free(node->child[0]);
	free(node->child[1]);
	node->child[0] = NULL;
	node->child[1] = NULL;
}


static void mac_filter_load(void)
{
	int res;
	u8 a[6];
	FILE *file = fopen(MAC_FILTER_PATH, "r");
	struct mac_node *node;

	if (file == NULL) {
		mac_tree.init = 0;
		return;
	}

	while ((res = fscanf(file, MAC_FILTER_FORMAT, (u32 *)&a[0], (u32 *)&a[1], (u32 *)&a[2],
					(u32 *)&a[3], (u32 *)&a[4], (u32 *)&a[5])) != EOF) {
		if (res == 6) {
			node = calloc(1, sizeof(struct mac_node));
			memcpy(&node->mac, a, sizeof(a));
			lib_rbInsert(&mac_tree.rb_tree, &node->node);
		}
	}

	fclose(file);
	mac_tree.init = 1;
}


static void ip_filter_load(void)
{
	int res;
	ip4_addr_t ip4;
	unsigned a, b, c, d, mask;
	FILE *file = fopen(IP_FILTER_PATH, "r");

	if (file == NULL) {
		ip_tree.init = 0;
		return;
	}

	while ((res = fscanf(file, IP_FILTER_FORMAT, &a, &b, &c, &d, &mask)) != EOF) {
		if (res == 5) {
			IP4_ADDR(&ip4, a, b, c, d);
			ip_tree_add(htonl(ip4.addr), mask);
		}
	}

	fclose(file);
	ip_tree.init = 1;
}


static void mac_filter_reload(void)
{
	mutexLock(mac_tree.lock);
	mac_filter_remove_downward();
	mac_filter_load();
	mutexUnlock(mac_tree.lock);
}


static void ip_filter_reload(void)
{
	mutexLock(ip_tree.lock);
	ip_filter_remove_downward(&ip_tree.root);
	ip_filter_load();
	mutexUnlock(ip_tree.lock);
}


static void reload_filters(void)
{
#ifdef HAVE_IP_FILTER
	ip_filter_reload();
#endif
#ifdef HAVE_MAC_FILTER
	mac_filter_reload();
#endif
}


static void filter_thread(void *arg)
{
	msg_t msg = {0};
	unsigned int rid;
	oid_t oid = {0, 0};

	if (portCreate(&oid.port) < 0) {
		printf("can't create port\n");
		return;
	}

	if (create_dev(&oid, "/dev/whitelist") < 0) {
		printf("can't create /dev/whitelist\n");
		return;
	}

	for (;;) {
		if (msgRecv(oid.port, &msg, &rid) < 0)
			continue;

		switch (msg.type) {
		case mtRead:
			msg.o.io.err = EOF;
			break;
		case mtWrite:
			msg.o.io.err = msg.i.size;
			reload_filters();
			break;
		default:
			break;
		}

		msgRespond(oid.port, &msg, rid);
	}
}


static void mac_filter_init(void)
{
	mutexCreate(&mac_tree.lock);
	lib_rbInit(&mac_tree.rb_tree, mac_node_cmp, NULL);
	mutexLock(mac_tree.lock);
	mac_filter_load();
	mutexUnlock(mac_tree.lock);
}


static void ip_filter_init(void)
{
	mutexCreate(&ip_tree.lock);
	mutexLock(ip_tree.lock);
	ip_filter_load();
	mutexUnlock(ip_tree.lock);

}


void init_filters(void)
{
#ifdef HAVE_IP_FILTER
	ip_filter_init();
#endif
#ifdef HAVE_MAC_FILTER
	mac_filter_init();
#endif

#if defined(HAVE_IP_FILTER) || defined (HAVE_MAC_FILTER)
	beginthread(filter_thread, 4, ip_filter_stack, FILTER_STACKSZ, NULL);
#endif
}
