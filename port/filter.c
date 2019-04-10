/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP ip and mac filtering
 *
 * Copyright 2019 Phoenix Systems
 * Author: Aleksander Kaminiski, Kamil Amanowicz
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <sys/threads.h>
#include <sys/msg.h>
#include <posix/utils.h>

#include "lwip/ip_addr.h"
#include "filter.h"


#define IP_FILTER_PATH "/local/ip_whitelist"
#define IP_FILTER_FORMAT "%u.%u.%u.%u/%u"
#define IP_FILTER_STACKSZ 4096

struct ip_tree_node {
	struct ip_tree_node *parent;
	struct ip_tree_node *child[2];
	unsigned short valid;
};


static struct {
	struct ip_tree_node root;
	handle_t lock;
	int init;
} ip_tree = { 0 };


static char ip_filter_stack[IP_FILTER_STACKSZ];


void ip_tree_add(unsigned int addr, unsigned char mask)
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


int ip_tree_find(unsigned int addr)
{
    struct ip_tree_node *node = &ip_tree.root;
    struct ip_tree_node *child;
    unsigned int bit = 1 << 31;
    int i;

	if (addr == IPADDR_ANY || addr == IPADDR_LOOPBACK)
		return 0;

	mutexLock(ip_tree.lock);
    for(i = 0; i <= 32; i++) {

		child = node->child[!!(addr & bit)];

        if (!ip_tree.init || node->valid) {
			mutexUnlock(ip_tree.lock);
			return 0;
		}

        if (child == NULL)
            break;

        bit >>= 1;
		node = child;
    }

	mutexUnlock(ip_tree.lock);
	return 1;
}


int ip_filter(struct pbuf *pbuf, struct netif *netif)
{
	struct ip_hdr *iphdr = (struct ip_hdr *)pbuf->payload;

	if (!ip_tree.init || !ip_tree_find(htonl(iphdr->src.addr)))
		return 0;

	pbuf_free(pbuf);
	return 1;
}


void ip_filter_remove_downward(struct ip_tree_node *node)
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


void ip_filter_load(void)
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


void ip_filter_reload(void)
{
	mutexLock(ip_tree.lock);
	ip_filter_remove_downward(&ip_tree.root);
	ip_filter_load();
	mutexUnlock(ip_tree.lock);
}


void ip_filter_thread(void *arg)
{
	msg_t msg = {0};
	unsigned int rid;
	oid_t oid = {0, 0};

	if (portCreate(&oid.port) < 0) {
		printf("can't create port\n");
		return;
	}

	if (create_dev(&oid, "/dev/ip_whitelist") < 0) {
		printf("can't create /dev/ip_whitelist\n");
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
			ip_filter_reload();
			break;
		default:
			break;
		}

		msgRespond(oid.port, &msg, rid);
	}
}


void ip_filter_init(void)
{
	mutexCreate(&ip_tree.lock);
	mutexLock(ip_tree.lock);
	ip_filter_load();
	mutexUnlock(ip_tree.lock);

	beginthread(ip_filter_thread, 4, ip_filter_stack, IP_FILTER_STACKSZ, NULL);
}


