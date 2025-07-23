/*
 * Phoenix-RTOS --- networking stack
 *
 * PHY selftest routine
 *
 * Copyright 2025 Phoenix Systems
 * Author: Marek Białowąs, Julian Uziembło
 *
 * %LICENSE%
 */
#ifndef NET_PHYSELFTEST_H_
#define NET_PHYSELFTEST_H_

#include <stdbool.h>
#include <sys/threads.h>


struct selftest_params {
	const char *module;
	struct netif *netif;
	int (*setup)(void *arg);
	int (*teardown)(void *arg);
	bool verbose;
};


int physelftest(const struct selftest_params *params);


#endif /* NET_PHYSELFTEST_H_ */
