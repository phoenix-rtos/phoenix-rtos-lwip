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


typedef int (*test_setup_fn)(void *arg);
typedef int (*test_teardown_fn)(void *arg);


struct selftest_params {
	const char *module;
	struct netif *netif;

	struct {
		test_setup_fn setup;
		test_teardown_fn teardown;
		void *arg;
	};

	bool is_crc_stripped;
	bool verbose;
};


int physelftest(const struct selftest_params *params);


#endif /* NET_PHYSELFTEST_H_ */
