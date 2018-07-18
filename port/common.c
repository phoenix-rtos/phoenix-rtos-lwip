/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer - common helpers
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "arch/cc.h"
#include "arch/sys_arch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>


void bail(const char *format, ...)
{
	va_list arg;

	va_start(arg, format);
	vprintf(format, arg);
	va_end(arg);

	exit(1);
}


void errout(int err, const char *format, ...)
{
	va_list arg;

	va_start(arg, format);
	vprintf(format, arg);
	va_end(arg);

	printf(": %s (%d)\n", strerror(err), err);

	exit(1);
}

uint32_t sys_now(void)
{
	time_t now;

	gettime(&now, NULL);

	return now / 1000;
}


void sys_init(void)
{
	void init_lwip_global_lock(void);
	void init_lwip_threads(void);

	init_lwip_global_lock();
	init_lwip_threads();
}
