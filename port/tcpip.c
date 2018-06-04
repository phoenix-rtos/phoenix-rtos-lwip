/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer - TCP/IP thread wrapper
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <lwip/tcpip.h>

#include <sys/threads.h>
#include <string.h>


static void trigger_sem(void *arg)
{
	semaphoreUp(arg);
}


__constructor__(1000)
void init_lwip_tcpip(void)
{
	semaphore_t sem;
	int err;

	err = semaphoreCreate(&sem, 0);
	if (err)
		bail("can't alloc semaphore: %s", strerror(err));

	tcpip_init(trigger_sem, &sem);

	semaphoreDown(&sem, 0);
	semaphoreDone(&sem);
}
