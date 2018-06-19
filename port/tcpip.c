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
		errout(err, "semaphoreCreate()");

	tcpip_init(trigger_sem, &sem);

	semaphoreDown(&sem, 0);
	semaphoreDone(&sem);
}
