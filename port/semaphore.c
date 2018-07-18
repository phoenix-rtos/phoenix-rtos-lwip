/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer - semaphore wrapper
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "arch/cc.h"
#include "arch/sys_arch.h"
#include "lwip/err.h"
#include "lwip/sys.h"

#include <sys/threads.h>
#include <sys/time.h>
#include <errno.h>
#include <time.h>


err_t sys_sem_new(sys_sem_t *sem, u8_t count)
{
	switch (semaphoreCreate(sem, count)) {
	case 0:
		return ERR_OK;
	case -ENOMEM:
		return ERR_MEM;
	case -EINVAL:
	default:
		return ERR_VAL;
	}
}


void sys_sem_free(sys_sem_t *sem)
{
	semaphoreDone(sem);
}


void sys_sem_signal(sys_sem_t *sem)
{
	semaphoreUp(sem);
}


u32_t sys_arch_sem_wait(sys_sem_t *sem, u32_t timeout)
{
	time_t to, now;

	to = timeout * 1000;
	gettime(&now, NULL);

	switch (semaphoreDown(sem, to)) {
	case 0:
		gettime(&to, NULL);
		return (to - now + 499) / 1000;
	case -ETIME:
	default:
		return SYS_ARCH_TIMEOUT;
	}
}
