/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer - mutex wrappers
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "arch/sys_arch.h"
#include "lwip/err.h"

#include <sys/threads.h>
#include <errno.h>


err_t sys_mutex_new(sys_mutex_t *mutex)
{
	switch (mutexCreate(mutex)) {
	case 0:
		return ERR_OK;
	case -ENOMEM:
		return ERR_MEM;
	case -EINVAL:
	default:
		return ERR_VAL;
	}
}


void sys_mutex_free(sys_mutex_t *mutex)
{
	if (mutex)
		resourceDestroy(*mutex);
}


void sys_mutex_lock(sys_mutex_t *mutex)
{
	mutexLock(*mutex);
}


void sys_mutex_unlock(sys_mutex_t *mutex)
{
	mutexUnlock(*mutex);
}
