/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP Wi-Fi
 *
 * Copyright 2021 Phoenix Systems
 * Author: Ziemowit Leszczynski
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "lwip/sys.h"

#include "cyabs_rtos.h"
#include "cy_log.h"

#include <time.h>
#include <unistd.h>
#include <stdlib.h>


cy_rslt_t cy_rtos_create_thread(cy_thread_t *thread, cy_thread_entry_fn_t entry_function,
	const char *name, void *stack, uint32_t stack_size,
	cy_thread_priority_t priority, cy_thread_arg_t arg)
{
	cy_log_msg(CYLF_RTOS, CY_LOG_DEBUG, "cy_rtos_create_thread (thread=%p name=%s stack=%p stack_size=%u priority=%d)\n",
		thread, name, stack, stack_size, priority);

	if (thread == NULL)
		return CY_RTOS_BAD_PARAM;

	/* NOTE: user stack is not supported */
	if (stack != NULL)
		return CY_RTOS_BAD_PARAM;

	if (sys_thread_opt_new(name, entry_function, arg, stack_size, 4, thread) < 0)
		return CY_RTOS_NO_MEMORY;

	return CY_RSLT_SUCCESS;
}


void cy_rtos_exit_thread(void)
{
	cy_log_msg(CYLF_RTOS, CY_LOG_DEBUG, "cy_rtos_exit_thread\n");

	/* nothing to do */
}


cy_rslt_t cy_rtos_terminate_thread(cy_thread_t *thread)
{
	cy_log_msg(CYLF_RTOS, CY_LOG_ERR, "cy_rtos_terminate_thread (thread=%p) - not implemented!\n", thread);

	/* TODO */

	return CY_RTOS_GENERAL_ERROR;
}


cy_rslt_t cy_rtos_join_thread(cy_thread_t *thread)
{
	cy_log_msg(CYLF_RTOS, CY_LOG_DEBUG, "cy_rtos_join_thread (thread=%p)\n", thread);

	if (sys_thread_join(*thread) < 0)
		return CY_RTOS_GENERAL_ERROR;

	return CY_RSLT_SUCCESS;
}


cy_rslt_t cy_rtos_init_mutex2(cy_mutex_t *mutex, bool recursive)
{
	cy_log_msg(CYLF_RTOS, CY_LOG_DEBUG, "cy_rtos_init_mutex2 (mutex=%p recursive=%u)\n", mutex, recursive);

	// TODO: support recursive mutex
	if (mutex == NULL)
		return CY_RTOS_BAD_PARAM;

	if (mutexCreate(mutex) < 0)
		return CY_RTOS_NO_MEMORY;

	return CY_RSLT_SUCCESS;
}


cy_rslt_t cy_rtos_get_mutex(cy_mutex_t *mutex, cy_time_t timeout_ms)
{
	if (mutex == NULL)
		return CY_RTOS_BAD_PARAM;

	if (timeout_ms == 0) {
		if (mutexTry(*mutex) == 0)
			return CY_RSLT_SUCCESS;
	}
	else if (timeout_ms == CY_RTOS_NEVER_TIMEOUT) {
		if (mutexLock(*mutex) == 0)
			return CY_RSLT_SUCCESS;
	}
	else {
		// TODO: optimize
		cy_time_t waited_ms = 0;

		while (timeout_ms > waited_ms) {
			if (mutexTry(*mutex) == 0)
				return CY_RSLT_SUCCESS;

			waited_ms += 1;
			usleep(1000);
		}
	}

	return CY_RTOS_TIMEOUT;
}


cy_rslt_t cy_rtos_set_mutex(cy_mutex_t *mutex)
{
	if (mutex == NULL)
		return CY_RTOS_BAD_PARAM;

	if (mutexUnlock(*mutex) < 0)
		return CY_RTOS_GENERAL_ERROR;

	return CY_RSLT_SUCCESS;
}


cy_rslt_t cy_rtos_deinit_mutex(cy_mutex_t *mutex)
{
	cy_log_msg(CYLF_RTOS, CY_LOG_DEBUG, "cy_rtos_deinit_mutex (mutex=%p)\n", mutex);

	if (mutex == NULL)
		return CY_RTOS_BAD_PARAM;

	resourceDestroy(*mutex);

	return CY_RSLT_SUCCESS;
}


cy_rslt_t cy_rtos_init_semaphore(cy_semaphore_t *semaphore, uint32_t maxcount, uint32_t initcount)
{
	cy_log_msg(CYLF_RTOS, CY_LOG_DEBUG, "cy_rtos_init_semaphore (semaphore=%p maxcount=%u initcount=%u)\n",
		semaphore, maxcount, initcount);

	if (semaphore == NULL)
		return CY_RTOS_BAD_PARAM;

	if (mutexCreate(&semaphore->mutex) != EOK)
		return CY_RTOS_NO_MEMORY;

	if (condCreate(&semaphore->cond) != EOK) {
		resourceDestroy(semaphore->mutex);
		return CY_RTOS_NO_MEMORY;
	}

	semaphore->m = maxcount;
	semaphore->v = initcount;

	return CY_RSLT_SUCCESS;
}


cy_rslt_t cy_rtos_get_semaphore(cy_semaphore_t *semaphore, cy_time_t timeout_ms, bool in_isr)
{
	// NOTE: ignore in_isr (we don't use semaphores in ISR)
	int err = EOK;
	time_t timeout = 0, now, when = 0;

	if (semaphore == NULL)
		return CY_RTOS_BAD_PARAM;

	if (timeout_ms && timeout_ms != CY_RTOS_NEVER_TIMEOUT) {
		gettime(&now, NULL);
		timeout = timeout_ms * 1000;
		when = now + timeout;
	}

	mutexLock(semaphore->mutex);

	for (;;) {
		if (semaphore->v > 0) {
			--semaphore->v;
			break;
		}

		if (timeout_ms == 0) {
			err = -ETIME;
			break;
		}

		if ((err = condWait(semaphore->cond, semaphore->mutex, timeout)) == -ETIME)
			break;

		if (timeout) {
			gettime(&now, NULL);

			if (now >= when)
				timeout = 1;
			else
				timeout = when - now;
		}
	}

	mutexUnlock(semaphore->mutex);

	return (err == EOK ? CY_RSLT_SUCCESS : CY_RTOS_TIMEOUT);
}


cy_rslt_t cy_rtos_set_semaphore(cy_semaphore_t *semaphore, bool in_isr)
{
	// NOTE: ignore in_isr (we don't use semaphores in ISR)
	if (semaphore == NULL)
		return CY_RTOS_BAD_PARAM;

	mutexLock(semaphore->mutex);

	if (semaphore->v < semaphore->m) {
		condSignal(semaphore->cond);
		++semaphore->v;
	}

	mutexUnlock(semaphore->mutex);

	return CY_RSLT_SUCCESS;
}


cy_rslt_t cy_rtos_deinit_semaphore(cy_semaphore_t *semaphore)
{
	cy_log_msg(CYLF_RTOS, CY_LOG_DEBUG, "cy_rtos_deinit_semaphore (semaphore=%p)\n", semaphore);

	if (semaphore == NULL)
		return CY_RTOS_BAD_PARAM;

	resourceDestroy(semaphore->mutex);
	resourceDestroy(semaphore->cond);

	return CY_RSLT_SUCCESS;
}


cy_rslt_t cy_rtos_get_time(cy_time_t *tval)
{
	struct timespec tp;

	if (tval == NULL)
		return CY_RTOS_BAD_PARAM;

	if (clock_gettime(CLOCK_MONOTONIC, &tp) < 0)
		return CY_RTOS_GENERAL_ERROR;

	*tval = tp.tv_sec * 1000 + tp.tv_nsec / 1000000;

	return CY_RSLT_SUCCESS;
}


cy_rslt_t cy_rtos_delay_milliseconds(cy_time_t num_ms)
{
	if (usleep(num_ms * 1000) < 0)
		return CY_RTOS_GENERAL_ERROR;

	return CY_RSLT_SUCCESS;
}
