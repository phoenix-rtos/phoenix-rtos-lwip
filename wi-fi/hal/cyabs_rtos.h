/***********************************************************************************************/ /**
 * \file cyabs_rtos.h
 *
 * \brief
 * Defines the Cypress RTOS Interface. Provides prototypes for functions that
 * allow Cypress libraries to use RTOS resources such as threads, mutexes &
 * timing functions in an abstract way. The APIs are implemented in the Port
 * Layer RTOS interface which is specific to the RTOS in use.
 *
 ***************************************************************************************************
 * \copyright
 * Copyright 2018-2021 Cypress Semiconductor Corporation (an Infineon company) or
 * an affiliate of Cypress Semiconductor Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **************************************************************************************************/

#pragma once

#include "cyabs_rtos_impl.h"
#include "cy_result.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * \defgroup group_abstraction_rtos_common Common
 * General types and defines for working with the RTOS abstraction layer.
 * \defgroup group_abstraction_rtos_event Events
 * APIs for acquiring and working with Events.
 * \defgroup group_abstraction_rtos_mutex Mutex
 * APIs for acquiring and working with Mutexes.
 * \defgroup group_abstraction_rtos_queue Queue
 * APIs for creating and working with Queues.
 * \defgroup group_abstraction_rtos_semaphore Semaphore
 * APIs for acquiring and working with Semaphores.
 * \defgroup group_abstraction_rtos_threads Threads
 * APIs for creating and working with Threads.
 * \defgroup group_abstraction_rtos_time Time
 * APIs for getting the current time and waiting.
 * \defgroup group_abstraction_rtos_timer Timer
 * APIs for creating and working with Timers.
 */

#ifdef __cplusplus
extern "C" {
#endif

/******************************************** CONSTANTS *******************************************/

/**
 * \ingroup group_abstraction_rtos_common
 * \{
 */

#if defined(DOXYGEN)
/** Return value indicating success */
#define CY_RSLT_SUCCESS ((cy_rslt_t)0x00000000U)
#endif

/** Used with RTOS calls that require a timeout.  This implies the call will never timeout. */
#define CY_RTOS_NEVER_TIMEOUT ((uint32_t)0xffffffffUL)

//
// Note on error strategy.  If the error is a normal part of operation (timeouts, full queues, empty
// queues), the these errors are listed here and the abstraction layer implementation must map from
// the underlying errors to these.  If the errors are special cases, the the error \ref
// CY_RTOS_GENERAL_ERROR will be returned and \ref cy_rtos_last_error() can be used to retrieve the
// RTOS specific error message.
//
/** Requested operation did not complete in the specified time */
#define CY_RTOS_TIMEOUT \
	CY_RSLT_CREATE(CY_RSLT_TYPE_ERROR, CY_RSLT_MODULE_ABSTRACTION_OS, 0)
/** The RTOS could not allocate memory for the specified operation */
#define CY_RTOS_NO_MEMORY \
	CY_RSLT_CREATE(CY_RSLT_TYPE_ERROR, CY_RSLT_MODULE_ABSTRACTION_OS, 1)
/** An error occurred in the RTOS */
#define CY_RTOS_GENERAL_ERROR \
	CY_RSLT_CREATE(CY_RSLT_TYPE_ERROR, CY_RSLT_MODULE_ABSTRACTION_OS, 2)
/** A bad argument was passed into the APIs */
#define CY_RTOS_BAD_PARAM \
	CY_RSLT_CREATE(CY_RSLT_TYPE_ERROR, CY_RSLT_MODULE_ABSTRACTION_OS, 5)
/** A memory alignment issue was detected. Ensure memory provided is aligned per \ref
   CY_RTOS_ALIGNMENT_MASK */
#define CY_RTOS_ALIGNMENT_ERROR \
	CY_RSLT_CREATE(CY_RSLT_TYPE_ERROR, CY_RSLT_MODULE_ABSTRACTION_OS, 6)

/** \} group_abstraction_rtos_common */

/********************************************* TYPES **********************************************/

/**
 * The state a thread can be in
 *
 * \ingroup group_abstraction_rtos_threads
 */
typedef enum cy_thread_state {
	CY_THREAD_STATE_INACTIVE,   /**< thread has not started or was terminated but not yet joined */
	CY_THREAD_STATE_READY,      /**< thread can run, but is not currently */
	CY_THREAD_STATE_RUNNING,    /**< thread is currently running */
	CY_THREAD_STATE_BLOCKED,    /**< thread is blocked waiting for something */
	CY_THREAD_STATE_TERMINATED, /**< thread has terminated but not freed */
	CY_THREAD_STATE_UNKNOWN     /**< thread is in an unknown state */
} cy_thread_state_t;

/**
 * The type of a function that is the entry point for a thread
 *
 * @param[in] arg the argument passed from the thread create call to the entry function
 *
 * \ingroup group_abstraction_rtos_threads
 */
typedef void (*cy_thread_entry_fn_t)(cy_thread_arg_t arg);

typedef struct {
	handle_t mutex;
	handle_t cond;
	volatile unsigned int v;
	unsigned int m;
} cy_semaphore_t;


/********************************************* Threads ********************************************/

/**
 * \ingroup group_abstraction_rtos_threads
 * \{
 */

/** Create a thread with specific thread argument.
 *
 * This function is called to startup a new thread. If the thread can exit, it must call
 * \ref cy_rtos_exit_thread() just before doing so. All created threads that can terminate, either
 * by themselves or forcefully by another thread MUST have \ref cy_rtos_join_thread() called on them
 * by another thread in order to cleanup any resources that might have been allocated for them.
 *
 * @param[out] thread         Pointer to a variable which will receive the new thread handle
 * @param[in]  entry_function Function pointer which points to the main function for the new thread
 * @param[in]  name           String thread name used for a debugger
 * @param[in]  stack          The buffer to use for the thread stack. This must be aligned to
 *                            \ref CY_RTOS_ALIGNMENT_MASK with a size of at least \ref
 *                            CY_RTOS_MIN_STACK_SIZE.
 *                            If stack is null, cy_rtos_create_thread will allocate a stack from
 *                            the heap.
 * @param[in]  stack_size     The size of the thread stack in bytes
 * @param[in]  priority       The priority of the thread. Values are operating system specific,
 *                            but some common priority levels are defined:
 *                                CY_THREAD_PRIORITY_LOW
 *                                CY_THREAD_PRIORITY_NORMAL
 *                                CY_THREAD_PRIORITY_HIGH
 * @param[in]  arg            The argument to pass to the new thread
 *
 * @return The status of thread create request. [\ref CY_RSLT_SUCCESS, \ref CY_RTOS_NO_MEMORY, \ref
 *         CY_RTOS_GENERAL_ERROR]
 */
cy_rslt_t cy_rtos_create_thread(cy_thread_t *thread, cy_thread_entry_fn_t entry_function,
	const char *name, void *stack, uint32_t stack_size,
	cy_thread_priority_t priority, cy_thread_arg_t arg);

/** Exit the current thread.
 *
 * This function is called just before a thread exits.  In some cases it is sufficient
 * for a thread to just return to exit, but in other cases, the RTOS must be explicitly
 * signaled. In cases where a return is sufficient, this should be a null funcition.
 * where the RTOS must be signaled, this function should perform that In cases operation.
 * In code using RTOS services, this function should be placed at any at any location
 * where the main thread function will return, exiting the thread. Threads that can
 * exit must still be joined (\ref cy_rtos_join_thread) to ensure their resources are
 * fully cleaned up.
 *
 * @return The status of thread exit request. [\ref CY_RSLT_SUCCESS, \ref CY_RTOS_GENERAL_ERROR]
 */
void cy_rtos_exit_thread(void);

/** Terminates another thread.
 *
 * This function is called to terminate another thread and reap the resources claimed
 * by the thread. This should be called both when forcibly terminating another thread
 * as well as any time a thread can exit on its own. For some RTOS implementations
 * this is not required as the thread resources are claimed as soon as it exits. In
 * other cases, this must be called to reclaim resources. Threads that are terminated
 * must still be joined (\ref cy_rtos_join_thread) to ensure their resources are fully
 * cleaned up.
 *
 * @param[in] thread Handle of the thread to terminate
 *
 * @returns The status of the thread terminate. [\ref CY_RSLT_SUCCESS, \ref CY_RTOS_GENERAL_ERROR]
 */
cy_rslt_t cy_rtos_terminate_thread(cy_thread_t *thread);

/** Waits for a thread to complete.
 *
 * This must be called on any thread that can complete to ensure that any resources that
 * were allocated for it are cleaned up.
 *
 * @param[in] thread Handle of the thread to wait for
 *
 * @returns The status of thread join request. [\ref CY_RSLT_SUCCESS, \ref CY_RTOS_GENERAL_ERROR]
 */
cy_rslt_t cy_rtos_join_thread(cy_thread_t *thread);

/** Checks if the thread is running
 *
 * This function is called to determine if a thread is actively running or not. For information on
 * the thread state, use the \ref cy_rtos_get_thread_state() function.
 *
 * @param[in] thread     Handle of the terminated thread to delete
 * @param[out] running   Returns true if the thread is running, otherwise false
 *
 * @returns The status of the thread running check. [\ref CY_RSLT_SUCCESS, \ref
 *          CY_RTOS_GENERAL_ERROR]
 */
cy_rslt_t cy_rtos_is_thread_running(cy_thread_t *thread, bool *running);

/** Gets the state the thread is currently in
 *
 * This function is called to determine if a thread is running/blocked/inactive/ready etc.
 *
 * @param[in] thread     Handle of the terminated thread to delete
 * @param[out] state     Returns the state the thread is currently in
 *
 * @returns The status of the thread state check. [\ref CY_RSLT_SUCCESS, \ref CY_RTOS_GENERAL_ERROR]
 */
cy_rslt_t cy_rtos_get_thread_state(cy_thread_t *thread, cy_thread_state_t *state);

/** Get current thread handle
 *
 * Returns the unique thread handle of the current running thread.
 *
 * @param[out] thread Handle of the current running thread
 *
 * @returns The status of thread join request. [\ref CY_RSLT_SUCCESS, \ref CY_RTOS_GENERAL_ERROR]
 */
cy_rslt_t cy_rtos_get_thread_handle(cy_thread_t *thread);


/** Suspend current thread until notification is received
 *
 * This function suspends the execution of current thread until it is notified
 * by \ref cy_rtos_set_thread_notification from another thread or ISR, or timed out with
 * specify timeout value
 *
 * @param[in] timeout_ms  Maximum number of milliseconds to wait
 *                        Use the \ref CY_RTOS_NEVER_TIMEOUT constant to wait forever.
 *
 * @returns The status of thread wait. [\ref CY_RSLT_SUCCESS, \ref CY_RTOS_TIMEOUT, \ref
 *                                     CY_RTOS_GENERAL_ERROR]
 */
cy_rslt_t cy_rtos_wait_thread_notification(cy_time_t timeout_ms);


/** Set the thread notification for a thread
 *
 * This function sets the thread notification for the target thread.
 * The target thread waiting for the notification to be set will resume from suspended state.
 *
 * @param[in] thread     Handle of the target thread
 * @param[in] in_isr     If true this is being called from within an ISR
 *
 * @returns The status of thread wait. [\ref CY_RSLT_SUCCESS, \ref CY_RTOS_GENERAL_ERROR,
 *                                      \ref CY_RTOS_BAD_PARAM]
 */
cy_rslt_t cy_rtos_set_thread_notification(cy_thread_t *thread, bool in_isr);


/** \} group_abstraction_rtos_threads */


/********************************************* Mutexes ********************************************/

/**
 * \ingroup group_abstraction_rtos_mutex
 * \{
 */

/** Create a recursive mutex.
 *
 * Creates a binary mutex which can be used for mutual exclusion to prevent simulatenous
 * access of shared resources. Created mutexes can support priority inheritance if recursive.
 *
 * This function has been replaced by \ref cy_rtos_init_mutex2 which allow for specifying
 * whether or not the mutex supports recursion or not.
 *
 * @param[out] mutex Pointer to the mutex handle to be initialized
 *
 * @return The status of mutex creation request. [\ref CY_RSLT_SUCCESS, \ref CY_RTOS_NO_MEMORY, \ref
 *         CY_RTOS_GENERAL_ERROR]
 */
#define cy_rtos_init_mutex(mutex) cy_rtos_init_mutex2(mutex, true)

/** Create a mutex which can support recursion or not.
 *
 * Creates a binary mutex which can be used for mutual exclusion to prevent simulatenous
 * access of shared resources. Created mutexes can support priority inheritance if recursive.
 *
 * \note Not all RTOS implementations support non-recursive mutexes. In this case a recursive
 * mutex will be created.
 *
 * @param[out] mutex     Pointer to the mutex handle to be initialized
 * @param[in]  recursive Should the created mutex support recursion or not
 *
 * @return The status of mutex creation request. [\ref CY_RSLT_SUCCESS, \ref CY_RTOS_NO_MEMORY, \ref
 *         CY_RTOS_GENERAL_ERROR]
 */
cy_rslt_t cy_rtos_init_mutex2(cy_mutex_t *mutex, bool recursive);

/** Get a mutex.
 *
 * If the mutex is available, it is acquired and this function returned.
 * If the mutex is not available, the thread waits until the mutex is available
 * or until the timeout occurs.
 *
 * @note This function must not be called from an interrupt context as it may block.
 *
 * @param[in] mutex       Pointer to the mutex handle
 * @param[in] timeout_ms  Maximum number of milliseconds to wait while attempting to get
 *                        the mutex. Use the \ref CY_RTOS_NEVER_TIMEOUT constant to wait forever.
 *
 * @return The status of the get mutex. Returns timeout if mutex was not acquired
 *                    before timeout_ms period. [\ref CY_RSLT_SUCCESS, \ref CY_RTOS_TIMEOUT, \ref
 *                    CY_RTOS_GENERAL_ERROR]
 */
cy_rslt_t cy_rtos_get_mutex(cy_mutex_t *mutex, cy_time_t timeout_ms);

/** Set a mutex.
 *
 * The mutex is released allowing any other threads waiting on the mutex to
 * obtain the semaphore.
 *
 * @param[in] mutex   Pointer to the mutex handle
 *
 * @return The status of the set mutex request. [\ref CY_RSLT_SUCCESS, \ref CY_RTOS_GENERAL_ERROR]
 *
 */
cy_rslt_t cy_rtos_set_mutex(cy_mutex_t *mutex);

/** Deletes a mutex.
 *
 * This function frees the resources associated with a semaphore.
 *
 * @param[in] mutex Pointer to the mutex handle
 *
 * @return The status to the delete request. [\ref CY_RSLT_SUCCESS, \ref CY_RTOS_GENERAL_ERROR]
 */
cy_rslt_t cy_rtos_deinit_mutex(cy_mutex_t *mutex);

/** \} group_abstraction_rtos_mutex */

/******************************************** Semaphores ******************************************/

/**
 * \ingroup group_abstraction_rtos_semaphore
 * \{
 */

/**
 * Create a semaphore
 *
 * This is basically a counting semaphore. It can be used for synchronization between tasks and
 * tasks and interrupts.
 *
 * @param[in,out] semaphore  Pointer to the semaphore handle to be initialized
 * @param[in] maxcount       The maximum count for this semaphore
 * @param[in] initcount      The initial count for this semaphore
 *
 * @return The status of the semaphore creation. [\ref CY_RSLT_SUCCESS, \ref CY_RTOS_NO_MEMORY, \ref
 *         CY_RTOS_GENERAL_ERROR]
 */
cy_rslt_t cy_rtos_init_semaphore(cy_semaphore_t *semaphore, uint32_t maxcount, uint32_t initcount);

/**
 * Get/Acquire a semaphore
 *
 * If the semaphore count is zero, waits until the semaphore count is greater than zero.
 * Once the semaphore count is greater than zero, this function decrements
 * the count and return.  It may also return if the timeout is exceeded.
 *
 * @param[in] semaphore   Pointer to the semaphore handle
 * @param[in] timeout_ms  Maximum number of milliseconds to wait while attempting to get
 *                        the semaphore. Use the \ref CY_RTOS_NEVER_TIMEOUT constant to wait
 *                        forever. Must be zero if in_isr is true.
 * @param[in] in_isr      true if we are trying to get the semaphore from with an ISR
 * @return The status of get semaphore operation [\ref CY_RSLT_SUCCESS, \ref CY_RTOS_TIMEOUT, \ref
 *         CY_RTOS_NO_MEMORY, \ref CY_RTOS_GENERAL_ERROR]
 */
cy_rslt_t cy_rtos_get_semaphore(cy_semaphore_t *semaphore, cy_time_t timeout_ms, bool in_isr);

/**
 * Set/Release a semaphore
 *
 * Increments the semaphore count, up to the maximum count for this semaphore.
 *
 * @param[in] semaphore   Pointer to the semaphore handle
 * @param[in] in_isr      Value of true indicates calling from interrupt context
 *                        Value of false indicates calling from normal thread context
 * @return The status of set semaphore operation [\ref CY_RSLT_SUCCESS, \ref CY_RTOS_NO_MEMORY, \ref
 *         CY_RTOS_GENERAL_ERROR]
 */
cy_rslt_t cy_rtos_set_semaphore(cy_semaphore_t *semaphore, bool in_isr);

/**
 * Get the count of a semaphore.
 *
 * Gets the number of available tokens on the semaphore.
 *
 * @param[in]  semaphore   Pointer to the semaphore handle
 * @param[out] count       Pointer to the return count
 * @return The status of get semaphore count operation [\ref CY_RSLT_SUCCESS, \ref
 *         CY_RTOS_GENERAL_ERROR]
 */
cy_rslt_t cy_rtos_get_count_semaphore(cy_semaphore_t *semaphore, size_t *count);

/**
 * Deletes a semaphore
 *
 * This function frees the resources associated with a semaphore.
 *
 * @param[in] semaphore   Pointer to the semaphore handle
 *
 * @return The status of semaphore deletion [\ref CY_RSLT_SUCCESS, \ref CY_RTOS_NO_MEMORY, \ref
 *         CY_RTOS_GENERAL_ERROR]
 */
cy_rslt_t cy_rtos_deinit_semaphore(cy_semaphore_t *semaphore);

/** \} group_abstraction_rtos_semaphore */

/********************************************** Time **********************************************/

/**
 * \ingroup group_abstraction_rtos_time
 * \{
 */

/** Gets time in milliseconds since RTOS start.
 *
 * @note Since this is only 32 bits, it will roll over every 49 days, 17 hours, 2 mins, 47.296
 * seconds
 *
 * @param[out] tval Pointer to the struct to populate with the RTOS time
 *
 * @returns Time in milliseconds since the RTOS started.
 */
cy_rslt_t cy_rtos_get_time(cy_time_t *tval);

/** Delay for a number of milliseconds.
 *
 * Processing of this function depends on the minimum sleep
 * time resolution of the RTOS. The current thread should sleep for
 * the longest period possible which is less than the delay required,
 * then makes up the difference with a tight loop.
 *
 * @param[in] num_ms The number of milliseconds to delay for
 *
 * @return The status of the delay request. [\ref CY_RSLT_SUCCESS, \ref CY_RTOS_GENERAL_ERROR]
 */
cy_rslt_t cy_rtos_delay_milliseconds(cy_time_t num_ms);

/** \} group_abstraction_rtos_time */

#ifdef __cplusplus
}  // extern "C"
#endif
