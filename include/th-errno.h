/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP errno wrapper
 *
 * Copyright 2019 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef PHOENIX_THREADED_ERRNO_H_
#define PHOENIX_THREADED_ERRNO_H_

#include <arch.h>
#include <errno.h>

// poor-man's TLS errno at (unused) bottom of thread's stack
// assuming stack is one page and aligned to its size

#define lwip_neg_errno (*(int *)((uintptr_t)STACK_PTR | (SIZE_PAGE - sizeof(int))))

#define set_errno(e) do { int __e = (e); if (!__builtin_constant_p(__e) || __e) lwip_neg_errno = -__e; } while (0)

#endif /* PHOENIX_THREADED_ERRNO_H_ */
