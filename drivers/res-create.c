/*
 * Phoenix-RTOS --- networking stack
 *
 * Utilities: cond/mutex bulk create
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * %LICENSE%
 */
#include <errno.h>
#include "res-create.h"


__attribute__((cold)) int create_mutexcond_bulk(handle_t *out, size_t n, uint32_t condMask)
{
	size_t i;
	int err = 0;

	if (n > (8 * sizeof(condMask))) {
		return -EINVAL;
	}

	for (i = 0; i < n; ++i) {
		err = ((condMask & (1U << i)) != 0) ? condCreate(&out[i]) : mutexCreate(&out[i]);
		if (err < 0) {
			break;
		}
	}

	if (i == n) {
		return 0;
	}

	while (i > 0) {
		i--;
		resourceDestroy(out[i]);
	}

	return err;
}
