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


__attribute__((cold))
int create_mutexcond_bulk(handle_t *out, size_t n, size_t cond_mask)
{
	size_t i;
	int err = 0;

	if (n > 8 * sizeof(cond_mask))
		return -EINVAL;

	for (i = 0; i < n; ++i, ++out, cond_mask >>= 1) {
		err = cond_mask & 1 ? condCreate(out) : mutexCreate(out);
		if (err < 0)
			break;
	}

	if (i == n)
		return 0;

	while (i--)
		resourceDestroy(*out);

	return err;
}
