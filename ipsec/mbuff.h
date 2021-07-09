/*
 * Phoenix-RTOS --- LwIP port
 *
 * Copyright 2016 Phoenix Systems
 * Author: Kuba Sejdak
 *
 * %LICENSE%
 */

#ifndef _MBUFF_H_
#define _MBUFF_H_

#include <stddef.h>


typedef struct _mbuff_t {
	struct _mbuff_t *next;

	void *data;
	size_t size;
	size_t total_size;

	void *ancillary;
	size_t ancillary_size;
	void *priv;
} mbuff_t;

mbuff_t *mbuff_alloc(void);
void mbuff_free(mbuff_t *mbuff);

int mbuff_feedEx(mbuff_t *mbuff, const void *data, size_t size, void *priv);
int mbuff_feed(mbuff_t *mbuff, const void *data, size_t size);
int mbuff_peekEx(mbuff_t *mbuff, void *data, size_t size, void **ancillary, size_t *ancillary_size, void **priv);
int mbuff_peek(mbuff_t *mbuff, void *data, size_t size);
int mbuff_takeEx(mbuff_t **mbuff, void *data, size_t size, void **ancillary, size_t *ancillary_size, void **priv);
int mbuff_take(mbuff_t **mbuff, void *data, size_t size);

mbuff_t *mbuff_last(mbuff_t *mbuff);
size_t mbuff_size(mbuff_t *mbuff);
size_t mbuff_sizeFirst(mbuff_t *mbuff);
void mbuff_merge(mbuff_t *first, mbuff_t *second);
void mbuff_remove(mbuff_t **mbuff, size_t size);

#endif
