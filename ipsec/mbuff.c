/*
 * Phoenix-RTOS --- LwIP port
 *
 * Copyright 2016 Phoenix Systems
 * Author: Kuba Sejdak, Marek Bialowas
 *
 * %LICENSE%
 */

#include "mbuff.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/minmax.h>


mbuff_t *mbuff_alloc(void)
{
	mbuff_t *mbuff = malloc(sizeof(mbuff_t));
	if (mbuff == NULL)
		return NULL;

	mbuff->next = NULL;
	mbuff->data = NULL;
	mbuff->size = 0;
	mbuff->total_size = 0;
	mbuff->ancillary = NULL;
	mbuff->ancillary_size = 0;
	mbuff->priv = NULL;

	return mbuff;
}

void mbuff_free(mbuff_t *mbuff)
{
	mbuff_t *it = mbuff;
	while (it != NULL) {
		mbuff_t *to_remove = it;
		it = it->next;

		free(to_remove->data);
		free(to_remove->ancillary);
		free(to_remove->priv);
		free(to_remove);
	}
}

int mbuff_feedEx(mbuff_t *mbuff, const void *data, size_t size, void *priv)
{
	mbuff_t *buff = mbuff;

	if (mbuff->size != 0) {
		buff = mbuff_alloc();
		if (buff == NULL)
			return -ENOMEM;
	}

	buff->data = malloc(size);
	if (buff->data == NULL) {
		if (buff != mbuff)
			free(buff);

		return -ENOMEM;
	}

	memcpy(buff->data, data, size);
	buff->size = size;
	buff->total_size = size;
	buff->priv = priv;

	mbuff_merge(mbuff, buff);
	return size;
}

int mbuff_feed(mbuff_t *mbuff, const void *data, size_t size)
{
	return mbuff_feedEx(mbuff, data, size, NULL);
}

int mbuff_peekEx(mbuff_t *mbuff, void *data, size_t size, void **ancillary, size_t *ancillary_size, void **priv)
{
	int to_read = min(mbuff->total_size, size);
	int offset = 0;

	mbuff_t *it = NULL;
	while (offset != to_read) {
		it = (it == NULL) ? mbuff : it->next;

		int read_size = min(it->size, (to_read - offset));
		memcpy(data + offset, it->data, read_size);
		offset += read_size;

		if (it->ancillary != NULL) {
			if (ancillary != NULL && ancillary_size != NULL) {
				*ancillary = it->ancillary;
				*ancillary_size = it->ancillary_size;
			}
			else
				free(it->ancillary);

			it->ancillary = NULL;
			it->ancillary_size = 0;
			break;
		}
	}

	if (priv != NULL)
		*priv = it->priv;

	return offset;
}

int mbuff_peek(mbuff_t *mbuff, void *data, size_t size)
{
	return mbuff_peekEx(mbuff, data, size, NULL, NULL, NULL);
}

int mbuff_takeEx(mbuff_t **mbuff, void *data, size_t size, void **ancillary, size_t *ancillary_size, void **priv)
{
	int read_size = mbuff_peekEx(*mbuff, data, size, ancillary, ancillary_size, priv);
	if (read_size < 0)
		return read_size;

	mbuff_remove(mbuff, read_size);
	return read_size;
}

int mbuff_take(mbuff_t **mbuff, void *data, size_t size)
{
	return mbuff_takeEx(mbuff, data, size, NULL, NULL, NULL);
}

mbuff_t *mbuff_last(mbuff_t *mbuff)
{
	mbuff_t *it;
	for (it = mbuff; it->next != NULL; it = it->next)
		;
	return it;
}

size_t mbuff_size(mbuff_t *mbuff)
{
	return mbuff->total_size;
}

size_t mbuff_sizeFirst(mbuff_t *mbuff)
{
	return mbuff->size;
}

void mbuff_merge(mbuff_t *first, mbuff_t *second)
{
	if (first == NULL || second == NULL)
		return;

	if (first == second)
		return;

	mbuff_t *it;
	for (it = first; it != NULL; it = it->next) {
		it->total_size += second->total_size;

		if (it->next == NULL) {
			it->next = second;
			break;
		}
	}
}

void mbuff_remove(mbuff_t **mbuff, size_t size)
{
	int to_remove = size;
	int removed = 0;

	assert((*mbuff)->total_size >= to_remove);

	mbuff_t *it = *mbuff;
	while (removed != to_remove) {
		mbuff_t *obsolete = it;

		int remove_size = min(it->size, (to_remove - removed));
		if (remove_size < it->size) {
			mbuff_t *new_mbuff = mbuff_alloc();
			mbuff_feed(new_mbuff, it->data + remove_size, it->size - remove_size);
			mbuff_merge(new_mbuff, it->next);
			it = new_mbuff;
		}
		else
			it = it->next;

		obsolete->next = NULL;
		mbuff_free(obsolete);

		removed += remove_size;
	}

	*mbuff = it;
	if (*mbuff == NULL)
		*mbuff = mbuff_alloc();
}
