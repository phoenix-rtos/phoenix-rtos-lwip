/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP status devices
 *
 * Copyright 2021 Phoenix Systems
 * Author: Ziemowit Leszczynski
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PHOENIX_DEVS_H_
#define PHOENIX_DEVS_H_

#include <sys/types.h>


int devs_init(unsigned int port);


int dev_open(id_t id, int flags);


int dev_close(id_t id);


int dev_read(id_t id, void *data, size_t size, size_t offset);


int dev_write(id_t id, void *data, size_t size, size_t offset);


#endif /* PHOENIX_DEVS_H_ */
