/*
 * Phoenix-RTOS --- networking stack
 *
 * Utilities: HW debugging helpers
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * %LICENSE%
 */
#ifndef NETLIB_HWDEBUG_H_
#define NETLIB_HWDEBUG_H_

#include <stdint.h>


uint32_t hwdebug_read(addr_t addr);


#endif /* NETLIB_HWDEBUG_H_ */
