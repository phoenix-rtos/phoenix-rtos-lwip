/*
 * Phoenix-RTOS
 *
 * lwIP
 *
 * Common MAC layer functions
 *
 * Copyright 2026 Phoenix Systems
 * Author: Julian Uziemblo
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef NET_MAC_H_
#define NET_MAC_H_

#include <stdbool.h>

#include "netif-driver.h"


void mac_setLinkState(struct netif *netif, bool linkState);


#endif
