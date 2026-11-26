/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP Wi-Fi RF Test Application
 *
 * Copyright 2026 Phoenix Systems
 * Author: Jan Wisniewski
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _PH_LWIP_WIFI_RFTEST_H_
#define _PH_LWIP_WIFI_RFTEST_H_

#include <stdbool.h>
#include <sys/msg.h>


void rftest_init(void);


/* the RF test and normal Wi-Fi operation can't use the chip at the same time */
bool rftest_isInitialized(void);


void rftest_handleCtrl(msg_t *msg, bool wifiRunning);


#endif /* _PH_LWIP_WIFI_RFTEST_H_ */
