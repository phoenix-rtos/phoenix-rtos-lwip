/*
 * Phoenix-RTOS --- networking stack
 *
 * Huawei modem definitions
 *
 * Copyright 2021 Phoenix Systems
 * Author: Maciej Purski
 *
 * %LICENSE%
 */

#ifndef MODEM_PPPOS_MODEM_H_
#define MODEM_PPPOS_MODEM_H_

#include <stddef.h>

#define PPPOS_USE_CONFIG_FILE     0
#define PPPOS_USE_AUTH            1
#define PPPOS_AUTH_TYPE           PPPAUTHTYPE_CHAP
#define PPPOS_AUTH_USER           "blank"
#define PPPOS_AUTH_PASSWD         "blank"
#define PPPOS_DISCONNECT_ON_INIT  0
#define AT_CONNECT_CMD            "ATDT*99#\r\n"
#define AT_DISCONNECT_CMD         "ATH\r\n"
#define AT_INIT_CMDS_TIMEOUT_MS   3000
#define AT_CONNECT_CMD_TIMEOUT_MS 3000

#ifndef PPPOS_DEFAULT_APN
#define PPPOS_DEFAULT_APN "internet"
#endif

static const char *at_init_cmds[] = {
	"ATZ\r\n",                                           /* reset modem */
	"AT+CFUN=1\r\n",                                     /* full functionality */
	"AT^SYSCFGEX=\"030201\",3FFFFFFF,0,1,800C5,,\r\n",   /* config params: prefer LTE, All bands, roam disabled, Data only */
	"AT+CGDCONT=1,\"IP\",\"" PPPOS_DEFAULT_APN "\"\r\n", /* set APN to "internet" */
	NULL,
};

#endif
