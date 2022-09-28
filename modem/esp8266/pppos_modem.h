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
#define PPPOS_DISCONNECT_ON_INIT  1
#define AT_CONNECT_CMD            "AT+PPPD\r\n"
#define AT_DISCONNECT_CMD         "AT+RST\r\n"
#define AT_INIT_CMDS_TIMEOUT_MS   3000
#define AT_CONNECT_CMD_TIMEOUT_MS 3000


static const char *at_init_cmds[] = {
	"AT+PPPD=\"10.0.0.1:10.0.0.2\",1\r\n",
	"AT+CWMODE=1,1\r\n",
	"ATE0\r\n",
	NULL,
};

#endif
