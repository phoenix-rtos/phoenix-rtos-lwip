/*
 * Phoenix-RTOS --- networking stack
 *
 * Telit modem definitions
 *
 * Copyright 2020 Phoenix Systems
 * Author: Daniel Sawka
 *
 * %LICENSE%
 */

#ifndef MODEM_PPPOS_MODEM_H_
#define MODEM_PPPOS_MODEM_H_

#include <stddef.h>

#define PPPOS_USE_CONFIG_FILE     1
#define PPPOS_USE_AUTH            0
#define PPPOS_DISCONNECT_ON_INIT  1
#define AT_CONNECT_CMD            "AT+CGDATA=\"PPP\",1\r\n"
#define AT_DISCONNECT_CMD         "ATH\r\n"
#define AT_INIT_CMDS_TIMEOUT_MS   3000
#define AT_CONNECT_CMD_TIMEOUT_MS 3000

static const char *at_init_cmds[] = {
	"ATZ\r\n",                               /* reset MODEM */
	"ATQ0 V1 E0 S0=0 &C1 &D2 +FCLASS=0\r\n", /* setup serial/message exchange */
	"AT+WS46=29\r\n",                        /* disable LTE */
	"AT+CREG?\r\n",                          /* check network registration (for debug) */
	"AT+COPS?\r\n",                          /* check operator registration (for debug) */
	"AT+CSQ\r\n",                            /* check signal quality (for debug) */
	NULL,
};

#endif
