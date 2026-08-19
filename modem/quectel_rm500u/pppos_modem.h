/*
 * Phoenix-RTOS --- networking stack
 *
 * Quectel RM500U-EA modem definitions
 *
 * Copyright 2026 Phoenix Systems
 * Author: Norbert Niderla
 *
 * %LICENSE%
 */

#ifndef MODEM_PPPOS_MODEM_H_
#define MODEM_PPPOS_MODEM_H_

#include <stddef.h>

#define PPPOS_MODEM_USE_AUTH                  0
#define PPPOS_MODEM_DISCONNECT_ON_INIT        0
#define PPPOS_MODEM_AT_CONNECT_CMD            "ATD*99***1#\r\n"
#define PPPOS_MODEM_AT_DISCONNECT_CMD         "ATH\r\n"
#define PPPOS_MODEM_AT_INIT_CMDS_TIMEOUT_MS   3000
#define PPPOS_MODEM_AT_CONNECT_CMD_TIMEOUT_MS 3000

static const char *const ppposModem_atInitCmds[] = {
	"ATE0\r\n",                             /* disable command echo */
	"AT+CFUN=1\r\n",                        /* Full RF functionality */
	"AT+CGATT=0\r\n",                       /* detach from PDN */
	"AT+CGDCONT=1,\"IP\",\"internet\"\r\n", /* set APN */
	"AT+CGATT=1\r\n",                       /* attach to PDN */
	NULL,
};

#endif
