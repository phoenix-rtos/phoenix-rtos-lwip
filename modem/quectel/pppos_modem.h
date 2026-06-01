/*
 * Phoenix-RTOS --- networking stack
 *
 * Quectel modem definitions
 *
 * Copyright 2020 Phoenix Systems
 * Author: Daniel Sawka
 *
 * %LICENSE%
 */

#ifndef MODEM_PPPOS_MODEM_H_
#define MODEM_PPPOS_MODEM_H_

#include <stddef.h>

#define PPPOS_MODEM_USE_AUTH                  0
#define PPPOS_MODEM_DISCONNECT_ON_INIT        0
#define PPPOS_MODEM_AT_CONNECT_CMD            "AT+CGDATA=\"PPP\",1\r\n"
#define PPPOS_MODEM_AT_DISCONNECT_CMD         "ATH\r\n"
#define PPPOS_MODEM_AT_INIT_CMDS_TIMEOUT_MS   3000
#define PPPOS_MODEM_AT_CONNECT_CMD_TIMEOUT_MS 3000

static const char *ppposModem_atInitCmds[] = {
	"ATZ\r\n",                   /* reset MODEM */
	"ATE0\r\n",                  /* disable command echo */
	"AT+QSCLK=0\r\n",            /* disable automatic deep sleep */
	"AT+CGATT=0\r\n",            /* detach from PDN */
	"AT+QCFG=\"autopdn\",0\r\n", /* disable automatic PDN attach (to allow PPP) */
	"AT+CREG?\r\n",              /* check network registration (for debug) */
	"AT+COPS?\r\n",              /* check operator registration (for debug) */
	"AT+CSQ\r\n",                /* check signal quality (for debug) */
	NULL,
};

#endif
