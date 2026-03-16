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

#define PPPOS_USE_CONFIG_FILE     0
#define PPPOS_USE_AUTH            0
#define PPPOS_DISCONNECT_ON_INIT  0
#define PPPOS_WAIT_FOR_RDY        1
#define AT_CONNECT_CMD            "ATD*99***1#\r\n"
#define AT_DISCONNECT_CMD         "ATH\r\n"
#define AT_INIT_CMDS_TIMEOUT_MS   3000
#define AT_CONNECT_CMD_TIMEOUT_MS 3000

#ifndef PPPOS_DEFAULT_APN
#define PPPOS_DEFAULT_APN "internet"
#endif

static const char *at_init_cmds[] = {
	/* TODO There should be PCIE initialization command here, but the problem is it
	will work only after reboot, so I don't know if it is good practice. For now we
	don't have to send that command because I only work on one modem and it already
	have correct mode set in non-volatile memory. */
	"ATE0\r\n",                                          /* disable command echo */
	"AT+CFUN=1\r\n",                                     /* Full RF functionality */
	"AT+CGATT=0\r\n",                                    /* detach from PDN */
	"AT+CGDCONT=1,\"IP\",\"" PPPOS_DEFAULT_APN "\"\r\n", /* set APN */
	NULL,
};

#endif
