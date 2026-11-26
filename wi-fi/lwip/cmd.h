/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP Wi-Fi device commands
 *
 * Copyright 2026 Phoenix Systems
 * Author: Jan Wisniewski
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _PH_LWIP_WIFI_CMD_H_
#define _PH_LWIP_WIFI_CMD_H_

#include <stddef.h>


typedef enum {
	CMD_ARGS_NO = 0, /* default when unset in a table */
	CMD_ARGS_REQUIRED,
	CMD_ARGS_OPTIONAL,
} cmdArgs_t;


typedef struct {
	const char *name; /* matched command */
	const char *args; /* not NUL-terminated unless the caller's data is */
	size_t argsLen;
	void *userData;
} cmdCtx_t;


typedef int (*cmdHandlerFn_t)(const cmdCtx_t *ctx);


typedef struct {
	const char *name;
	cmdHandlerFn_t handler;
	cmdArgs_t args;
} cmd_t;


/* strips surrounding whitespace, e.g. the newline added by echo */
const char *cmd_trim(const char *str, size_t *len);


/* finds the command in trimmed data and sets ctx->args/argsLen, NULL if no command matches */
const cmd_t *cmd_find(const cmd_t *cmds, size_t count, const char *data, size_t size, cmdCtx_t *ctx);


#endif /* _PH_LWIP_WIFI_CMD_H_ */
