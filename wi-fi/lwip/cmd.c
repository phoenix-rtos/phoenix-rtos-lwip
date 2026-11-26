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

#include <ctype.h>
#include <string.h>

#include "cmd.h"


const char *cmd_trim(const char *str, size_t *len)
{
	size_t sz = *len;

	while ((sz > 0U) && (isgraph((unsigned char)*str) == 0)) {
		str++;
		sz--;
	}

	while ((sz > 0U) && (isgraph((unsigned char)str[sz - 1U]) == 0)) {
		sz--;
	}

	*len = sz;

	return str;
}


const cmd_t *cmd_find(const cmd_t *cmds, size_t count, const char *data, size_t size, cmdCtx_t *ctx)
{
	for (size_t i = 0; i < count; i++) {
		const cmd_t *cmd = &cmds[i];
		size_t nameLen = strlen(cmd->name);

		if ((size < nameLen) || (strncmp(cmd->name, data, nameLen) != 0)) {
			continue;
		}

		if (size == nameLen) {
			if (cmd->args == CMD_ARGS_REQUIRED) {
				continue;
			}
		}
		else if ((data[nameLen] != ' ') || (cmd->args == CMD_ARGS_NO)) {
			continue;
		}
		else {
			/* args follow a single space, more spaces belong to the args (e.g. an SSID) */
			nameLen++;
		}

		ctx->name = cmd->name;
		ctx->args = data + nameLen;
		ctx->argsLen = size - nameLen;

		return cmd;
	}

	return NULL;
}
