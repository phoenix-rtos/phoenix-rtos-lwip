/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP Wi-Fi
 *
 * Copyright 2021 Phoenix Systems
 * Author: Ziemowit Leszczynski
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cy_log.h"

#include <stdbool.h>
#include <syslog.h>


static struct {
	bool init;
	CY_LOG_LEVEL_T loglevel[CYLF_MAX];
} log_common;


cy_rslt_t cy_log_init(CY_LOG_LEVEL_T level)
{
	if (level >= CY_LOG_MAX)
		level = CY_LOG_MAX - 1;

	for (unsigned int i = 0; i < CYLF_MAX; i++)
		log_common.loglevel[i] = level;

	log_common.init = true;

	return CY_RSLT_SUCCESS;
}


cy_rslt_t cy_log_shutdown(void)
{
	if (!log_common.init)
		return CY_RSLT_TYPE_ERROR;

	closelog();

	log_common.init = false;

	return CY_RSLT_SUCCESS;
}


cy_rslt_t cy_log_set_facility_level(CY_LOG_FACILITY_T facility, CY_LOG_LEVEL_T level)
{
	if (!log_common.init)
		return CY_RSLT_TYPE_ERROR;

	if (facility >= CYLF_MAX)
		facility = CYLF_DEF;

	if (level >= CY_LOG_MAX)
		level = CY_LOG_MAX - 1;

	log_common.loglevel[facility] = level;

	return CY_RSLT_SUCCESS;
}


cy_rslt_t cy_log_set_all_levels(CY_LOG_LEVEL_T level)
{
	if (!log_common.init)
		return CY_RSLT_TYPE_ERROR;

	if (level >= CY_LOG_MAX)
		level = CY_LOG_MAX - 1;

	for (unsigned int i = 0; i < CYLF_MAX; i++)
		log_common.loglevel[i] = level;

	return CY_RSLT_SUCCESS;
}


CY_LOG_LEVEL_T cy_log_get_facility_level(CY_LOG_FACILITY_T facility)
{
	if (!log_common.init)
		return CY_LOG_OFF;

	if (facility >= CYLF_MAX)
		facility = CYLF_DEF;

	return log_common.loglevel[facility];
}


static int get_priority(CY_LOG_LEVEL_T level)
{
	switch (level) {
		case CY_LOG_ERR:
			return LOG_ERR;
		case CY_LOG_WARNING:
			return LOG_WARNING;
		case CY_LOG_NOTICE:
			return LOG_NOTICE;
		case CY_LOG_INFO:
			return LOG_INFO;
		case CY_LOG_DEBUG:
			return LOG_DEBUG;
		default:
			return LOG_INFO;
	}
}


cy_rslt_t cy_log_msg(CY_LOG_FACILITY_T facility, CY_LOG_LEVEL_T level, const char *fmt, ...)
{
	va_list args;

	if (!log_common.init)
		return CY_RSLT_TYPE_ERROR;

	if (facility >= CYLF_MAX)
		facility = CYLF_DEF;

	if ((log_common.loglevel[facility] == CY_LOG_OFF) || (level > log_common.loglevel[facility]))
		return CY_RSLT_SUCCESS;

	va_start(args, fmt);
	vsyslog(get_priority(level), fmt, args);
	va_end(args);

	return CY_RSLT_SUCCESS;
}
