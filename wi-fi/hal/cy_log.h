/*
 * Copyright 2019-2021, Cypress Semiconductor Corporation (an Infineon company) or
 * an affiliate of Cypress Semiconductor Corporation.  All rights reserved.
 *
 * This software, including source code, documentation and related
 * materials ("Software") is owned by Cypress Semiconductor Corporation
 * or one of its affiliates ("Cypress") and is protected by and subject to
 * worldwide patent protection (United States and foreign),
 * United States copyright laws and international treaty provisions.
 * Therefore, you may use this Software only as provided in the license
 * agreement accompanying the software package from which you
 * obtained this Software ("EULA").
 * If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
 * non-transferable license to copy, modify, and compile the Software
 * source code solely for use in connection with Cypress's
 * integrated circuit products.  Any reproduction, modification, translation,
 * compilation, or representation of this Software except as specified
 * above is prohibited without the express written permission of Cypress.
 *
 * Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
 * reserves the right to make changes to the Software without notice. Cypress
 * does not assume any liability arising out of the application or use of the
 * Software or any product or circuit described in the Software. Cypress does
 * not authorize its products for use in any products where a malfunction or
 * failure of the Cypress product may reasonably be expected to result in
 * significant property damage, injury or death ("High Risk Product"). By
 * including Cypress's product in a High Risk Product, the manufacturer
 * of such system or application assumes all risk of such use and in doing
 * so agrees to indemnify Cypress against all liability.
 */

/**
 * @file
 * @addtogroup logging_utils
 *
 * A logging subsystem that allows run time control for the logging level.
 * Log messages are passed back to the application for output.
 * Log messages are given sequence numbers.
 * A time callback can be provided by the application for the timestamp for each output line.
 * Log messages are mutex protected across threads so that log messages do not interrupt each other.
 */
/*
 * in Main application file:
 *
 *  Log output callback function - The App decides what and how logging is to be output
 *
 *  int app_log_output_callback(CY_LOG_FACILITY_T facility, CY_LOG_LEVEL_T level, char *logmsg)
 *  {
 *      (void)facility;     // Can be used to decide to reduce output or send output to remote logging
 *      (void)level;        // Can be used to decide to reduce output, although the output has already been
 *                          // limited by the log routines
 *
 *      return printf( "%s\n", logmsg);   // print directly to console
 *  }
 *
 *
 *  Log time callback - get the current time for the log message timestamp in milliseconds
 *
 *  cy_rslt_t app_log_time(uint32_t* time)
 *  {
 *      if (time != NULL)
 *      {
 *          *time = get_time_ms(); // get system time (in milliseconds)
 *      }
 *      return CY_RSLT_SUCCESS;
 *  }
 *
 *
 *  Log initialization - default os OFF, no output from any facility
 *
 *  result = cy_log_init(CY_LOG_OFF, app_log_output_callback, app_log_time);
 *  if (result != CY_RSLT_SUCCESS)
 *  {
 *      printf("cy_log_init() FAILED %ld\n", result);
 *  }
 *
 *
 *  Example using TEST facility
 *
 *  cy_log_set_facility_level(CYLF_TEST, CY_LOG_WARNING);           // set log message level to WARNING
 *
 *  cy_log_printf("TEST message: always print.");                   // Bypass facility/level check and always print message
 *                                                                  // calls app_log_output_callback(CYLF_DEF, CY_LOG_PRINTF, logmsg)
 *
 *  cy_log_msg(CYLF_TEST, CY_LOG_ERR,     "TEST message: ERR");     // Print if CYLF_TEST level is CY_LOG_ERR or higher
 *  cy_log_msg(CYLF_TEST, CY_LOG_WARNING, "TEST message: WARNING"); // Print if CYLF_TEST level is CY_LOG_WARNING or higher
 *  cy_log_msg(CYLF_TEST, CY_LOG_NOTICE,  "TEST message: NOTICE");  // Print if CYLF_TEST level is CY_LOG_NOTICE or higher
 *
 *  cy_log_msg(CYLF_DRIVER, CY_LOG_ERR,   "DRIVER message: ERR");   // Print if CYLF_DRIVER level is CY_LOG_ERR or higher
 *
 *  OUTPUT:
 *
 *  TEST message: always print.
 *  TEST message: ERR
 *  TEST message: WARNING
 *
 *  - No other CYLF_TEST output due to level set as CY_LOG_WARNING
 *  - No CYLF_DRIVER output due to level set as CY_LOG_OFF
 */

#pragma once

#include <stdarg.h>
#include "cy_result.h"

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************
 *                      Macros
 ******************************************************/

/******************************************************
 *                    Constants
 ******************************************************/

/******************************************************
 *                   Enumerations
 ******************************************************/

/******************************************************************************/
/** \addtogroup group_logging_enums 
 * Documentation of the enums provided by logging utility.
 */
/** \{ */
/******************************************************************************/

/** Logging levels. NOTE: Default value for all facilities is passed in to init call */
typedef enum {
	CY_LOG_OFF = 0, /**< Do not print log messages */
	CY_LOG_ERR,     /**< Print log message if run-time level is <= CY_LOG_ERR       */
	CY_LOG_WARNING, /**< Print log message if run-time level is <= CY_LOG_WARNING   */
	CY_LOG_NOTICE,  /**< Print log message if run-time level is <= CY_LOG_NOTICE    */
	CY_LOG_INFO,    /**< Print log message if run-time level is <= CY_LOG_INFO      */
	CY_LOG_DEBUG,   /**< Print log message if run-time level is <= CY_LOG_DEBUG     */

	CY_LOG_MAX
} CY_LOG_LEVEL_T;

/** Log Facility type
 * Log facilities allow for separate subsystems to have different run-time log levels for output.
 *  This allows for someone working in the Driver subsystem to turn on DEBUG level without turning DEBUG
 *  level for middleware - makes for less unwanted output during debugging / testing.
 */
typedef enum {
	CYLF_DEF = 0,    /**< General log message not associated with any specific Facility */
	CYLF_RTOS,       /**< RTOS Facility */
	CYLF_GPIO,       /**< GPIO Facility */
	CYLF_SDIO,       /**< SDIO Facility */
	CYLF_MIDDLEWARE, /**< Middleware Facility */

	CYLF_MAX /**< Must be last, not an actual index */
} CY_LOG_FACILITY_T;

/** \} */

/*****************************************************************************/
/**
 *
 *  @addtogroup group_logging_func
 *
 * A logging subsystem provides a set of helper functions to manage logging in the application. 
 *
 *  @{
 */
/*****************************************************************************/
/******************************************************
 *               Function Declarations
 ******************************************************/
/** Initialize the logging subsystem.
 *
 * @param[in] level           : The initial logging level to use for all facilities.
 *
 * @return cy_rslt_t
 */
cy_rslt_t cy_log_init(CY_LOG_LEVEL_T level);

/** Shutdown the logging subsystem.
 *
 * @return cy_rslt_t
 */
cy_rslt_t cy_log_shutdown(void);

/** Set the logging level for a facility.
 *
 * @param[in] facility  : The facility for which to set the log level.
 * @param[in] level     : The new log level to use.
 *
 * @return cy_rslt_t
 */
cy_rslt_t cy_log_set_facility_level(CY_LOG_FACILITY_T facility, CY_LOG_LEVEL_T level);

/** Set the logging level for all facilities.
 *
 * @param[in] level  : The new log level to use.
 *
 * @return cy_rslt_t
 */
cy_rslt_t cy_log_set_all_levels(CY_LOG_LEVEL_T level);

/** Get the logging level for a facility.
 *
 * @param[in] facility  : The facility for which to return the log level.
 *
 * @return The current log level.
 */
CY_LOG_LEVEL_T cy_log_get_facility_level(CY_LOG_FACILITY_T facility);

/** Write a log message.
 *
 * @note The format arguments are the same as for printf.
 *
 * @param[in] facility  : The facility for the log message.
 * @param[in] level     : Log level of the message.
 * @param[in] fmt       : Format control string followed by any optional arguments.
 *
 * @return cy_rslt_t
 */
cy_rslt_t cy_log_msg(CY_LOG_FACILITY_T facility, CY_LOG_LEVEL_T level, const char *fmt, ...);

/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif
