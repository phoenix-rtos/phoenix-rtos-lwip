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

#include "cyhal_gpio.h"
#include "cyhal_utils.h"
#include "cyabs_rtos.h"
#include "cy_log.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <board_config.h>


#ifndef CONFIG_WL_PWR_ON_PORT
#define CONFIG_WL_PWR_ON_PORT 3
#endif

#ifndef CONFIG_WL_PWR_ON_PIN
#define CONFIG_WL_PWR_ON_PIN 9
#endif

#ifndef CONFIG_WL_PWR_ON_MUX_PAD
#define CONFIG_WL_PWR_ON_MUX_PAD mux_lcd_d4
#endif

#ifndef CONFIG_WL_PWR_ON_PAD
#define CONFIG_WL_PWR_ON_PAD pad_lcd_d4
#endif

#ifndef CONFIG_WL_REG_ON_PORT
#define CONFIG_WL_REG_ON_PORT 4
#endif

#ifndef CONFIG_WL_REG_ON_PIN
#define CONFIG_WL_REG_ON_PIN 26
#endif

#ifndef CONFIG_WL_REG_ON_MUX_PAD
#define CONFIG_WL_REG_ON_MUX_PAD mux_csi_d5
#endif

#ifndef CONFIG_WL_REG_ON_PAD
#define CONFIG_WL_REG_ON_PAD pad_csi_d5
#endif


static int gpio_set_dir(int gpio, unsigned int pin, unsigned int dir)
{
	char buf[32];
	int fd;
	ssize_t ret;
	uint32_t data[2];

	if (gpio < 0) {
		/* Pin not present in current configuration, presumably we don't need to manipulate it. */
		return 0;
	}

	snprintf(buf, sizeof(buf), "/dev/gpio%d/dir", gpio);
	if ((fd = open(buf, O_WRONLY)) < 0)
		return -1;

	data[0] = dir << pin;
	data[1] = 1 << pin;

	ret = write(fd, data, sizeof(data));

	close(fd);

	if (ret != sizeof(data))
		return -1;

	return 0;
}


static int gpio_set_val(int gpio, unsigned int pin, unsigned int val)
{
	char buf[32];
	int fd;
	ssize_t ret;
	uint32_t data[2];

	if (gpio < 0) {
		/* Pin not present in current configuration, presumably we don't need to manipulate it. */
		return 0;
	}

	snprintf(buf, sizeof(buf), "/dev/gpio%d/port", gpio);
	if ((fd = open(buf, O_WRONLY)) < 0)
		return -1;

	data[0] = val << pin;
	data[1] = 1 << pin;

	ret = write(fd, data, sizeof(data));

	close(fd);

	if (ret != sizeof(data))
		return -1;

	return 0;
}


/* NOTE: pin, direction, drvMode, initVal are ignored - pin configuration is hardcoded */
cy_rslt_t cyhal_gpio_init(cyhal_gpio_t pin, cyhal_gpio_direction_t direction, cyhal_gpio_drive_mode_t drvMode,
		bool initVal)
{
	cy_log_msg(CYLF_GPIO, CY_LOG_DEBUG, "cyhal_gpio_init\n");

	if (CONFIG_WL_PWR_ON_PORT >= 0) {
		/* configure and set WL_POWER_ON pin to 0 */
		if (gpio_set_dir(CONFIG_WL_PWR_ON_PORT, CONFIG_WL_PWR_ON_PIN, 1) < 0) {
			cy_log_msg(CYLF_GPIO, CY_LOG_ERR, "can't set WL_PWR_ON pin direction\n");
			return CYHAL_GPIO_RSLT_ERR_BAD_PARAM;
		}
		if (gpio_set_val(CONFIG_WL_PWR_ON_PORT, CONFIG_WL_PWR_ON_PIN, 0) < 0) {
			cy_log_msg(CYLF_GPIO, CY_LOG_ERR, "can't set WL_PWR_ON pin value\n");
			return CYHAL_GPIO_RSLT_ERR_BAD_PARAM;
		}
		if (cyhal_utils_set_iomux(PCTL(CONFIG_WL_PWR_ON_MUX_PAD), 5) < 0) {
			cy_log_msg(CYLF_GPIO, CY_LOG_ERR, "can't set WL_PWR_ON pin iomux\n");
			return CYHAL_GPIO_RSLT_ERR_BAD_PARAM;
		}
	}

	if (CONFIG_WL_REG_ON_PORT >= 0) {
		/* configure and set WL_REG_ON pin to 0 */
		if (gpio_set_dir(CONFIG_WL_REG_ON_PORT, CONFIG_WL_REG_ON_PIN, 1) < 0) {
			cy_log_msg(CYLF_GPIO, CY_LOG_ERR, "can't set WL_REG_ON pin direction\n");
			return CYHAL_GPIO_RSLT_ERR_BAD_PARAM;
		}
		if (gpio_set_val(CONFIG_WL_REG_ON_PORT, CONFIG_WL_REG_ON_PIN, 0) < 0) {
			cy_log_msg(CYLF_GPIO, CY_LOG_ERR, "can't set WL_REG_ON pin value\n");
			return CYHAL_GPIO_RSLT_ERR_BAD_PARAM;
		}
		if (cyhal_utils_set_iomux(PCTL(CONFIG_WL_REG_ON_MUX_PAD), 5) < 0) {
			cy_log_msg(CYLF_GPIO, CY_LOG_ERR, "can't configure WL_REG_ON pin iomux\n");
			return CYHAL_GPIO_RSLT_ERR_BAD_PARAM;
		}
		if (cyhal_utils_set_iopad(PCTL(CONFIG_WL_REG_ON_PAD), 0, 2, 1, 1, 0, 0, 1, 0) < 0) { /* 100K Ohm Pull up */
			cy_log_msg(CYLF_GPIO, CY_LOG_ERR, "can't configure WL_REG_ON pin iopad\n");
			return CYHAL_GPIO_RSLT_ERR_BAD_PARAM;
		}
	}

	usleep(10000);

	/* set WL_POWER_ON pin to 1 */
	if (gpio_set_val(CONFIG_WL_PWR_ON_PORT, CONFIG_WL_PWR_ON_PIN, 1) < 0) {
		cy_log_msg(CYLF_GPIO, CY_LOG_ERR, "can't set WL_PWR_ON pin value\n");
		return CYHAL_GPIO_RSLT_ERR_BAD_PARAM;
	}

	return CY_RSLT_SUCCESS;
}


/* NOTE: pin is ignored - pin configuration is hardcoded */
void cyhal_gpio_free(cyhal_gpio_t pin)
{
	cy_log_msg(CYLF_GPIO, CY_LOG_DEBUG, "cyhal_gpio_free\n");

	/* set WL_REG_ON pin to 0 */
	if (gpio_set_val(CONFIG_WL_REG_ON_PORT, CONFIG_WL_REG_ON_PIN, 0) < 0) {
		cy_log_msg(CYLF_GPIO, CY_LOG_ERR, "can't set WL_REG_ON pin value\n");
	}

	/* set WL_POWER_ON pin to 0 */
	if (gpio_set_val(CONFIG_WL_PWR_ON_PORT, CONFIG_WL_PWR_ON_PIN, 0) < 0) {
		cy_log_msg(CYLF_GPIO, CY_LOG_ERR, "can't set WL_PWR_ON pin value\n");
	}
}


/* NOTE: pin is ignored - pin configuration is hardcoded */
void cyhal_gpio_write(cyhal_gpio_t pin, bool value)
{
	cy_log_msg(CYLF_GPIO, CY_LOG_DEBUG, "cyhal_gpio_write (%d)\n", value);

	if (gpio_set_val(CONFIG_WL_REG_ON_PORT, CONFIG_WL_REG_ON_PIN, value ? 1 : 0) < 0) {
		cy_log_msg(CYLF_GPIO, CY_LOG_ERR, "can't set WL_REG_ON pin value\n");
	}
}


/* NOTE: currently not used */
void cyhal_gpio_register_irq(cyhal_gpio_t pin, uint8_t intrPriority, cyhal_gpio_irq_handler_t handler,
		void *handler_arg)
{
	cy_log_msg(CYLF_GPIO, CY_LOG_ERR, "cyhal_gpio_register_irq - not implemented!\n");
}


/* NOTE: currently not used */
void cyhal_gpio_irq_enable(cyhal_gpio_t pin, cyhal_gpio_irq_event_t event, bool enable)
{
	cy_log_msg(CYLF_GPIO, CY_LOG_ERR, "cyhal_gpio_irq_enable - not implemented!\n");
}
