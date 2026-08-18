/*
 * Phoenix-RTOS --- networking stack
 *
 * STM32 GPIO interface for PHY driver header file
 *
 * Copyright 2026 Phoenix Systems
 * Author: Jacek Maksymowicz
 *
 * %LICENSE%
 */
#ifndef _STM32_GPIO_H_
#define _STM32_GPIO_H_

#include <sys/msg.h>
#include <stdint.h>


#define STM32_PIN_CONFIG_INPUT  -1
#define STM32_PIN_CONFIG_OUTPUT -2

#define STM32_MULTI_PATH "/dev/multi"

/* afMode - pin's alternate mode setting or one of STM32_PIN_SETUP_* values */
int stm32_pinConfig(const oid_t *dev, int port, uint8_t pin, int afMode);


int stm32_pinSet(const oid_t *dev, int port, uint8_t pin, uint8_t state);


int stm32_pinGet(const oid_t *dev, int port, uint8_t pin, uint8_t *state);

#endif /* _STM32_GPIO_H_ */
