/*
 * Copyright 2023, Cypress Semiconductor Corporation (an Infineon company)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** @file
 *  Broadcom WLAN USB Protocol interface
 *
 *  Implements the WHD Bus Protocol Interface for USB
 *  Provides functions for initializing, de-intitializing 802.11 device,
 *  sending/receiving raw packets etc
 *
 */

#include "cybsp.h"

#if (CYBSP_WIFI_INTERFACE_TYPE == CYBSP_USB_INTERFACE)

#include "cyabs_rtos.h"
#include "cyhal_usb.h"
#include "whd_buffer_api.h"
#include "whd_cdc_bdc.h"
#include "whd_utils.h"

#include <stdlib.h>
#include <sys/minmax.h>

#include "whd_bus_usb_protocol.h"

#define WHD_BUS_USB_RX_QUEUE_LENGTH      16
#define WHD_BUS_USB_RX_THREAD_STACK_SIZE 2048
#define WHD_BUS_USB_N_CONSECUTIVE_FAILS  10


/******************************************************
 *             Structures
 ******************************************************/
struct whd_bus_priv {
    void *usb_obj;
};

struct rdl_state_le
{
    uint32_t state;
    uint32_t bytes;
};


/* SDIO bus specific header - Software header */
typedef struct {
    uint8_t sequence;              /* Rx/Tx sequence number */
    uint8_t channel_and_flags;     /*  4 MSB Channel number, 4 LSB arbitrary flag */
    uint8_t next_length;           /* Length of next data frame, reserved for Tx */
    uint8_t header_length;         /* Data offset */
    uint8_t wireless_flow_control; /* Flow control bits, reserved for Tx */
    uint8_t bus_data_credit;       /* Maximum Sequence number allowed by firmware for Tx */
    uint8_t _reserved[2];          /* Reserved */
} __attribute__((packed)) sdpcm_sw_header_t;

/* SDPCM header definitions */
typedef struct {
    uint16_t frametag[2];
    sdpcm_sw_header_t sw_header;
} __attribute__((packed)) sdpcm_header_t;


static struct {
    uint32_t chipid;
    whd_usb_config_t config;

    struct {
        cy_queue_t queue;
        cy_semaphore_t semaphore;
        cy_thread_t thread;
        bool failed;
    } rx;
} whd_bus_usb_common;


/******************************************************
*             Static Function Declarations
******************************************************/

static whd_result_t whd_bus_usb_dl_needed(whd_driver_t whd_driver, bool *needed);
static whd_result_t whd_bus_usb_resetcfg(whd_driver_t whd_driver);
static whd_result_t whd_bus_usb_download_firmware(whd_driver_t whd_driver);
static whd_bool_t whd_bus_usb_wake_interrupt_present(whd_driver_t whd_driver);
static uint32_t whd_bus_usb_packet_available_to_read(whd_driver_t whd_driver);
static whd_result_t whd_bus_usb_start_rx(whd_driver_t whd_driver);
static whd_result_t whd_bus_usb_stop_rx(whd_driver_t whd_driver);
static whd_result_t whd_bus_usb_rx_queue_enqueue(whd_buffer_t *data);
static whd_result_t whd_bus_usb_rx_queue_dequeue(whd_buffer_t *data);
static void whd_usb_rx_thread_notify(void);

whd_result_t whd_bus_usb_send_buffer(whd_driver_t whd_driver, whd_buffer_t buffer);
whd_result_t whd_bus_usb_read_frame(whd_driver_t whd_driver, whd_buffer_t* buffer);
static whd_result_t whd_bus_usb_irq_enable(whd_driver_t whd_driver, whd_bool_t enable);
static whd_result_t whd_bus_usb_irq_register(whd_driver_t whd_driver);
static whd_result_t whd_bus_usb_reinit_stats(whd_driver_t whd_driver, whd_bool_t wake_from_firmware);
static whd_result_t whd_bus_usb_print_stats(whd_driver_t whd_driver, whd_bool_t reset_after_print);
static void whd_bus_usb_init_stats(whd_driver_t whd_driver);
static uint32_t whd_bus_usb_get_max_transfer_size(whd_driver_t whd_driver);
static whd_bool_t whd_bus_usb_use_status_report_scheme(whd_driver_t whd_driver);
static uint8_t whd_bus_usb_backplane_read_padd_size(whd_driver_t whd_driver);
static whd_result_t whd_bus_usb_ack_interrupt(whd_driver_t whd_driver, uint32_t intstatus);
static whd_result_t whd_bus_usb_poke_wlan(whd_driver_t whd_driver);
static whd_result_t whd_bus_usb_wakeup(whd_driver_t whd_driver);
static whd_result_t whd_bus_usb_sleep(whd_driver_t whd_driver);
static whd_result_t whd_bus_usb_wait_for_wlan_event(whd_driver_t whd_driver, cy_semaphore_t *transceive_semaphore);


/* ------------------------------------------------------------------------------------- */
uint32_t whd_bus_usb_attach(whd_driver_t whd_driver, whd_usb_config_t *config, cyhal_usb_t *usb_obj)
{
    struct whd_bus_info* whd_bus_info;

    whd_bus_info = (whd_bus_info_t *)malloc(sizeof(whd_bus_info_t));

    if (whd_bus_info == NULL)
    {
        WPRINT_WHD_ERROR(("Memory allocation failed for whd_bus_info in %s\n", __FUNCTION__));
        return WHD_BUFFER_UNAVAILABLE_PERMANENT;
    }
    memset(whd_bus_info, 0, sizeof(whd_bus_info_t));

    whd_driver->bus_if = whd_bus_info;

    whd_driver->bus_priv = (struct whd_bus_priv *)malloc(sizeof(struct whd_bus_priv));

    if (whd_driver->bus_priv == NULL)
    {
        WPRINT_WHD_ERROR(("Memory allocation failed for whd_bus_priv in %s\n", __FUNCTION__));
        return WHD_BUFFER_UNAVAILABLE_PERMANENT;
    }
    memset(whd_driver->bus_priv, 0, sizeof(struct whd_bus_priv));

    whd_driver->bus_priv->usb_obj = usb_obj;
    memcpy(&whd_bus_usb_common.config, config, sizeof(*config));

    whd_bus_info->whd_bus_init_fptr = whd_bus_usb_init;
    whd_bus_info->whd_bus_deinit_fptr = whd_bus_usb_deinit;

    whd_bus_info->whd_bus_send_buffer_fptr = whd_bus_usb_send_buffer;
    whd_bus_info->whd_bus_read_frame_fptr = whd_bus_usb_read_frame;

    whd_bus_info->whd_bus_packet_available_to_read_fptr = whd_bus_usb_packet_available_to_read;
    whd_bus_info->whd_bus_poke_wlan_fptr = whd_bus_usb_poke_wlan;
    whd_bus_info->whd_bus_wait_for_wlan_event_fptr = whd_bus_usb_wait_for_wlan_event;

    whd_bus_info->whd_bus_ack_interrupt_fptr = whd_bus_usb_ack_interrupt;
    whd_bus_info->whd_bus_wake_interrupt_present_fptr = whd_bus_usb_wake_interrupt_present;

    whd_bus_info->whd_bus_wakeup_fptr = whd_bus_usb_wakeup;
    whd_bus_info->whd_bus_sleep_fptr = whd_bus_usb_sleep;

    whd_bus_info->whd_bus_backplane_read_padd_size_fptr = whd_bus_usb_backplane_read_padd_size;
    whd_bus_info->whd_bus_use_status_report_scheme_fptr = whd_bus_usb_use_status_report_scheme;

    whd_bus_info->whd_bus_get_max_transfer_size_fptr = whd_bus_usb_get_max_transfer_size;

    whd_bus_info->whd_bus_init_stats_fptr = whd_bus_usb_init_stats;
    whd_bus_info->whd_bus_print_stats_fptr = whd_bus_usb_print_stats;
    whd_bus_info->whd_bus_reinit_stats_fptr = whd_bus_usb_reinit_stats;
    whd_bus_info->whd_bus_irq_register_fptr = whd_bus_usb_irq_register;
    whd_bus_info->whd_bus_irq_enable_fptr = whd_bus_usb_irq_enable;

    return WHD_SUCCESS;
}


/***************************************************************************************************
 * whd_bus_usb_detach
 **************************************************************************************************/
void whd_bus_usb_detach(whd_driver_t whd_driver)
{
    whd_bus_usb_deinit(whd_driver);
    if (whd_driver->bus_if != NULL) {
        free(whd_driver->bus_if);
        whd_driver->bus_if = NULL;
    }
    if (whd_driver->bus_priv != NULL) {
        free(whd_driver->bus_priv);
        whd_driver->bus_priv = NULL;
    }
    memset(&whd_bus_usb_common, 0, sizeof(whd_bus_usb_common));
}


static whd_result_t whd_bus_usb_wait_and_init_device(whd_driver_t whd_driver)
{
    cy_rslt_t result;

    result = cyhal_usb_wait_state(whd_bus_usb_common.config.path, true);
    if (result != CY_RSLT_SUCCESS) {
        return WHD_HAL_ERROR;
    }

    result = cyhal_usb_init(whd_driver->bus_priv->usb_obj, whd_bus_usb_common.config.path);
    return result == CY_RSLT_SUCCESS ? WHD_SUCCESS : WHD_HAL_ERROR;
}


static whd_result_t whd_bus_usb_init_internal(whd_driver_t whd_driver)
{
    bool needed;
    whd_result_t result;

    result = whd_bus_usb_wait_and_init_device(whd_driver);
    if (result != WHD_SUCCESS) {
        return result;
    }

    result = whd_bus_usb_dl_needed(whd_driver, &needed);
    if (result != WHD_SUCCESS) {
        return result;
    }
    if (needed) {
        WPRINT_WHD_DEBUG(("Download needed, downloading firmware\n"));
        result = whd_bus_usb_download_firmware(whd_driver);
        if (result != WHD_SUCCESS) {
            WPRINT_WHD_ERROR(("Failed to download firmware.\n"));
            return result;
        }

        /* re-initialize USB as it's re-enumerated */
        (void)cyhal_usb_wait_state(whd_bus_usb_common.config.path, false);
        (void)cyhal_usb_free(whd_driver->bus_priv->usb_obj);
        result = whd_bus_usb_wait_and_init_device(whd_driver);
        if (result != WHD_SUCCESS) {
            WPRINT_WHD_ERROR(("Failed to wait for device.\n"));
            return result;
        }

        /* set chip ID once again after download because device re-enumerated */
        if (whd_bus_usb_common.chipid != 0) {
            whd_chip_set_chip_id(whd_driver, whd_bus_usb_common.chipid);
            result = cyhal_usb_set_chip(whd_driver->bus_priv->usb_obj, whd_bus_usb_common.chipid);
            if (result != CY_RSLT_SUCCESS) {
                WPRINT_WHD_ERROR(("Failed to set device's chip ID.\n"));
                return result;
            }
        }
    }

    whd_bus_set_state(whd_driver, WHD_TRUE);

    return WHD_SUCCESS;
}


/***************************************************************************************************
 * whd_bus_usb_init
 **************************************************************************************************/
whd_result_t whd_bus_usb_init(whd_driver_t whd_driver)
{
    whd_result_t result;
    
    result = whd_bus_usb_init_internal(whd_driver);
    if (result != WHD_SUCCESS) {
        whd_bus_usb_deinit(whd_driver);
        return result;
    }

    result = whd_bus_usb_start_rx(whd_driver);
    if (result != WHD_SUCCESS) {
        whd_bus_usb_deinit(whd_driver);
        return result;
    }

    return WHD_SUCCESS;
}


/***************************************************************************************************
 * whd_bus_usb_deinit
 **************************************************************************************************/
whd_result_t whd_bus_usb_deinit(whd_driver_t whd_driver)
{
    if (whd_bus_is_up(whd_driver) == WHD_FALSE) {
        return WHD_SUCCESS;
    }
    whd_bus_set_state(whd_driver, WHD_FALSE);
    cy_rslt_t cy_result = cyhal_usb_free(whd_driver->bus_priv->usb_obj);
    whd_result_t whd_result = whd_bus_usb_stop_rx(whd_driver);
    return ((whd_result == WHD_SUCCESS) && (cy_result == CY_RSLT_SUCCESS)) ? WHD_SUCCESS : WHD_HAL_ERROR;
}


static bool whd_bus_rx_queue_is_full(void)
{
    size_t spaces;
    (void)cy_rtos_queue_space(&whd_bus_usb_common.rx.queue, &spaces);
    return spaces == 0;
}


static inline whd_result_t whd_bus_usb_handle_rx(whd_driver_t whd_driver, whd_buffer_t buffer)
{
    cy_rslt_t result;
    uint8_t *data = whd_buffer_get_current_piece_data_pointer(whd_driver, buffer);
    size_t size = WHD_USB_MAX_RECEIVE_BUF_SIZE;

    result = cyhal_usb_bulk_receive(whd_driver->bus_priv->usb_obj, data, &size);
    if (result == CY_RSLT_SUCCESS) {
        /* Set final size of received packet */
        whd_buffer_set_size(whd_driver, buffer, size);
        (void)whd_bus_usb_rx_queue_enqueue(&buffer);
    }
    else {
        return WHD_HAL_ERROR;
    }

    return WHD_SUCCESS;
}


static void whd_bus_usb_rx_thread(cy_thread_arg_t arg)
{
    whd_driver_t whd_driver = arg;
    whd_buffer_t buffer = NULL;
    int consecutive_fails_cnt = 0;

    WPRINT_WHD_DEBUG(("whd_bus_usb_rx_thread started\n"));

    for (;;) {
        if (!(whd_bus_is_up(whd_driver) == WHD_TRUE)) {
            break;
        }

        if (!whd_bus_rx_queue_is_full()) {
            if (whd_host_buffer_get(whd_driver, &buffer, WHD_NETWORK_RX, WHD_USB_MAX_RECEIVE_BUF_SIZE, CY_RTOS_NEVER_TIMEOUT) != WHD_SUCCESS) {
                WPRINT_WHD_ERROR(("whd_host_buffer_get failed\n"));
                cy_rtos_delay_milliseconds(10);
                continue;
            }

            if (whd_bus_usb_handle_rx(whd_driver, buffer) != WHD_SUCCESS) {
                whd_buffer_release(whd_driver, buffer, WHD_NETWORK_RX);
                consecutive_fails_cnt++;
                if (consecutive_fails_cnt > WHD_BUS_USB_N_CONSECUTIVE_FAILS) {
                    WPRINT_WHD_ERROR(("%s: handle RX failed\n", __FUNCTION__));
                    whd_bus_usb_common.rx.failed = true;
                    whd_thread_notify(whd_driver);
                    break;
                }
                cy_rtos_delay_milliseconds(10);
            }
            else {
                consecutive_fails_cnt = 0;
            }
        }
        else {
            WPRINT_WHD_INFO(("whd queue is full, going to sleep\n"));
            whd_thread_notify(whd_driver);
            cy_rtos_get_semaphore(&whd_bus_usb_common.rx.semaphore, CY_RTOS_NEVER_TIMEOUT, false /* ignored */);
        }

        whd_thread_notify(whd_driver);
    }

    cy_rtos_exit_thread();
}


static whd_result_t whd_bus_usb_start_rx(whd_driver_t whd_driver)
{
    cy_rslt_t result;

    result = cy_rtos_init_semaphore(&whd_bus_usb_common.rx.semaphore, 1, 0);
    if (result != CY_RSLT_SUCCESS) {
        WPRINT_WHD_ERROR(("USB Bus: failed to init semaphore\n"));
        return WHD_RTOS_ERROR;
    }

    result = cy_rtos_queue_init(&whd_bus_usb_common.rx.queue, WHD_BUS_USB_RX_QUEUE_LENGTH, sizeof(whd_buffer_t));
    if (result != CY_RSLT_SUCCESS) {
        WPRINT_WHD_ERROR(("USB Bus: failed to init queue\n"));
        return WHD_RTOS_ERROR;
    }

    result = cy_rtos_create_thread(&whd_bus_usb_common.rx.thread, whd_bus_usb_rx_thread, "whd_bus_usb_rx_thread",
        NULL, WHD_BUS_USB_RX_THREAD_STACK_SIZE, max(whd_driver->thread_info.thread_priority - 1, 0), whd_driver);
    if (result != CY_RSLT_SUCCESS) {
        WPRINT_WHD_ERROR(("USB Bus: failed to create RX thread\n"));
        return WHD_RTOS_ERROR;
    }

    return WHD_SUCCESS;
}


static whd_result_t whd_bus_usb_stop_rx(whd_driver_t whd_driver)
{
    cy_rslt_t result = CY_RSLT_SUCCESS;
    whd_usb_rx_thread_notify();
    whd_thread_notify(whd_driver);
    result |= cy_rtos_join_thread(&whd_bus_usb_common.rx.thread);
    result |= cy_rtos_queue_deinit(&whd_bus_usb_common.rx.queue);
    result |= cy_rtos_deinit_semaphore(&whd_bus_usb_common.rx.semaphore);
    return (result == CY_RSLT_SUCCESS) ? WHD_SUCCESS : WHD_RTOS_ERROR;
}


/***************************************************************************************************
 * whd_bus_usb_dl_needed
 **************************************************************************************************/
static whd_result_t whd_bus_usb_dl_needed(whd_driver_t whd_driver, bool *needed)
{
    cy_rslt_t result;
    struct bootrom_id_le id;

    if (whd_driver == NULL)
    {
        return 1;
    }

    /* Check if firmware is already downloaded  by querying runtime ID */
    id.chip = 0xDEAD;

    (void)whd_bus_usb_dl_cmd(whd_driver, WHD_USB_DL_GETVER, &id, sizeof(id));

    WPRINT_WHD_INFO(("Chip %x rev 0x%x\n", id.chip, id.chiprev));

    if (id.chip == WHD_USB_POSTBOOT_ID)
    {
        if (whd_bus_usb_common.chipid != 0) {
            result = cyhal_usb_set_chip(whd_driver->bus_priv->usb_obj, whd_bus_usb_common.chipid);
            if (result != CY_RSLT_SUCCESS) {
                return result;
            }
        }
        else {
            result = cyhal_usb_get_chip(whd_driver->bus_priv->usb_obj, &whd_bus_usb_common.chipid);
            if (result != CY_RSLT_SUCCESS) {
                return result;
            }
        }
        whd_chip_set_chip_id(whd_driver, whd_bus_usb_common.chipid);
        WPRINT_WHD_INFO(("Firmware already downloaded\n"));
        whd_bus_usb_dl_cmd(whd_driver, WHD_USB_DL_RESETCFG, &id, sizeof(id));
        *needed = false;
    }
    else {
        whd_bus_usb_common.chipid = id.chip;
        whd_chip_set_chip_id(whd_driver, id.chip);
        result = cyhal_usb_set_chip(whd_driver->bus_priv->usb_obj, whd_bus_usb_common.chipid);
        if (result != CY_RSLT_SUCCESS) {
            return result;
        }
        *needed = true;
    }

    return WHD_SUCCESS;
}


/***************************************************************************************************
 * whd_bus_usb_resetcfg
 **************************************************************************************************/
static whd_result_t whd_bus_usb_resetcfg(whd_driver_t whd_driver)
{
    whd_result_t result;
    struct bootrom_id_le id;
    uint32_t loop_cnt = 0;

    do
    {
        cy_rtos_delay_milliseconds(WHD_USB_RESET_GETVER_SPINWAIT);
        loop_cnt++;

        /* Check if after firmware download we get runtime ID */
        id.chip = 0xDEAD;
        result = whd_bus_usb_dl_cmd(whd_driver, WHD_USB_DL_GETVER, &id, sizeof(id));
        if (result != WHD_SUCCESS)
        {
            return result;
        }

        if (id.chip == WHD_USB_POSTBOOT_ID)
        {
            break;
        }
    } while (loop_cnt < WHD_USB_RESET_GETVER_LOOP_CNT);

    if (id.chip == WHD_USB_POSTBOOT_ID) {
        (void)whd_bus_usb_dl_cmd(whd_driver, WHD_USB_DL_RESETCFG, &id, sizeof(id));
        cy_rtos_delay_milliseconds(1000);
        return WHD_SUCCESS;
    }
    else {
        WPRINT_WHD_ERROR(("%s: Cannot talk to Dongle. Firmware is not UP, %u ms\n", __FUNCTION__, WHD_USB_RESET_GETVER_SPINWAIT * loop_cnt));
        return WHD_HAL_ERROR;
    }
}


/***************************************************************************************************
 * whd_bus_usb_download_firmware
 **************************************************************************************************/
static whd_result_t whd_bus_usb_download_firmware(whd_driver_t whd_driver)
{
    whd_result_t result;

    uint32_t image_size;
    uint32_t size;
    uint32_t sent = 0;
    static uint8_t buff[WHD_USB_TRX_RDL_CHUNK];

    struct rdl_state_le state;

    WPRINT_WHD_INFO(("\n\rStart FW download\n\r"));

    result = whd_resource_size(whd_driver, WHD_RESOURCE_WLAN_FIRMWARE, &image_size);
    if (result != WHD_SUCCESS)
    {
        WPRINT_WHD_ERROR(("Fatal error: download_resource doesn't exist, %s failed at line %d \n",
                          __func__, __LINE__));
        return result;
    }

    if (image_size <= 0)
    {
        WPRINT_WHD_ERROR(("Fatal error: download_resource can't load with invalid size,"
                          "%s failed at line %d \n", __func__, __LINE__));
        return WHD_BADARG;
    }

    /* Prepare USB boot loader for runtime image and check we are in the
     * Waiting state */
    result = whd_bus_usb_dl_cmd(whd_driver, WHD_USB_DL_START, &state, sizeof(state));
    if ((result != WHD_SUCCESS) || (state.state != WHD_USB_DL_WAITING))
    {
        WPRINT_WHD_ERROR(("%s: Failed to DL_START\n", __FUNCTION__));
        return (result != WHD_SUCCESS) ? result : state.state;
    }

    /* Download firmware */
    while (state.bytes != image_size)
    {
        /* Wait until the usb device reports it received all
         * the bytes we sent */
        if ((state.bytes == sent) && (state.bytes != image_size))
        {
            #if 0
            if ((image_size - sent) < WHD_USB_TRX_RDL_CHUNK)
            {
                size = image_size - sent;
            }
            else
            {
                size = WHD_USB_TRX_RDL_CHUNK;
            }
            #endif

            /* Read resource */
            CHECK_RETURN(whd_resource_read(whd_driver, WHD_RESOURCE_WLAN_FIRMWARE,
                                           /* offset */ state.bytes,
                                           /* size   */ WHD_USB_TRX_RDL_CHUNK,
                                           /* size   */ &size,
                                           /* buffer */ buff));

            /* Simply avoid having to send a ZLP by ensuring we never have an even multiple of 64 */
            if (size % 64 == 0) {
                size -= 4;
            }

            /* Send data by USB Bulk */
            result = whd_bus_usb_bulk_send(whd_driver, (uint8_t*)buff, size);
            if (result != WHD_SUCCESS)
            {
                WPRINT_WHD_ERROR(("%s: Failed to write firmware image\n", __FUNCTION__));
                return result;
            }

            sent += size;
        }

        /* Read the status and restart if an error is reported */
        result = whd_bus_usb_dl_cmd(whd_driver, WHD_USB_DL_GETSTATE, &state, sizeof(state));
        if (result != WHD_SUCCESS) {
            WPRINT_WHD_ERROR(("%s: DL_GETSTATE Failed\n", __FUNCTION__));
            return result;
        }

        if ((state.state == WHD_USB_DL_BAD_HDR) || (state.state == WHD_USB_DL_BAD_CRC)) {
            WPRINT_WHD_ERROR(("%s: Bad Hdr or Bad CRC state %u\n\n", __FUNCTION__, state.state));
            return state.state;
        }
    }
    WPRINT_WHD_INFO(("FW download complete, wrote %u bytes\n\r", state.bytes));

    /* Start the image */
    WPRINT_WHD_INFO(("\n\rStart the FW image \n\r"));
    if (state.state == WHD_USB_DL_RUNNABLE) {
        whd_bus_usb_dl_cmd(whd_driver, CYHAL_USB_DL_CMD_GO, NULL, 0);
        /* error ignored as is done in the original file */
        (void)whd_bus_usb_resetcfg(whd_driver);
    }
    else {
        WPRINT_WHD_ERROR(("%s: Dongle not runnable\n", __FUNCTION__));
        return WHD_HAL_ERROR;
    }

    return WHD_SUCCESS;
}


/***************************************************************************************************
 * whd_bus_usb_wake_interrupt_present
 **************************************************************************************************/
static whd_bool_t whd_bus_usb_wake_interrupt_present(whd_driver_t whd_driver)
{
    return WHD_SUCCESS;
}


/***************************************************************************************************
 * whd_bus_usb_packet_available_to_read
 **************************************************************************************************/
static uint32_t whd_bus_usb_packet_available_to_read(whd_driver_t whd_driver)
{
    if (whd_bus_usb_common.rx.failed) {
        return WHD_BUS_FAIL;
    }

    size_t count;
    (void)cy_rtos_queue_count(&whd_bus_usb_common.rx.queue, &count);
    return count;
}


/***************************************************************************************************
 * whd_bus_usb_send_buffer
 **************************************************************************************************/
whd_result_t whd_bus_usb_send_buffer(whd_driver_t whd_driver, whd_buffer_t buffer)
{
    whd_result_t status = WHD_SUCCESS;

    uint8_t *data = (uint8_t *)((whd_transfer_bytes_packet_t *)(whd_buffer_get_current_piece_data_pointer(whd_driver, buffer) + sizeof(whd_buffer_t)))->data;
    uint16_t size = (uint16_t)(whd_buffer_get_current_piece_size(whd_driver, buffer) - sizeof(whd_buffer_t));

    /* The packet to sent has sdpcm header, so cast to sdpcm_header_t
     * to check packet type */
    sdpcm_header_t* sdpcm_header = (sdpcm_header_t*)data;
    uint32_t sdpcm_header_size = sdpcm_header->sw_header.header_length;

    /* Check the SDPCM channel to decide what to do with packet. */
    switch (sdpcm_header->sw_header.channel_and_flags & 0x0f)
    {
        case DATA_HEADER:
        {
            /* We need to send only BDC header + data, so find offset without sdpcm_header_t */
            bdc_header_t* bdc_header = (bdc_header_t*)(data + sdpcm_header_size);
            uint32_t bdc_size = size - sdpcm_header_size;

            // WPRINT_WHD_DEBUG(("BULK: sending packet of size %u:\n", bdc_size - 4));

            status = whd_bus_usb_bulk_send(whd_driver, bdc_header, bdc_size - 4 /* TODO: add define for -4 */);
            break;
        }

        case CONTROL_HEADER:  /* Sent IOCTL/IOVAR packet (CDC packet) */
        {
            whd_buffer_t rec_buffer = NULL;

            /* We need to send only CDC header + data, so find offset without sdpcm_header_t */
            cdc_header_t* cdc_header = (cdc_header_t*)(data + sdpcm_header_size);
            uint32_t cdc_size = size - sdpcm_header_size;

            /* Send control request */
            CHECK_RETURN(whd_bus_usb_send_ctrl(whd_driver, cdc_header, &cdc_size));

            /* Receive control response */
            CHECK_RETURN(whd_bus_usb_receive_ctrl_buffer(whd_driver, &rec_buffer));

            if (rec_buffer != NULL) {
                (void)whd_buffer_set_size(whd_driver, rec_buffer, cdc_size - 4);
            }

            /* Process CDC data... */
            whd_process_cdc(whd_driver, rec_buffer);
            break;
        }

        default:
            whd_minor_assert("whd_bus_usb_send_buffer: SDPCM packet of unknown channel received - dropping packet", 0 != 0);
            break;
    }

    whd_buffer_release(whd_driver, buffer, WHD_NETWORK_TX);

    return status;
}


/***************************************************************************************************
 * whd_bus_usb_read_frame
 **************************************************************************************************/
whd_result_t whd_bus_usb_read_frame(whd_driver_t whd_driver, whd_buffer_t* buffer)
{
    /* Ensure the wlan backplane bus is up */
    CHECK_RETURN(whd_ensure_wlan_bus_is_up(whd_driver));

    /* Check if we have something in rx_queue */
    if (whd_bus_usb_packet_available_to_read(whd_driver) != 0) {
        /* Take queue data */
        return whd_bus_usb_rx_queue_dequeue(buffer);
    }

    return 1;
}


whd_result_t whd_bus_usb_dl_cmd(whd_driver_t whd_driver, uint8_t cmd, void *buffer, uint32_t buflen)
{
    cy_rslt_t result = cyhal_usb_dl_cmd(whd_driver->bus_priv->usb_obj, cmd, buffer, buflen);
    return (result == CY_RSLT_SUCCESS) ? WHD_SUCCESS : WHD_HAL_ERROR;
}


whd_result_t whd_bus_usb_bulk_send(whd_driver_t whd_driver, void *buffer, int len)
{
    size_t buflen = len;
    cy_rslt_t result = cyhal_usb_bulk_send(whd_driver->bus_priv->usb_obj, buffer, &buflen);
    return (result == CY_RSLT_SUCCESS) ? WHD_SUCCESS : WHD_HAL_ERROR;
}


whd_result_t whd_bus_usb_bulk_receive(whd_driver_t whd_driver, void *buffer, int len)
{
    size_t buflen = len;
    cy_rslt_t result = cyhal_usb_bulk_receive(whd_driver->bus_priv->usb_obj, buffer, &buflen);
    return (result == CY_RSLT_SUCCESS) ? WHD_SUCCESS : WHD_HAL_ERROR;
}


whd_result_t whd_bus_usb_send_ctrl(whd_driver_t whd_driver, void *buffer, uint32_t *len)
{
    size_t buflen = *len;
    cy_rslt_t result = cyhal_usb_ctrl_send(whd_driver->bus_priv->usb_obj, buffer, &buflen);
    *len = buflen;
    return (result == CY_RSLT_SUCCESS) ? WHD_SUCCESS : WHD_HAL_ERROR;
}


whd_result_t whd_bus_usb_receive_ctrl_buffer(whd_driver_t whd_driver, whd_buffer_t *buffer)
{
    if (whd_host_buffer_get(whd_driver, buffer, WHD_NETWORK_RX,
                (unsigned short)(WHD_USB_MAX_RECEIVE_BUF_SIZE + (uint16_t)sizeof(whd_buffer_header_t)),
                (whd_sdpcm_has_tx_packet(whd_driver) ? 0 : WHD_RX_BUF_TIMEOUT)) != WHD_SUCCESS) {
        return WHD_BUFFER_ALLOC_FAIL;
    }

    void *data = whd_buffer_get_current_piece_data_pointer(whd_driver, *buffer);
    size_t buflen = WHD_USB_MAX_RECEIVE_BUF_SIZE;
    cy_rslt_t result = cyhal_usb_ctrl_receive(whd_driver->bus_priv->usb_obj, data, &buflen);

    return (result == CY_RSLT_SUCCESS) ? WHD_SUCCESS : WHD_HAL_ERROR;
}


/* Adds an element to the end of the queue  */
static whd_result_t whd_bus_usb_rx_queue_enqueue(whd_buffer_t *data)
{
    cy_rslt_t result = cy_rtos_queue_put(&whd_bus_usb_common.rx.queue, data);
    return (result == CY_RSLT_SUCCESS) ? WHD_SUCCESS : WHD_QUEUE_ERROR;
}


/* Removes an element from the front of the queue */
static whd_result_t whd_bus_usb_rx_queue_dequeue(whd_buffer_t *data)
{
    cy_rslt_t result = cy_rtos_queue_get(&whd_bus_usb_common.rx.queue, data);
    return (result == CY_RSLT_SUCCESS) ? WHD_SUCCESS : WHD_QUEUE_ERROR;
}


/***************************************************************************************************
 * whd_bus_usb_irq_enable
 **************************************************************************************************/
static whd_result_t whd_bus_usb_irq_enable(whd_driver_t whd_driver, whd_bool_t enable)
{
    return WHD_SUCCESS;
}


/***************************************************************************************************
 * whd_bus_usb_irq_register
 **************************************************************************************************/
static whd_result_t whd_bus_usb_irq_register(whd_driver_t whd_driver)
{
    return WHD_SUCCESS;
}


/***************************************************************************************************
 * whd_bus_usb_reinit_stats
 **************************************************************************************************/
static whd_result_t whd_bus_usb_reinit_stats(whd_driver_t whd_driver, whd_bool_t wake_from_firmware)
{
    return WHD_SUCCESS;
}


/***************************************************************************************************
 * whd_bus_usb_print_stats
 **************************************************************************************************/
static whd_result_t whd_bus_usb_print_stats(whd_driver_t whd_driver, whd_bool_t reset_after_print)
{
    return WHD_SUCCESS;
}


/***************************************************************************************************
 * whd_bus_usb_init_stats
 **************************************************************************************************/
static void whd_bus_usb_init_stats(whd_driver_t whd_driver)
{
}


/***************************************************************************************************
 * whd_bus_usb_get_max_transfer_size
 **************************************************************************************************/
static uint32_t whd_bus_usb_get_max_transfer_size(whd_driver_t whd_driver)
{
    return WHD_USB_MAX_BULK_TRANSFER_SIZE;
}


/***************************************************************************************************
 * whd_bus_usb_use_status_report_scheme
 **************************************************************************************************/
static whd_bool_t whd_bus_usb_use_status_report_scheme(whd_driver_t whd_driver)
{
    return true;
}


/***************************************************************************************************
 * whd_bus_usb_backplane_read_padd_size
 **************************************************************************************************/
static uint8_t whd_bus_usb_backplane_read_padd_size(whd_driver_t whd_driver)
{
    return 0;
}


/***************************************************************************************************
 * whd_bus_usb_ack_interrupt
 **************************************************************************************************/
static whd_result_t whd_bus_usb_ack_interrupt(whd_driver_t whd_driver, uint32_t intstatus)
{
    return WHD_SUCCESS;
}


/***************************************************************************************************
 * whd_bus_usb_poke_wlan
 **************************************************************************************************/
static whd_result_t whd_bus_usb_poke_wlan(whd_driver_t whd_driver)
{
    return WHD_SUCCESS;
}


/***************************************************************************************************
 * whd_bus_usb_wakeup
 **************************************************************************************************/
static whd_result_t whd_bus_usb_wakeup(whd_driver_t whd_driver)
{
    return WHD_SUCCESS;
}


/***************************************************************************************************
 * whd_bus_usb_sleep
 **************************************************************************************************/
static whd_result_t whd_bus_usb_sleep(whd_driver_t whd_driver)
{
    return WHD_SUCCESS;
}


/***************************************************************************************************
 * whd_usb_rx_thread_notify
 **************************************************************************************************/
void whd_usb_rx_thread_notify(void)
{
    (void)cy_rtos_set_semaphore(&whd_bus_usb_common.rx.semaphore, false /* ignored */);
}


/***************************************************************************************************
 * whd_bus_usb_wait_for_wlan_event
 **************************************************************************************************/
static whd_result_t whd_bus_usb_wait_for_wlan_event(whd_driver_t whd_driver, cy_semaphore_t *transceive_semaphore)
{
    cy_rslt_t result;

    whd_usb_rx_thread_notify();

    if (whd_bus_usb_packet_available_to_read(whd_driver) != 0) {
        return WHD_SUCCESS;
    }

    result = cy_rtos_get_semaphore(transceive_semaphore, CY_RTOS_NEVER_TIMEOUT, WHD_FALSE);
    return (result == CY_RSLT_SUCCESS) ? WHD_SUCCESS : WHD_HAL_ERROR;
}


#endif /* (CYBSP_WIFI_INTERFACE_TYPE == CYBSP_USB_INTERFACE) */
