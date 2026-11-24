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
#include "whd_utils.h"

#if (CYBSP_WIFI_INTERFACE_TYPE == CYBSP_USB_INTERFACE)
#include "whd_bus_usb_protocol.h"

#include "cyabs_rtos.h"
#include "cyhal_usb.h"

#define CY_USB_VENDOR_ID_CYPRESS 0x04b4
#define CY_USB_4373_DEVICE_ID    0xbd29 /* CYW4373 device */
#define BRCM_USB_BCMFW_DEVICE_ID 0x0bdc /* Special entry for device with firmware loaded and running */

#define WHD_USB_RX_QUEUE_SIZE (8)


/******************************************************
*             Structures
******************************************************/


/* Structures for backplane & jtag accesses */
typedef struct
{
    uint32_t        cmd;        /* tag to identify the cmd */
    uint32_t        addr;       /* backplane address for write */
    uint32_t        len;        /* length of data: 1, 2, 4 bytes */
    uint32_t        data;       /* data to write */
} whd_bus_usb_hwacc_t;

struct whd_bus_priv
{
    cyhal_usb_t *usb_obj;
    cy_queue_t queue;
    cy_semaphore_t init_sem;
};

struct rdl_state_le
{
    uint32_t state;
    uint32_t bytes;
};

#pragma pack(1)

/* SDIO bus specific header - Software header */
typedef struct
{
    uint8_t sequence;               /* Rx/Tx sequence number */
    uint8_t channel_and_flags;      /*  4 MSB Channel number, 4 LSB arbitrary flag */
    uint8_t next_length;            /* Length of next data frame, reserved for Tx */
    uint8_t header_length;          /* Data offset */
    uint8_t wireless_flow_control;  /* Flow control bits, reserved for Tx */
    uint8_t bus_data_credit;        /* Maximum Sequence number allowed by firmware for Tx */
    uint8_t _reserved[2];           /* Reserved */
} sdpcm_sw_header_t;

/* SDPCM header definitions */
typedef struct
{
    uint16_t frametag[2];
    sdpcm_sw_header_t sw_header;
} sdpcm_header_t;

#pragma pack()


static const cyhal_usb_devinfo_t whd_bus_usb_device_filters[] = {
	/*
	 * Sterling LWB5+ USB Dongle
	 * Enumerates as Remote Download for the host to download firmware onto it.
	 * After downloading the firmware, it enumerates as the 802.11 device.
	 */
	/* Remote Download Wireless Adapter */
	{ .vid = CY_USB_VENDOR_ID_CYPRESS, .pid = CY_USB_4373_DEVICE_ID },
	/* Cypress USB 802.11 Wireless Adapter */
	{ .vid = CY_USB_VENDOR_ID_CYPRESS, .pid = BRCM_USB_BCMFW_DEVICE_ID },
};


/******************************************************
*             Static Function Declarations
******************************************************/

static bool whd_bus_usb_dl_needed(whd_driver_t whd_driver);
static whd_result_t whd_bus_usb_resetcfg(whd_driver_t whd_driver);
static whd_result_t whd_bus_usb_download_firmware(whd_driver_t whd_driver);
static whd_bool_t whd_bus_usb_wake_interrupt_present(whd_driver_t whd_driver);
static uint32_t whd_bus_usb_packet_available_to_read(whd_driver_t whd_driver);

whd_result_t whd_bus_usb_send_buffer(whd_driver_t whd_driver, whd_buffer_t buffer);
whd_result_t whd_bus_usb_read_frame(whd_driver_t whd_driver, whd_buffer_t* buffer);
static whd_result_t whd_bus_usb_irq_enable(whd_driver_t whd_driver, whd_bool_t enable);
static whd_result_t whd_bus_usb_irq_register(whd_driver_t whd_driver);
static whd_result_t whd_bus_usb_reinit_stats(whd_driver_t whd_driver,
                                             whd_bool_t wake_from_firmware);
static whd_result_t whd_bus_usb_print_stats(whd_driver_t whd_driver, whd_bool_t reset_after_print);
static void whd_bus_usb_init_stats(whd_driver_t whd_driver);
static uint32_t whd_bus_usb_get_max_transfer_size(whd_driver_t whd_driver);
static whd_bool_t whd_bus_usb_use_status_report_scheme(whd_driver_t whd_driver);
static uint8_t whd_bus_usb_backplane_read_padd_size(whd_driver_t whd_driver);
static whd_result_t whd_bus_usb_ack_interrupt(whd_driver_t whd_driver, uint32_t intstatus);
static whd_result_t whd_bus_usb_poke_wlan(whd_driver_t whd_driver);
static whd_result_t whd_bus_usb_wakeup(whd_driver_t whd_driver);
static whd_result_t whd_bus_usb_sleep(whd_driver_t whd_driver);
static whd_result_t whd_bus_usb_wait_for_wlan_event(whd_driver_t whd_driver,
                                                    cy_semaphore_t* transceive_semaphore);

static void whd_bus_usb_on_device_ready(cyhal_usb_devinfo_t *info);
static void whd_bus_usb_on_device_removed(cyhal_usb_devinfo_t *info);

static void whd_bus_usb_on_receive(const void *data, size_t len);

/*****************************************************
 *             Global Function definitions
 ******************************************************/

whd_driver_t cybsp_get_wifi_driver(void);


/* ------------------------------------------------------------------------------------- */

uint32_t whd_bus_usb_attach(whd_driver_t whd_driver, cyhal_usb_t* usb_obj)
{
    struct whd_bus_info* whd_bus_info;

    whd_bus_info = (whd_bus_info_t*)whd_mem_malloc(sizeof(whd_bus_info_t));

    if (whd_bus_info == NULL)
    {
        WPRINT_WHD_ERROR(("Memory allocation failed for whd_bus_info in %s\n", __FUNCTION__));
        return WHD_BUFFER_UNAVAILABLE_PERMANENT;
    }
    memset(whd_bus_info, 0, sizeof(whd_bus_info_t));

    whd_driver->bus_if = whd_bus_info;

    whd_driver->bus_priv = (struct whd_bus_priv*)whd_mem_malloc(sizeof(struct whd_bus_priv));

    if (whd_driver->bus_priv == NULL)
    {
        WPRINT_WHD_ERROR(("Memory allocation failed for whd_bus_priv in %s\n", __FUNCTION__));
        return WHD_BUFFER_UNAVAILABLE_PERMANENT;
    }
    memset(whd_driver->bus_priv, 0, sizeof(struct whd_bus_priv));

    whd_driver->bus_priv->usb_obj = usb_obj;

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
    if (whd_driver->bus_if != NULL)
    {
        whd_mem_free(whd_driver->bus_if);
        whd_driver->bus_if = NULL;
    }
    if (whd_driver->bus_priv != NULL)
    {
        whd_bus_usb_deinit(whd_driver);
        whd_mem_free(whd_driver->bus_priv);
        whd_driver->bus_priv = NULL;
    }
}


/***************************************************************************************************
 * whd_bus_usb_init
 **************************************************************************************************/
whd_result_t whd_bus_usb_init(whd_driver_t whd_driver)
{
    /* Initialize BULK vendor class */
    cyhal_usb_config_t usb_config = {
        .filters = whd_bus_usb_device_filters,
        .nfilters = sizeof(whd_bus_usb_device_filters) / sizeof(whd_bus_usb_device_filters[0]),

        .bulkRecvBufSz = WHD_USB_MAX_RECEIVE_BUF_SIZE,
        .onInsertion = whd_bus_usb_on_device_ready,
        .onDeletion = whd_bus_usb_on_device_removed,
        .onBulkRecv = whd_bus_usb_on_receive,
    };
    cy_rslt_t result;
    whd_result_t status = whd_bus_rx_queue_init(whd_driver);

    if (status != WHD_SUCCESS) {
        return status;
    }

    if (cy_rtos_init_semaphore(&whd_driver->bus_priv->init_sem, 1, 0) != WHD_SUCCESS) {
        whd_bus_rx_queue_deinit(whd_driver);
        return WHD_HAL_ERROR;
    }

    if (cyhal_usb_init(whd_driver->bus_priv->usb_obj, &usb_config) != CY_RSLT_SUCCESS) {
        whd_bus_rx_queue_deinit(whd_driver);
        cy_rtos_deinit_semaphore(&whd_driver->bus_priv->init_sem);
        return WHD_HAL_ERROR;
    }

    /* wait for USB initialization */
    result = cy_rtos_get_semaphore(&whd_driver->bus_priv->init_sem, 5000, false);
    if (result != CY_RSLT_SUCCESS) {
        WPRINT_ERROR(("timed out waiting for USB device\n"));
        cyhal_usb_deinit(whd_driver->bus_priv->usb_obj);
        whd_bus_rx_queue_deinit(whd_driver);
        cy_rtos_deinit_semaphore(&whd_driver->bus_priv->init_sem);
        return WHD_TIMEOUT;
    }

    whd_bus_set_state(whd_driver, WHD_TRUE);
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
    
    cy_rslt_t cy_result = cyhal_usb_deinit(whd_driver->bus_priv->usb_obj) ;
    whd_result_t whd_result = whd_bus_rx_queue_deinit(whd_driver);
    return ((cy_result == CY_RSLT_SUCCESS) && (whd_result == WHD_SUCCESS)) ? WHD_SUCCESS : WHD_HAL_ERROR;
}


/***************************************************************************************************
 * whd_bus_usb_dl_needed
 **************************************************************************************************/
static bool whd_bus_usb_dl_needed(whd_driver_t whd_driver)
{
    struct bootrom_id_le id;

    if (whd_driver == NULL)
    {
        return false;
    }

    /* Check if firmware is already downloaded  by querying runtime ID */
    id.chip = 0xDEAD;
    whd_bus_usb_dl_cmd(whd_driver, WHD_USB_DL_GETVER, &id, sizeof(id));

    WPRINT_WHD_INFO(("Chip %x rev 0x%x\n", id.chip, id.chiprev));

    if (id.chip == WHD_USB_POSTBOOT_ID)
    {
        WPRINT_WHD_INFO(("Firmware already downloaded\n"));

        whd_bus_usb_dl_cmd(whd_driver, WHD_USB_DL_RESETCFG, &id, sizeof(id));
        return false;
    }

    return true;
}


/***************************************************************************************************
 * whd_bus_usb_resetcfg
 **************************************************************************************************/
static whd_result_t whd_bus_usb_resetcfg(whd_driver_t whd_driver)
{
    whd_result_t result;
    struct bootrom_id_le id;
    uint32_t loop_cnt = 0;

    do {
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

    if (id.chip == WHD_USB_POSTBOOT_ID)
    {
        (void)whd_bus_usb_dl_cmd(whd_driver, WHD_USB_DL_RESETCFG, &id, sizeof(id));
        return 0;
    }
    else
    {
        WPRINT_WHD_ERROR(("%s: Cannot talk to Dongle. Firmware is not UP, %lu ms\n",
                          __FUNCTION__, WHD_USB_RESET_GETVER_SPINWAIT * loop_cnt));
        return 1;
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
    uint32_t buff[WHD_USB_TRX_RDL_CHUNK / sizeof(uint32_t)];

    struct rdl_state_le state;

    WPRINT_WHD_INFO(("\n\rStart FW download\n\r"));

    result = whd_resource_size(whd_driver, WHD_RESOURCE_WLAN_FIRMWARE, &image_size);
    if (result != WHD_SUCCESS)
    {
        WPRINT_WHD_ERROR(("Fatal error: download_resource doesn't exist, %s failed at line %d \n",
                          __func__, __LINE__));
    }

    if (image_size <= 0)
    {
        WPRINT_WHD_ERROR(("Fatal error: download_resource can't load with invalid size,"
                          "%s failed at line %d \n", __func__, __LINE__));
        result = WHD_BADARG;
    }

    /* Prepare USB boot loader for runtime image and check we are in the
     * Waiting state */
    result = whd_bus_usb_dl_cmd(whd_driver, WHD_USB_DL_START, &state, sizeof(state));
    if ((result != WHD_SUCCESS) || (state.state != WHD_USB_DL_WAITING))
    {
        WPRINT_WHD_ERROR(("%s: Failed to DL_START\n", __FUNCTION__));
        return 1;
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

            /* Simply avoid having to send a ZLP by ensuring we never have an even
             * multiple of 64 */
            if (!(size % 64))
            {
                size -= 4;
            }

            /* Send data by USB Bulk */
            result = whd_bus_usb_bulk_send(whd_driver, (uint8_t*)buff, size);
            if (result != WHD_SUCCESS)
            {
                WPRINT_WHD_ERROR(("%s: Failed to write firmware image\n", __FUNCTION__));
            }

            sent += size;
        }

        /* Read the status and restart if an error is reported */
        result = whd_bus_usb_dl_cmd(whd_driver, WHD_USB_DL_GETSTATE, &state, sizeof(state));
        if (result)
        {
            WPRINT_WHD_ERROR(("%s: DL_GETSTATE Failed\n", __FUNCTION__));
            return 1;
        }

        if ((state.state == WHD_USB_DL_BAD_HDR) || (state.state == WHD_USB_DL_BAD_CRC))
        {
            WPRINT_WHD_ERROR(("%s: Bad Hdr or Bad CRC state %lu\n\n", __FUNCTION__, state.state));
            return 1;
        }
    }
    WPRINT_WHD_INFO(("FW download complete, wrote %u bytes\n\r", state.bytes));

    /* Start the image */
    WPRINT_WHD_INFO(("\n\rStart the FW image \n\r"));
    if (state.state == WHD_USB_DL_RUNNABLE)
    {
        whd_bus_usb_dl_go(whd_driver);
        /* The USB Dongle may go for re-enumeration. */
    }
    else
    {
        WPRINT_WHD_ERROR(("%s: Dongle not runnable\n", __FUNCTION__));
        return 1;
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
    return whd_bus_rx_queue_size( whd_driver);
}


/***************************************************************************************************
 * whd_bus_usb_send_buffer
 **************************************************************************************************/
whd_result_t whd_bus_usb_send_buffer(whd_driver_t whd_driver, whd_buffer_t buffer)
{
    whd_result_t status = WHD_SUCCESS;

    uint8_t* data =
        (uint8_t*)((whd_transfer_bytes_packet_t*)(whd_buffer_get_current_piece_data_pointer(
                                                      whd_driver,
                                                      buffer) + sizeof(whd_buffer_t)))->data;
    uint16_t size =
        (uint16_t)(whd_buffer_get_current_piece_size(whd_driver, buffer) - sizeof(whd_buffer_t));

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

            status =
                whd_bus_usb_bulk_send(whd_driver, bdc_header,
                                      bdc_size - 4 /* TODO: add define for -4 */);
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

            /* Process CDC data... */
            whd_process_cdc(whd_driver, rec_buffer);
            break;
        }

        default:
            whd_minor_assert("whd_bus_usb_send_buffer: SDPCM packet of unknown"
                             " channel received - dropping packet", 0 != 0);
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
    if (whd_bus_rx_queue_size(whd_driver))
    {
        /* Take a queue data */
        whd_bus_rx_queue_dequeue(whd_driver, buffer);
        return WHD_SUCCESS;
    }

    return 1;
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
 * whd_bus_usb_wait_for_wlan_event
 **************************************************************************************************/
void whd_usb_rx_thread_notify(whd_driver_t whd_driver);

/***************************************************************************************************
 * whd_bus_usb_wait_for_wlan_event
 **************************************************************************************************/
static whd_result_t whd_bus_usb_wait_for_wlan_event(whd_driver_t whd_driver,
                                                    cy_semaphore_t* transceive_semaphore)
{
    whd_result_t result;

    whd_usb_rx_thread_notify(whd_driver);

    result = cy_rtos_get_semaphore(transceive_semaphore, CY_RTOS_NEVER_TIMEOUT, WHD_FALSE);
    return result;
}


/***************************************************************************************************
 * whd_usb_rx_thread_notify
 **************************************************************************************************/
void whd_usb_rx_thread_notify(whd_driver_t whd_driver)
{
    cyhal_usb_start_bulk_rx(whd_driver->bus_priv->usb_obj);
}


/***************************************************************************************************
 * whd_usb_rx_thread
 **************************************************************************************************/
static void whd_bus_usb_on_receive(const void *data, size_t len)
{
    whd_driver_t whd_driver = cybsp_get_wifi_driver();
    whd_buffer_t rx_buffer;
    uint8_t *rec_buf;

    if (whd_bus_is_up(whd_driver) == WHD_FALSE) {
        cyhal_usb_stop_bulk_rx(whd_driver->bus_priv->usb_obj);
        return;
    }

    if (whd_host_buffer_get(whd_driver, &rx_buffer, WHD_NETWORK_RX, (uint16_t)(WHD_USB_MAX_RECEIVE_BUF_SIZE), 0) != WHD_SUCCESS) {
        WPRINT_WHD_ERROR(("whd_usb_rx: couldn't allocate buffer for new packet, dropping\n"));
        return;
    }

    rec_buf = whd_buffer_get_current_piece_data_pointer(whd_driver, rx_buffer);
    memcpy(rec_buf, data, len);

    whd_buffer_set_size(whd_driver, rx_buffer, len);

    /* always succeeds: if, after this call, the queue is full, we disable RX. */
    whd_bus_rx_queue_enqueue(whd_driver, rx_buffer);

    if (whd_bus_rx_queue_is_full(whd_driver)) {
        whd_thread_notify(whd_driver);
        cyhal_usb_stop_bulk_rx(whd_driver->bus_priv->usb_obj);
    }
}


/***************************************************************************************************
 * whd_bus_usb_dl_cmd
 **************************************************************************************************/
whd_result_t whd_bus_usb_dl_cmd(whd_driver_t whd_driver, uint8_t cmd, void* buffer, uint32_t buflen)
{
    cy_rslt_t result = cyhal_usb_dl_cmd(whd_driver->bus_priv->usb_obj, cmd, (cmd == WHD_USB_DL_GO) ? 1 : 0, buffer, buflen);
    return (result == CY_RSLT_SUCCESS) ? WHD_SUCCESS : WHD_HAL_ERROR;
}


/***************************************************************************************************
 * whd_bus_usb_dl_go
 **************************************************************************************************/
whd_result_t whd_bus_usb_dl_go(whd_driver_t whd_driver)
{
    return whd_bus_usb_dl_cmd(whd_driver, WHD_USB_DL_GO, NULL, 0);
}


/***************************************************************************************************
 * whd_bus_usb_bulk_send
 **************************************************************************************************/
whd_result_t whd_bus_usb_bulk_send(whd_driver_t whd_driver, void* buffer, int len)
{
    cy_rslt_t result;
    size_t buflen;

    /* Writes data to the BULK device */
    result = cyhal_usb_bulk_send(whd_driver->bus_priv->usb_obj, buffer, &buflen);

    if (result != CY_RSLT_SUCCESS)
    {
        WPRINT_WHD_ERROR(("BULK send failed: %d", result));
        return WHD_HAL_ERROR;
    }

    return WHD_SUCCESS;
}


/*
   The bootloader supports additional commands to read and write data to/from backplane addresses
    DL_RDHW8: read an 8-bit value from a backplane address
    DL_RDHW16: read a 16-bit value from a backplane address (must be 2-byte aligned)
    DL_RDHW32: read a 32-bit value from a backplane address (must be 4-byte aligned)

   For example, to read the first 16-bit word of 43236 CIS (the CIS region begins at offset 0x30 of
      OTP, which starts at backplane address 0x18000800):
    bmRequestType: 0xC1 (Read Vendor Interface)
    bRequest: 0x11 (DL_RDHW16)
    wValue:   0x0830 (lower 16 bits of backplane address)
    wIndex:   0x1800 (upper 16 bits of backplane address)
    wLength:  sizeof(hwacc_t)

    response buffer should be a pointer to type hwacc_t; if successful, the value read will be in
       the hwacc_t.data field
    DL_WRHW: write a 8/16/32 bit value to a backplane address, observing byte alignment requirements

   For example, to write a 32-bit word to backplane address 0x18000634:
    bmRequestType: 0x41 (Write Vendor Interface)
    bRequest: 0x14 (DL_WRHW)
    wValue:   0x0001
    wIndex:   0x0000
    wLength:  sizeof(hwacc_t)

    buffer should be a pointer to type hwacc_t:
    hwacc.cmd  = 0x14 (DL_WRHW)
    hwacc.addr = 0x18000634
    hwacc.data = 32-bit value to write
    hwacc.len  = 4
 */


/* Device data transfer functions */
whd_result_t whd_bus_usb_send_ctrl(whd_driver_t whd_driver, void* buffer, uint32_t* len)
{
    cy_rslt_t result =  cyhal_usb_ctrl_send(whd_driver->bus_priv->usb_obj, buffer, len);
    return (result == CY_RSLT_SUCCESS) ? WHD_SUCCESS : WHD_HAL_ERROR;
}


/***************************************************************************************************
 * whd_bus_usb_receive_ctrl_buffer
 **************************************************************************************************/
whd_result_t whd_bus_usb_receive_ctrl_buffer(whd_driver_t whd_driver, whd_buffer_t* buffer)
{
    uint32_t size = WHD_USB_MAX_RECEIVE_BUF_SIZE;
    whd_result_t status = whd_host_buffer_get(whd_driver, buffer, WHD_NETWORK_RX,
            (unsigned short)(WHD_USB_MAX_RECEIVE_BUF_SIZE + (uint16_t)sizeof(whd_buffer_header_t)),
            (whd_sdpcm_has_tx_packet(whd_driver) ? 0 : WHD_RX_BUF_TIMEOUT));

    if (status != WHD_SUCCESS) {
        return status;
    }

    cy_rslt_t result =  cyhal_usb_ctrl_receive(whd_driver->bus_priv->usb_obj, whd_buffer_get_current_piece_data_pointer(whd_driver, *buffer), &size);
    return (result == CY_RSLT_SUCCESS) ? WHD_SUCCESS : WHD_HAL_ERROR;
}


/***************************************************************************************************
 * whd_bus_usb_on_device_ready
 **************************************************************************************************/
static void whd_bus_usb_on_device_ready(cyhal_usb_devinfo_t *info)
{
    whd_driver_t whd_driver = cybsp_get_wifi_driver();
    cy_rslt_t result;

    assert(info->vid == CY_USB_VENDOR_ID_CYPRESS);
    assert(info->pid == CY_USB_4373_DEVICE_ID || info->pid == BRCM_USB_BCMFW_DEVICE_ID);

    switch (info->pid) {
        case CY_USB_4373_DEVICE_ID:
            if (whd_bus_usb_dl_needed(whd_driver))
            {
                whd_bus_usb_download_firmware(whd_driver);
            }
            break;

        case BRCM_USB_BCMFW_DEVICE_ID:
            if (whd_bus_usb_resetcfg(whd_driver)) {
                WPRINT_WHD_ERROR(("USB firmware downloaded, but reset failed"));
                break;
            }
            result = cyhal_usb_start_bulk_rx(whd_driver->bus_priv->usb_obj);
            if (result != CY_RSLT_SUCCESS) {
                WPRINT_WHD_ERROR(("could not start bulk RX"));
            }
            else {
                cy_rtos_set_semaphore(&whd_driver->bus_priv->init_sem, false);
            }
            break;

        default:
            break;
    }
}


/***************************************************************************************************
 * whd_bus_usb_on_device_removed
 **************************************************************************************************/
static void whd_bus_usb_on_device_removed(cyhal_usb_devinfo_t *info)
{
    whd_driver_t whd_driver = cybsp_get_wifi_driver();

    if (info->vid == CY_USB_VENDOR_ID_CYPRESS && info->pid == BRCM_USB_BCMFW_DEVICE_ID) {
        (void)cyhal_usb_stop_bulk_rx(whd_driver->bus_priv->usb_obj);
    }
}


/* Initialize rx_queue */
whd_result_t whd_bus_rx_queue_init(whd_driver_t whd_driver)
{
    if (cy_rtos_queue_init(&whd_driver->bus_priv->queue, WHD_USB_RX_QUEUE_SIZE, sizeof(whd_buffer_t*)) != CY_RSLT_SUCCESS)
    {
        return WHD_QUEUE_ERROR;
    }
    return WHD_SUCCESS;
}


/* Deinitialize rx_queue */
whd_result_t whd_bus_rx_queue_deinit(whd_driver_t whd_driver)
{
    if (cy_rtos_queue_deinit(&whd_driver->bus_priv->queue) != CY_RSLT_SUCCESS)
    {
        return WHD_QUEUE_ERROR;
    }
    return WHD_SUCCESS;
}


/* Checks if the queue is full */
bool whd_bus_rx_queue_is_full(whd_driver_t whd_driver)
{
    size_t num_spaces;
    cy_rtos_queue_space(&whd_driver->bus_priv->queue, &num_spaces);

    return num_spaces ? false : true;
}


/* Returns the total number of elements in the queue */
size_t whd_bus_rx_queue_size(whd_driver_t whd_driver)
{
    size_t num = 0;
    cy_rtos_queue_count(&whd_driver->bus_priv->queue, &num);
    return num;
}


/* Adds an element to the end of the queue  */
whd_result_t whd_bus_rx_queue_enqueue(whd_driver_t whd_driver, whd_buffer_t* data)
{
    cy_rslt_t status = cy_rtos_queue_put(&whd_driver->bus_priv->queue, &data);
    return status ? WHD_QUEUE_ERROR : WHD_SUCCESS;
}


/* Removes an element from the front of the queue */
whd_result_t whd_bus_rx_queue_dequeue(whd_driver_t whd_driver, whd_buffer_t* data)
{
    cy_rslt_t status = cy_rtos_queue_get(&whd_driver->bus_priv->queue, data);
    return status ? WHD_QUEUE_ERROR : WHD_SUCCESS;
}


#endif /* (CYBSP_WIFI_INTERFACE_TYPE == CYBSP_USB_INTERFACE) */