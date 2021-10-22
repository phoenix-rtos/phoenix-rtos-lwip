#
# Makefile for phoenix-rtos-lwip
#
# Copyright 2019-2021 Phoenix Systems
#
# %LICENSE%
#

NAME := wifi-whd

LOCAL_SRCS := whd_ap.c whd_buffer_api.c whd_cdc_bdc.c whd_chip.c whd_chip_constants.c whd_clm.c whd_debug.c \
              whd_events.c whd_logging.c whd_management.c whd_network_if.c whd_resource_if.c whd_resources.c \
              whd_sdpcm.c whd_thread.c whd_utils.c whd_wifi_api.c whd_wifi.c whd_wifi_p2p.c bus_protocols/whd_bus.c \
              bus_protocols/whd_bus_common.c bus_protocols/whd_bus_sdio_protocol.c

LOCAL_CFLAGS += -DCYHAL_API_VERSION=1

include $(static-lib.mk)
