#
# Makefile for phoenix-rtos-lwip
#
# Copyright 2019-2021 Phoenix Systems
#
# %LICENSE%
#

NAME := wifi-lwip

LOCAL_SRCS := cybsp.c cybsp_wifi.c cy_network_buffer_lwip.c cy_lwip.c cy_lwip_dhcp_server.c main.c

LOCAL_CFLAGS += -DCY_WIFI_HOST_WAKE_SW_FORCE=0
LOCAL_CFLAGS += -DCY_RSLT_MODULE_BOARD_LIB_WHD_INTEGRATION=0x2ff
LOCAL_CFLAGS += -DENABLE_WIFI_MIDDLEWARE_LOGS
LOCAL_CFLAGS += -DCYBSP_WIFI_WL_REG_ON=0 # fake value - actual pin is hardcoded

include $(static-lib.mk)
