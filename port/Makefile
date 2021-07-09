# core Phoenix-RTOS LwIP port sources
NAME := lwip
LOCAL_PATH := $(call my-dir)
SRCS := $(wildcard $(LOCAL_PATH)*.c)
DEP_LIBS := lwip-drivers lwip-core

# FIXME: use constructors for registration in lwip
LOCAL_CFLAGS := $(addprefix -DHAVE_DRIVER_,$(sort $(NET_DRIVERS)))

ifeq (${LWIP_IPSEC_BUILD},yes)
  LOCAL_CFLAGS += -DLWIP_IPSEC=1 -DLWIP_IPSEC_DEV=\"${LWIP_IPSEC_DEV}\"
  DEP_LIBS += lwip-ipsec
else
  LOCAL_CFLAGS += -DLWIP_IPSEC=0
endif

ifeq (${LWIP_WIFI_BUILD},yes)
  LOCAL_CFLAGS += -DLWIP_WIFI=1
  DEP_LIBS += wifi-hal wifi-lwip wifi-whd
else
  LOCAL_CFLAGS += -DLWIP_WIFI=0
endif

include $(binary.mk)
