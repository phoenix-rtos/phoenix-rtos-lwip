# core Phoenix-RTOS LwIP port sources
NAME := lwip
LOCAL_PATH := $(call my-dir)
SRCS := $(wildcard $(LOCAL_PATH)*.c)
DEP_LIBS := lwip-drivers lwip-core


ifeq ($(LWIP_G3_BUILD), yes)
LIBS := ps_eap ps_g3_sap libtinyaes hal
endif


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

LWIP_MAIN_THREAD_STACKSIZE ?= 4096
LOCAL_LDFLAGS := -z stack-size=$(LWIP_MAIN_THREAD_STACKSIZE)

include $(binary.mk)
