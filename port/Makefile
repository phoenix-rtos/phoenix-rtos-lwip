# core Phoenix-RTOS LwIP port sources
NAME := lwip
LOCAL_PATH := $(call my-dir)
SRCS := $(wildcard $(LOCAL_PATH)*.c)
DEP_LIBS := lwip-drivers lwip-core

# FIXME: use constructors for registration in lwip
LOCAL_CFLAGS := $(addprefix -DHAVE_DRIVER_,$(sort $(NET_DRIVERS)))

include $(binary.mk)
