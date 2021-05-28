#
# Makefile for phoenix-rtos-lwip
#
# Copyright 2019-2021 Phoenix Systems
#
# %LICENSE%
#

LOCAL_PATH := $(call my-dir)

# force G3-PLC custom lwipopts.h
LWIPOPTS_DIR := "include/default-opts/g3"

LWIP_EXCLUDE += netif/lowpan6.c netif/lowpan6_common.c
LWIP_SRCS := $(filter-out $(addprefix $(LWIPDIR)/,$(LWIP_EXCLUDE)),$(LWIPNOAPPSFILES))

G3_SRCS := lowpan6_g3.c lowpan6_common.c lbp_g3.c loadng_g3.c
LWIP_SRCS += $(addprefix $(LOCAL_PATH),$(G3_SRCS))
