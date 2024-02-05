#
# Makefile for phoenix-rtos-lwip
#
# Copyright 2019-2021 Phoenix Systems
#
# %LICENSE%
#
# set local path manually as we're including other Makefiles here (as an empty var - TOPDIR)

# calling my-dir works only when Makefile.common is already included before including this file
# as this is not a case here we need to this manually
LWIP_LOCAL_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

include ../phoenix-rtos-build/Makefile.common

.DEFAULT_GOAL := all

# default path for the programs to be installed in rootfs
DEFAULT_INSTALL_PATH := /sbin

# core LwIP component
LWIPDIR := lib-lwip/src
include $(LWIPDIR)/Filelists.mk
LWIP_EXCLUDE := netif/slipif.c
LWIP_SRCS := $(filter-out $(addprefix $(LWIPDIR)/,$(LWIP_EXCLUDE)),$(LWIPNOAPPSFILES))

# G3-PLC modifications to core LwIP
ifeq (${LWIP_G3_BUILD}, yes)
include g3/Makefile
endif

LWIPOPTS_DIR ?= include/default-opts
LWIPPORT_DIR ?= include/

# port specific definitions
include Makefile.contrib

ifeq ("$(TARGET)","host-generic-pc")
DEPS := lwip-port lwip-opts
LOCAL_HEADERS_DIR :=  $(LWIPDIR)/include
else
# don't install include subdir contents, these are actually internal headers
LOCAL_HEADERS_DIR :=  nothing
endif

CFLAGS += -Wundef -I$(LWIPPORT_DIR) -I$(LWIPDIR)/include -I$(LWIPOPTS_DIR) 

LOCAL_DIR := $(LWIP_LOCAL_DIR)
NAME := lwip-core
SRCS := $(LWIP_SRCS)
include $(static-lib.mk)

# should define NET_DRIVERS and platform driver sources
-include _targets/Makefile.$(TARGET_FAMILY)-$(TARGET_SUBFAMILY)

ifeq (${LWIP_WIFI_BUILD},yes)
CFLAGS += -Iwi-fi/hal -Iwi-fi/lwip -Iwi-fi/whd
include wi-fi/hal/Makefile
include wi-fi/whd/Makefile
include wi-fi/lwip/Makefile
endif

ifeq (${LWIP_IPSEC_BUILD},yes)
include ipsec/Makefile
endif

include drivers/Makefile
ifneq ("$(TARGET)","host-generic-pc")
include port/Makefile
endif

DEFAULT_COMPONENTS := $(ALL_COMPONENTS)

# create generic targets
.PHONY: all install clean
all: $(DEFAULT_COMPONENTS)
install: $(patsubst %,%-install,$(DEFAULT_COMPONENTS))
clean: $(patsubst %,%-clean,$(ALL_COMPONENTS))
