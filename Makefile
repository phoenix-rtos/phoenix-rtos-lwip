#
# Makefile for phoenix-rtos-lwip
#
# Copyright 2019-2021 Phoenix Systems
#
# %LICENSE%
#

include ../phoenix-rtos-build/Makefile.common

# set local path manually as we're including other Makefiles here (as an empty var - TOPDIR)
LOCAL_DIR :=

.DEFAULT_GOAL := all

LWIPOPTS_DIR ?= "include/default-opts"

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

CFLAGS += -Wundef -Iinclude -Ilib-lwip/src/include -I"$(LWIPOPTS_DIR)"

NAME := lwip-core
SRCS := $(LWIP_SRCS)
# don't install include subdir contents, these are actually internal headers
LOCAL_HEADER_DIR := nothing
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
include port/Makefile

DEFAULT_COMPONENTS := $(ALL_COMPONENTS)

# create generic targets
.PHONY: all install clean
all: $(DEFAULT_COMPONENTS)
install: $(patsubst %,%-install,$(DEFAULT_COMPONENTS))
clean: $(patsubst %,%-clean,$(ALL_COMPONENTS))
