#
# Makefile for phoenix-rtos-lwip
#
# Copyright 2019-2021 Phoenix Systems
#
# %LICENSE%
#

include ../phoenix-rtos-build/Makefile.common

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
include $(static-lib.mk)

# should define NET_DRIVERS and platform driver sources
-include _targets/Makefile.$(TARGET_FAMILY)-$(TARGET_SUBFAMILY)

include drivers/Makefile
include port/Makefile

DEFAULT_COMPONENTS := $(ALL_COMPONENTS)

# create generic targets
.PHONY: all install clean
all: $(DEFAULT_COMPONENTS)
install: $(patsubst %,%-install,$(DEFAULT_COMPONENTS))
clean: $(patsubst %,%-clean,$(ALL_COMPONENTS))
