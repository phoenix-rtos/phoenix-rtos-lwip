#
# Makefile for phoenix-rtos-lwip
#
# Copyright 2019-2021 Phoenix Systems
#
# %LICENSE%
#

SIL ?= @
MAKEFLAGS += --no-print-directory

TARGET ?= ia32-generic
#TARGET ?= armv7m4-stm32l4x6
#TARGET ?= armv7a7-imx6ull

include ../phoenix-rtos-build/Makefile.common
include ../phoenix-rtos-build/Makefile.$(TARGET_SUFF)

LWIPOPTS_DIR ?= "include/default-opts"

CFLAGS += -Wundef -I"$(PREFIX_H)" -Iinclude -Ilib-lwip/src/include -I"$(LWIPOPTS_DIR)"
LDFLAGS += -L"$(PREFIX_A)"

all: $(PREFIX_PROG_STRIPPED)lwip

LWIPDIR := lib-lwip/src
include $(LWIPDIR)/Filelists.mk
LWIP_EXCLUDE := netif/slipif.c
LWIP_SRCS := $(filter-out $(addprefix $(LWIPDIR)/,$(LWIP_EXCLUDE)),$(LWIPNOAPPSFILES))
LWIP_OBJS := $(patsubst %.c,$(PREFIX_O)%.o,$(LWIP_SRCS))

PORT_SRCS := $(wildcard port/*.c)
PORT_OBJS := $(patsubst %.c,$(PREFIX_O)%.o,$(PORT_SRCS))

DRIVERS_SRCS := netif-driver.c
DRIVERS_SRCS_UTIL := bdring.c pktmem.c physmmap.c res-create.c
DRIVERS_SRCS_pppos := pppos.c
DRIVERS_SRCS_pppou := pppou.c
DRIVERS_SRCS_tuntap := tuntap.c
-include _targets/Makefile.$(TARGET_FAMILY)-$(TARGET_SUBFAMILY)
DRIVERS_SRCS += $(foreach driver,$(NET_DRIVERS),$(if $(filter $(driver),$(NET_DRIVERS_SUPPORTED)),\
	$(DRIVERS_SRCS_$(driver)),\
	$(error Driver '$(driver)' is not supported on target '$(TARGET)')))
DRIVERS_OBJS := $(patsubst %.c,$(PREFIX_O)%.o,$(addprefix drivers/, $(DRIVERS_SRCS)))

ifneq ($(filter pppos,$(NET_DRIVERS)),)
PPPOS_MODEMS_SUPPORTED := $(patsubst ./modem/%/,%,$(sort $(dir $(wildcard ./modem/*/))))
ifneq ($(filter $(PPPOS_MODEM),$(PPPOS_MODEMS_SUPPORTED)),)
CFLAGS += -I./modem/$(PPPOS_MODEM)
else
$(error PPPOS_MODEM must have one of the following values: $(PPPOS_MODEMS_SUPPORTED))
endif
endif

CFLAGS += $(addprefix -DHAVE_DRIVER_,$(sort $(NET_DRIVERS)))

ifneq ($(EPHY_KSZ8081RND),)
	CFLAGS += -DEPHY_KSZ8081RND
endif

$(PREFIX_PROG)lwip: $(LWIP_OBJS) $(PORT_OBJS) $(DRIVERS_OBJS)
	$(LINK)

.PHONY: clean
clean:
	@echo "rm -rf $(BUILD_DIR)"

ifneq ($(filter clean,$(MAKECMDGOALS)),)
	$(shell rm -rf $(BUILD_DIR))
endif
