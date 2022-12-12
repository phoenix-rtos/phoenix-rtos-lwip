# Makefile for lwip drivers to be included

# TODO: make every driver a separate component?
ifneq ($(EPHY_KSZ8081RND),)
  LOCAL_CFLAGS := -DEPHY_KSZ8081RND
endif

# make possible to specify defalult APN name externally
ifneq ($(PPPOS_DEFAULT_APN),)
  LOCAL_CFLAGS := -DPPPOS_DEFAULT_APN=\"$(PPPOS_DEFAULT_APN)\"
endif


# abstract drivers available on every platform
DRIVERS_SRCS := netif-driver.c
DRIVERS_SRCS_UTIL := bdring.c pktmem.c physmmap.c res-create.c
DRIVERS_SRCS_pppos := pppos.c
DRIVERS_SRCS_pppou := pppou.c
DRIVERS_SRCS_tuntap := tuntap.c

DRIVERS_SRCS += $(foreach driver,$(NET_DRIVERS),$(if $(filter $(driver),$(NET_DRIVERS_SUPPORTED)),\
	$(DRIVERS_SRCS_$(driver)),\
	$(error Driver '$(driver)' is not supported on target '$(TARGET)')))

# PPPoS: check if we support given modem
ifneq ($(filter pppos,$(NET_DRIVERS)),)
  PPPOS_MODEMS_SUPPORTED := $(patsubst ./modem/%/,%,$(sort $(dir $(wildcard ./modem/*/))))
  ifneq ($(filter $(PPPOS_MODEM),$(PPPOS_MODEMS_SUPPORTED)),)
    CFLAGS += -I./modem/$(PPPOS_MODEM)
  else
    $(error PPPOS_MODEM must have one of the following values: $(PPPOS_MODEMS_SUPPORTED))
  endif
endif

NAME := lwip-drivers
LOCAL_SRCS := $(DRIVERS_SRCS)
include $(static-lib.mk)
