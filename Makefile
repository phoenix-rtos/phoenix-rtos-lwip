#!make -f

TARGET ?= ia32
NET_DRIVERS ?= $(if $(filter ia32%,$(TARGET)),rtl) $(if $(filter arm-imx%,$(TARGET)),enet) pppos


CC = $(CROSS)gcc
AR = $(CROSS)ar
STRIP = $(CROSS)strip


MAKEFLAGS += --no-print-directory --output-sync

CFLAGS += -O3 -g -Wall -Wstrict-prototypes
CFLAGS += -Iinclude -Ilib-lwip/src/include
CFLAGS += -static -ffunction-sections -fdata-sections
CFLAGS += -nostartfiles -nostdlib

LDFLAGS += --gc-sections -nostdlib
LIBS = -lphoenix -lgcc

include Makefile.$(TARGET)

.PHONY: clean all
all: netsrv

OUT_LIBS := lwip lwip-port netdrivers
OBJS := $(addprefix build/lib,$(addsuffix .a,$(OUT_LIBS)))

#
# LwIP sources
#

LWIPDIR := lib-lwip/src
include $(LWIPDIR)/Filelists.mk
LWIP_EXCLUDE := netif/slipif.c
LWIP_SRCS := $(filter-out $(addprefix $(LWIPDIR)/,$(LWIP_EXCLUDE)),$(LWIPNOAPPSFILES))
LWIP_OBJS := $(patsubst $(LWIPDIR)/%.c,build/lwip/%.o,$(LWIP_SRCS))

build/lwip/%.o: $(LWIPDIR)/%.c include/lwipopts.h $(filter clean,$(MAKECMDGOALS))
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

build/liblwip.a: $(LWIP_OBJS)
	$(AR) $(ARFLAGS) $@ $^

#
# LwIP system wrapper
#
#
PORT_SRCS := $(wildcard port/*.c)
PORT_OBJS := $(patsubst %.c,build/%.o,$(PORT_SRCS))

build/port/%.o: port/%.c $(filter clean,$(MAKECMDGOALS))
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

build/liblwip-port.a: $(PORT_OBJS)
	$(AR) $(ARFLAGS) $@ $^

#
# netif drivers
#
include drivers/Makefile.inc
NDRV_SRCS := $(addprefix drivers/,$(sort $(foreach v,common $(NET_DRIVERS),$(DRIVER_SRCS_$(v)))))
NDRV_OBJS := $(patsubst %.c,build/%.o,$(NDRV_SRCS))
CFLAGS += $(addprefix -DHAVE_DRIVER_,$(sort $(NET_DRIVERS)))

build/drivers/%.o: drivers/%.c $(filter clean,$(MAKECMDGOALS))
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

build/libnetdrivers.a: $(NDRV_OBJS)
	$(AR) $(ARFLAGS) $@ $^


netsrv: $(OBJS)
	$(CC) $(CFLAGS) $(addprefix -Wl$(comma),$(LDFLAGS) -Map=$@.map) -o $@ -Wl,-\( $(LIBS) $(OBJS) -Wl,-\)


clean:
	rm -rf netsrv netsrv.s build

comma = ,
