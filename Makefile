#!make -f

TARGET ?= ia32
NET_DRIVERS ?= $(if $(filter ia32%,$(TARGET)),rtl) $(if $(filter arm-imx%,$(TARGET)),enet)


CC = $(CROSS)gcc
AR = $(CROSS)ar
STRIP = $(CROSS)strip


MAKEFLAGS += --no-print-directory --output-sync

CFLAGS += -O3 -g -Wall -Wstrict-prototypes
CFLAGS += -Iinclude -Ilib-lwip/src/include
CFLAGS += -static -ffunction-sections -fdata-sections
CFLAGS += -nostartfiles -nostdlib

ARFLAGS += -r

LDFLAGS += --gc-sections -nostdlib
LIBS = -lphoenix -lgcc

include Makefile.$(TARGET)

#
# LwIP sources
#

LWIPDIR := lib-lwip/src
include $(LWIPDIR)/Filelists.mk
LWIP_EXCLUDE := netif/slipif.c
LWIP_SRCS := $(filter-out $(addprefix $(LWIPDIR)/,$(LWIP_EXCLUDE)),$(LWIPNOAPPSFILES))
LWIP_OBJS := $(patsubst $(LWIPDIR)/%.c,build/lwip/%.o,$(LWIP_SRCS))

build/lwip/%.o: $(LWIPDIR)/%.c include/lwipopts.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<


#
# LwIP system wrapper
#
#
PORT_SRCS := $(wildcard port/*.c)
PORT_OBJS := $(patsubst %.c,build/%.o,$(PORT_SRCS))

build/port/%.o: port/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<


#
# netif drivers
#
include drivers/Makefile.inc
NDRV_SRCS := $(addprefix drivers/,$(sort $(foreach v,common $(NET_DRIVERS),$(DRIVER_SRCS_$(v)))))
NDRV_OBJS := $(patsubst %.c,build/%.o,$(NDRV_SRCS))
CFLAGS += $(addprefix -DHAVE_DRIVER_,$(sort $(NET_DRIVERS)))

build/drivers/%.o: drivers/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<


OBJS := $(LWIP_OBJS) $(NDRV_OBJS) $(PORT_OBJS)


netsrv: $(OBJS)
	$(CC) $(CFLAGS) $(addprefix -Wl$(comma),$(LDFLAGS)) -o $@ -Wl,-\( $(LIBS) $(OBJS) -Wl,-\)


.PHONY: clean
clean:
	rm -rf netsrv netsrv.s build

comma = ,
