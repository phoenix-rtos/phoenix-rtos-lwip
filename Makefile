#!make -f

TARGET ?= arm-imx
NET_DRIVERS ?= $(if $(filter ia32%,$(TARGET)),rtl) $(if $(filter arm-imx%,$(TARGET)),enet) pppos

SIL = @

CC = $(CROSS)gcc
AR = $(CROSS)ar
STRIP = $(CROSS)strip
OBJDUMP = $(CROSS)objdump


MAKEFLAGS += --no-print-directory --output-sync

CFLAGS += -O3 -g -Wall -Wstrict-prototypes
CFLAGS += -Iinclude -Ilib-lwip/src/include
CFLAGS += -static -ffunction-sections -fdata-sections
CFLAGS += -nostartfiles -nostdlib

LDFLAGS += --gc-sections -nostdlib
LIBS = -lphoenix -lgcc

ARFLAGS = -r

include Makefile.$(TARGET)

.PHONY: clean all
all: lwip

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
	@(printf "CC  lib-lwip/src/%s/%-24s\n" "$(notdir $(@D))" "$(@F)")
	$(SIL)$(CC) $(CFLAGS) -c -o $@ $<

build/liblwip.a: $(LWIP_OBJS)
	@(printf "AR  %s/%-24s\n" "$(notdir $(@D))" "$(@F)")
	$(SIL)$(AR) $(ARFLAGS) $@ $^ 2>/dev/null

#
# LwIP system wrapper
#
#
PORT_SRCS := $(wildcard port/*.c)
PORT_OBJS := $(patsubst %.c,build/%.o,$(PORT_SRCS))

build/port/%.o: port/%.c $(filter clean,$(MAKECMDGOALS))
	@mkdir -p $(dir $@)
	@(printf "CC  %s/%-24s\n" "$(notdir $(@D))" "$(@F)")
	$(SIL)$(CC) $(CFLAGS) -c -o $@ $<

build/liblwip-port.a: $(PORT_OBJS)
	@(printf "AR  %s/%-24s\n" "$(notdir $(@D))" "$(@F)")
	$(SIL)$(AR) $(ARFLAGS) $@ $^ 2>/dev/null

#
# netif drivers
#
include drivers/Makefile.inc
NDRV_SRCS := $(addprefix drivers/,$(sort $(foreach v,common $(NET_DRIVERS),$(DRIVER_SRCS_$(v)))))
NDRV_OBJS := $(patsubst %.c,build/%.o,$(NDRV_SRCS))
CFLAGS += $(addprefix -DHAVE_DRIVER_,$(sort $(NET_DRIVERS)))

build/drivers/%.o: drivers/%.c $(filter clean,$(MAKECMDGOALS))
	@mkdir -p $(dir $@)
	@(printf "CC  %s/%-24s\n" "$(notdir $(@D))" "$(@F)")
	$(SIL)$(CC) $(CFLAGS) -c -o $@ $<

build/libnetdrivers.a: $(NDRV_OBJS)
	@(printf "AR  %s/%-24s\n" "$(notdir $(@D))" "$(@F)")
	$(SIL)$(AR) $(ARFLAGS) $@ $^ 2>/dev/null


lwip: $(OBJS)
	@echo "\033[1;34mLD $@\033[0m"
	
	@(\
	printf "Subsystem                  | text    | rodata  | data\n";\
	printf "=========================================================\n";\
	for f in $(ARCHS) $(OBJS); do\
	 	datasz=0;\
		textsz=0;\
		rodatasz=0;\
		file=$$f;\
		for i in `$(OBJDUMP) -t $$file | grep -e " O " | grep -v ".rodata" | awk '{ print $$1 }'`; do\
			datasz=`echo $$(($$datasz + 0x$$i))`;\
		done;\
		for i in `$(OBJDUMP) -t $$file | grep -e " O " | grep ".rodata" | awk '{ print $$1 }'`; do \
			rodatasz=`echo $$(($$rodatasz + 0x$$i))`;\
		done; \
		for i in `$(OBJDUMP) -t $$file | grep -e " F " | awk '{ print $$5 }'`; do \
			textsz=`echo $$(($$textsz + 0x$$i))`;\
		done;\
		n=`dirname $$f`;\
		n=`basename $$n | sed "s/libphoenix/./"`;\
		f=`basename $$f`;\
		printf "%-26s | %-7d | %-7d | %-7d\n" $$n/$$f $$textsz $$rodatasz $$datasz;\
	done;)
	
	$(SIL)$(CC) $(CFLAGS) $(addprefix -Wl$(comma),$(LDFLAGS) -Map=$@.map) -o $@ -Wl,-\( $(LIBS) $(OBJS) -Wl,-\)
	
	@(echo "";\
	echo "=> lwip for [$(TARGET)] has been created";\
	echo "")


clean:
	rm -rf lwip lwip.s build

comma = ,
