#!make -f

CFLAGS = -Iinclude -Ilib-lwip/src/include

CFLAGS += -O2 -g -Wall -Wstrict-prototypes -I$(SRCDIR) -nostartfiles -nostdlib \
	-m32 -mtune=generic -mno-mmx -mno-sse -fno-pic -fno-pie \
	-fomit-frame-pointer -ffreestanding \
	--sysroot=$(HOME)/src/phs/compiler/i386-phoenix \
	-static -ffunction-sections -fdata-sections

LIBS = -lphoenix $(shell $(CC) $(CFLAGS) -print-file-name=libgcc.a)
LDFLAGS = -m elf_i386 --gc-sections

#
# LwIP sources
#

LWIPDIR := lib-lwip/src
include $(LWIPDIR)/Filelists.mk
LWIP_EXCLUDE := netif/slipif.c
LWIP_SRCS := $(filter-out $(addprefix $(LWIPDIR)/,$(LWIP_EXCLUDE)),$(LWIPNOAPPSFILES))
LWIP_OBJS := $(patsubst $(LWIPDIR)/%.c,build/lwip/%.o,$(LWIP_SRCS))

build/lwip/%.o: $(LWIPDIR)/%.c
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


OBJS := $(LWIP_OBJS) $(PORT_OBJS)


test: $(OBJS)
	$(CC) $(CFLAGS) $(addprefix -Wl$(comma),$(LDFLAGS)) -o $@ -Wl,-\( $(LIBS) $(OBJS) -Wl,-\)


.PHONY: clean
clean:
	rm -rf test build

comma = ,
