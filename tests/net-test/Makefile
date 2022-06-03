#
# Makefile for phoenix-rtos-posixsrv
#
# Copyright 2018 Phoenix Systems
#
# %LICENSE%
#

SIL ?= @
MAKEFLAGS += --no-print-directory

# Compliation options for various architectures
TARGET_FAMILY = $(firstword $(subst -, ,$(TARGET)-))
include Makefile.$(TARGET_FAMILY)

### output target and sources ###
PROG := net-test
SRCS := $(wildcard src/*.c)
#LDLIBS := -ltty $(LDLIBS)

### build/install dirs ###
PREFIX_BUILD ?= ../_build/$(TARGET)
PREFIX_BUILD := $(abspath $(PREFIX_BUILD))
BUILD_DIR ?= $(PREFIX_BUILD)/$(notdir $(TOPDIR))
BUILD_DIR := $(abspath $(BUILD_DIR))

PREFIX_O := $(BUILD_DIR)/$(PROG)/
PREFIX_A ?= $(PREFIX_BUILD)/lib/
PREFIX_H ?= $(PREFIX_BUILD)/include/
PREFIX_PROG ?= $(PREFIX_BUILD)/prog/
PREFIX_PROG_STRIPPED ?= $(PREFIX_BUILD)/prog.stripped/

# setup paths
CFLAGS += -I$(PREFIX_H)
LDFLAGS += -L$(PREFIX_A)

### intermediate targets ###
PROG_OBJS += $(patsubst %,$(PREFIX_O)%,$(SRCS:.c=.o))
PROG_UNSTRIPPED := $(patsubst %,$(PREFIX_PROG)%,$(PROG))
PROG_STRIPPED   := $(patsubst %,$(PREFIX_PROG_STRIPPED)%,$(PROG))

# try to resolve static libs to provice correct rebuild dependencies
PSMK_LDPATH := $(subst ",,$(patsubst -L%,%,$(filter -L%,$(LDFLAGS)))) $(shell $(CC) $(CFLAGS) -print-search-dirs |grep "libraries: " |tr : " ")
PSMK_RESOLVED_LDLIBS := $(filter-out -l%,$(LDLIBS)) $(foreach lib,$(patsubst -l%,lib%.a,$(LDLIBS)),$(foreach ldpath,$(PSMK_LDPATH),$(wildcard $(ldpath)/$(lib))))

# generic rules
$(PREFIX_O)%.o: %.c
	@mkdir -p $(@D)
	$(SIL)(printf " CC  %-24s\n" "$<")
	$(SIL)$(CC) -c $(CFLAGS) "$<" -o "$@"
	$(SIL)$(CC) -M  -MD -MP -MF $(PREFIX_O)$*.c.d -MT "$@" $(CFLAGS) $<


$(PROG_UNSTRIPPED): $(PROG_OBJS) $(PSMK_RESOLVED_LDLIBS)
	@mkdir -p $(@D)
	@(printf " LD  %-24s\n" "$(@F)")
	$(SIL)$(LD) $(LDFLAGS) -o "$@" $(PROG_OBJS) $(LDLIBS)

$(PROG_STRIPPED): $(PROG_UNSTRIPPED)
	@mkdir -p $(@D)
	@(printf " STR %-24s  \n" "$(@F)")
	$(SIL)$(STRIP) -s -o "$@" "$<"


### default target ###
# suppress 'nothing to be done'
all: $(PROG_UNSTRIPPED) $(PROG_STRIPPED) $(PROG_OBJS)
	@echo > /dev/null;

clean:
	$(SIL)rm -rf build*

# include file dependencies
ALL_D := $(wildcard $(PREFIX_O)*.d)
-include $(ALL_D)

.PHONY: all clean
