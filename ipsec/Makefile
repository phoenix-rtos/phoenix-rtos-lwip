#
# Makefile for phoenix-rtos-lwip
#
# Copyright 2019-2021 Phoenix Systems
#
# %LICENSE%
#

IPSEC_SRCS := aes.c ah.c des.c esp.c ipsec.c ipsecdev.c key_sockets.c mbuff.c md5.c md5_imp.c sa.c sadb.c sha1.c sha1_imp.c sha256.c util.c

NAME := lwip-ipsec
LOCAL_SRCS := $(IPSEC_SRCS)
LICENSE := BSD-3-Clause AND OpenSSL AND LicenseRef-Public-Domain
LOCAL_SBOM := sbom.json
include $(static-lib.mk)
