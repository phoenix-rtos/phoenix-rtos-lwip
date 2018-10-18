#
# Makefile for Phoenix Networking
#

SRCS_ia32_pci = pci.c pci-x86.c physmmap.c
SRCS_util = bdring.c pktmem.c physmmap.c res-create.c
SRCS_ephy = ephy.c gpio.c imx6ull-gpio.c
SRCS_pppos = pppos.c


DRIVER_SRCS_common = netif-driver.c
DRIVER_SRCS_rtl = rtl8139cp.c $(SRCS_util) $(SRCS_ia32_pci)
DRIVER_SRCS_enet = imx6-enet.c $(SRCS_ephy) $(SRCS_util) hw-debug.c
DRIVER_SRCS_pppos = $(SRCS_pppos)
