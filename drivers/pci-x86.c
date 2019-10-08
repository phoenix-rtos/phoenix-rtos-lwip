#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arch/ia32/io.h>
#include "pci.h"


#define IO_PCICONF_ADDRESS (void *)0xCF8
#define IO_PCICONF_DATA (void *)0xCFC


static inline uint32_t pci_configSelector(uint16_t devnum, uint16_t addr)
{
	return 0x80000000 | ((addr & 0xF00) << 16) | (devnum << 8) | (addr & 0xFC);
}


uint32_t pci_configRead(uint16_t devnum, uint16_t addr)
{
	outl(IO_PCICONF_ADDRESS, pci_configSelector(devnum, addr));
	return inl(IO_PCICONF_DATA);
}


uint64_t pci_configReadBAR(uint16_t devnum, int bar)
{
	uint32_t addr, sz, cfg = pci_configSelector(devnum, 0x10 + bar * 4);
	uint32_t io = (uint32_t)IO_PCICONF_ADDRESS;

	asm volatile (
		"cli;"
		"outl %0, %w2;"
		"addl $4, %2;"
		"inl %w2, %0;"
		"movl %0, %1;"
		"xorl %0, %0;"
		"notl %0;"
		"outl %0, %w2;"
		"inl %w2, %0;"
		"xchgl %0, %1;"
		"outl %0, %w2;"
		"sti"
	: "=a" (addr), "=&r" (sz), "+d" (io)
	: "0" (cfg)
	: "memory");

	sz = ~sz | (sz & 1 ? 0x3 : 0xf);
	return ~sz ? ((uint64_t)sz << 32) | addr : 0;
}


void pci_configWrite(uint16_t devnum, uint16_t addr, uint32_t value)
{
	outl(IO_PCICONF_ADDRESS, pci_configSelector(devnum, addr));
	outl(IO_PCICONF_DATA, value);
}
