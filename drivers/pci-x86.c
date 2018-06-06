#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arch/ia32/io.h>
#include "pci.h"


#define IO_PCICONF_ADDRESS (void *)0xCF8
#define IO_PCICONF_DATA (void *)0xCFC


static inline u32 pci_configSelector(u16 devnum, u16 addr)
{
	return 0x80000000 | ((addr & 0xF00) << 16) | (devnum << 8) | (addr & 0xFC);
}


u32 pci_configRead(u16 devnum, u16 addr)
{
	outl(IO_PCICONF_ADDRESS, pci_configSelector(devnum, addr));
	return inl(IO_PCICONF_DATA);
}


u64 pci_configReadBAR(u16 devnum, int bar)
{
	u32 addr, sz, cfg = pci_configSelector(devnum, 0x10 + bar * 4);
	u32 io = (u32)IO_PCICONF_ADDRESS;

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
	return ~sz ? ((u64)sz << 32) | addr : 0;
}


void pci_configWrite(u16 devnum, u16 addr, u32 value)
{
	outl(IO_PCICONF_ADDRESS, pci_configSelector(devnum, addr));
	outl(IO_PCICONF_DATA, value);
}
