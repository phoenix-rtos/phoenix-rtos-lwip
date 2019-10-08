#include <stdio.h>
#include "pci.h"
#include "physmmap.h"


int pci_parseDevnum(const char *s)
{
	unsigned int bus, dev, fn;

	if (sscanf(s, "%x:%x.%u", &bus, &dev, &fn) != 3)
		return -1;

	if (bus > 0xFF || dev > 0x1F || fn > 7)
		return -1;

	return pci_makeDevNum(bus, dev, fn);
}


void pci_setBusMaster(uint16_t devnum, int enable)
{
	uint32_t cmds;

	cmds = pci_configRead(devnum, 0x04);
	cmds |= 0x04;
	pci_configWrite(devnum, 0x04, cmds);
}


volatile void *pci_mapMemBAR(uint16_t devnum, int bar)
{
	volatile void *p;
	uint32_t sz, pa;
	uint64_t v;

	v = pci_configReadBAR(devnum, bar);
	sz = v >> 32;
	pa = v;

	if (!sz)
		return NULL;

	p = physmmap(pa, sz + 1);
	if (p == MAP_FAILED)
		return NULL;

	return p;
}
