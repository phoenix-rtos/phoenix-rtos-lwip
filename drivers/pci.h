#ifndef PCIBUS_H_
#define PCIBUS_H_

#include <stdlib.h>


typedef struct {
	u16 devnum;
	u16 flags;
	u32 device_id;
	u32 subsystem_id;
	u32 class_rev;
} pci_device_t;

/* flags */
#define	PCIDEV_MMIO_ENABLED	0x0001
#define	PCIDEV_IRQ_ENABLED	0x0002
#define	PCIDEV_BUSMASTER	0x0004
#define	PCIDEV_BRIDGE		0x0008
#define	PCIDEV_MULTIFN		0x8000


static inline u16 pci_makeDevNum(u8 bus, u8 dev, u8 fn)
{
	return (bus << 8) | ((dev & 0x1F) << 3) | (fn & 7);
}


#define PCI_DEVNUM_FMT "%02x:%02x.%u"
#define PCI_DEVNUM_ARGS(d) ((d) >> 8), (((d) >> 3) & 0x1f), ((d) & 7)


int pci_parseDevnum(const char *str);


u32 pci_configRead(u16 devnum, u16 addr);
u64 pci_configReadBAR(u16 devnum, int bar);
void pci_configWrite(u16 devnum, u16 addr, u32 value);


volatile void *pci_mapMemBAR(u16 devnum, int bar);
void pci_setBusMaster(u16 devnum, int enable);


/* driver main() */

typedef int (*init_device_f)(u16 devnum, int irq);
typedef int (*poll_device_f)(void);
int pci_driver(int argc, char **argv, init_device_f init, poll_device_f poll);


#endif /* PCIBUS_H_ */
