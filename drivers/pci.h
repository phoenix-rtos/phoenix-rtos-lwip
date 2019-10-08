#ifndef PCIBUS_H_
#define PCIBUS_H_

#include <stdlib.h>


typedef struct {
	uint16_t devnum;
	uint16_t flags;
	uint32_t device_id;
	uint32_t subsystem_id;
	uint32_t class_rev;
} pci_device_t;

/* flags */
#define	PCIDEV_MMIO_ENABLED	0x0001
#define	PCIDEV_IRQ_ENABLED	0x0002
#define	PCIDEV_BUSMASTER	0x0004
#define	PCIDEV_BRIDGE		0x0008
#define	PCIDEV_MULTIFN		0x8000


static inline uint16_t pci_makeDevNum(uint8_t bus, uint8_t dev, uint8_t fn)
{
	return (bus << 8) | ((dev & 0x1F) << 3) | (fn & 7);
}


#define PCI_DEVNUM_FMT "%02x:%02x.%u"
#define PCI_DEVNUM_ARGS(d) ((d) >> 8), (((d) >> 3) & 0x1f), ((d) & 7)


int pci_parseDevnum(const char *str);


uint32_t pci_configRead(uint16_t devnum, uint16_t addr);
uint64_t pci_configReadBAR(uint16_t devnum, int bar);
void pci_configWrite(uint16_t devnum, uint16_t addr, uint32_t value);


volatile void *pci_mapMemBAR(uint16_t devnum, int bar);
void pci_setBusMaster(uint16_t devnum, int enable);


/* driver main() */

typedef int (*init_device_f)(uint16_t devnum, int irq);
typedef int (*poll_device_f)(void);
int pci_driver(int argc, char **argv, init_device_f init, poll_device_f poll);


#endif /* PCIBUS_H_ */
