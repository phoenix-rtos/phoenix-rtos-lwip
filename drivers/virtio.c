/*
 * Phoenix-RTOS --- networking stack
 *
 * virtio net device driver
 *
 * Copyright 2019 Phoenix Systems
 * Author: Kamil Amanowicz
 *
 * %LICENSE%
 */
#include "netif-driver.h"
#include "lwip/netifapi.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arch.h>
#include <errno.h>
#include <limits.h>

#include <sys/threads.h>
#include <sys/msg.h>
#include <sys/interrupt.h>
#include <sys/platform.h>
#include <sys/mman.h>

#include <arch/ia32/io.h>
#include <phoenix/arch/ia32.h>

#include "virtio.h"

//#define TRACE(msg, ...)
#define TRACE(msg, ...) do { printf(__FILE__ ":%d - " msg "\n", __LINE__, ##__VA_ARGS__ ); } while (0)
#define DTRACE(msg, ...) do { printf(__FILE__ ":%d - " msg "\n", __LINE__, ##__VA_ARGS__ ); } while (0)

#define VIRTIO_DEV(dev) ((virtio_device_t *)dev)
#define VIRTIO_PCI(dev) ((virtio_pci_device_t *)dev)

#define VIRTIO_BUFF_SIZE 1526

static virtio_pci_id_t virtio_pci_tbl[] = {
	{ VIRTIO_PCI_VENDOR_ID, VIRTIO_PCI_DEV_ID_NET, PCI_ANY, PCI_ANY, PCI_ANY},
	{ VIRTIO_PCI_VENDOR_ID, VIRTIO_PCI_TRANS_DEV_ID_NET, PCI_ANY, PCI_ANY, PCI_ANY}
};

/*  memory barrier */
#define MB() do { __builtin_ia32_mfence(); } while(0)
/* read memory barrier */
#define RMB() do { __builtin_ia32_lfence(); } while(0)
/* write memory barrier */
#define WMB() do { __builtin_ia32_sfence(); } while(0)


struct virtio_pci_net_config {
	uint8_t mac[6];
	volatile uint16_t status;
	volatile uint16_t max_virtqueue_pairs;
	volatile uint16_t mtu;
};


typedef struct virtio_pci_net_device {
	virtio_pci_device_t virtio_pci_dev;

	struct netif *netif;
	struct virtio_pci_net_config *net_cfg;

	uint8_t isr_status;

	struct virtq tx;
	struct virtq rx;

	char irqStack[4096];

	handle_t rx_cond;
	handle_t rx_lock;
	handle_t tx_lock;
	handle_t inth;

	uint32_t net_hdr_size;

} virtio_pci_net_device_t;


int virtio_pciGetCap(virtio_pci_device_t *dev, const uint8_t type, void **data, const size_t sz)
{
	struct virtio_pci_cap *cap;
	int i = 0;

	if (!(dev->pci_dev.status & (0x1 << 4)))
		return -ENOTSUP;

	cap = (struct virtio_pci_cap *)&dev->pci_cap_list.data[0];

	do {

		if (cap->cap_vndr != 0x09 || cap->cfg_type != type) {
			i++;
			cap = (struct virtio_pci_cap *)&dev->pci_cap_list.data[cap->cap_next];
			continue;
		}

		if (dev->bar[cap->bar] == NULL || cap->length < sz)
			return -EINVAL;

		if (type == VIRTIO_PCI_CAP_NOTIFY_CFG)
			*data = cap;
		else
			*data = dev->bar[cap->bar] + cap->offset;
		return EOK;

	} while ((addr_t)cap != (addr_t)&dev->pci_cap_list.data[0]);

	return -ENOENT;
}


static int virtio_initVirtq(virtio_device_t *dev, struct virtq *virtq)
{
	dev->common_cfg->queue_select = virtq->index;
	MB();

	if (!dev->common_cfg->queue_size || dev->common_cfg->queue_size < virtq->size)
		return -ENOTSUP;

	RMB();
	dev->common_cfg->queue_size = virtq->size;
	dev->common_cfg->queue_desc = (uint64_t)va2pa(virtq->desc);
	dev->common_cfg->queue_driver = (uint64_t)va2pa(virtq->avail);
	dev->common_cfg->queue_device = (uint64_t)va2pa(virtq->used);
	MB();
	dev->common_cfg->queue_enable = 1;
	return EOK;
}


static int virtio_pciInitVirtq(virtio_pci_device_t *dev, struct virtq *virtq)
{
	int res;

	if ((res = virtio_initVirtq(&dev->virtio_dev, virtq)))
		return res;

	dev->virtio_dev.common_cfg->queue_select = virtq->index;
	MB();
	virtq->notify_addr = (uint16_t *)(dev->bar[dev->virtio_dev.notify_cap->cap.bar] +
		dev->virtio_dev.notify_cap->cap.offset +
		(dev->virtio_dev.common_cfg->queue_notify_off * dev->virtio_dev.notify_cap->notify_off_multiplier));

	return EOK;
}


static int virtio_freeVirtq(struct virtq *virtq)
{
	int i = 0;
	munmap(virtq->desc, _PAGE_SIZE);
	munmap(virtq->avail, _PAGE_SIZE);
	munmap(virtq->used, _PAGE_SIZE);

	for (i = 0; i < virtq->size - 1; i += 2)
		munmap((void *)virtq->vbuffs[i], _PAGE_SIZE);

	free(virtq->vbuffs);
	free(virtq->pbuffs);

	virtq->size = 0;

	return EOK;;
}


static int virtio_allocVirtqDesc(struct virtq *virtq)
{
	int i;

	for (i = 0; i < virtq->size - 1; i += 2) {
		virtq->vbuffs[i] = (addr_t)mmap(NULL, _PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_UNCACHED | MAP_ANONYMOUS, -1, 0);

		if (!virtq->vbuffs[i])
			return -ENOMEM;

		memset((void *)virtq->vbuffs[i], 0, _PAGE_SIZE);
		virtq->vbuffs[i + 1] = (addr_t)(virtq->vbuffs[i] + _PAGE_SIZE / 2);
		virtq->pbuffs[i] = (addr_t)va2pa((void *)virtq->vbuffs[i]);
		virtq->pbuffs[i + 1] = (addr_t)va2pa((void *)virtq->vbuffs[i + 1]);
	}
	return EOK;
}


static int virtio_allocVirtq(struct virtq *virtq, const uint16_t idx, const uint16_t size)
{
	if (size > VIRTQ_MAX_SIZE)
		return -ERANGE;

	if (size % 2)
		return -EINVAL;

	virtq->index = idx;
	virtq->size = size;
	virtq->last = 0;
	virtq->desc = mmap(NULL, _PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_UNCACHED | MAP_ANONYMOUS, -1, 0);
	virtq->avail = mmap(NULL, _PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_UNCACHED | MAP_ANONYMOUS, -1, 0);
	virtq->used = mmap(NULL, _PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_UNCACHED | MAP_ANONYMOUS, -1, 0);

	virtq->vbuffs = calloc(VIRTQ_MAX_SIZE, sizeof(addr_t));
	virtq->pbuffs = calloc(VIRTQ_MAX_SIZE, sizeof(addr_t));

	if (!virtq->desc || !virtq->avail || !virtq->used || !virtq->pbuffs || !virtq->vbuffs) {
		munmap(virtq->desc, _PAGE_SIZE);
		munmap(virtq->avail, _PAGE_SIZE);
		munmap(virtq->used, _PAGE_SIZE);
		free(virtq->vbuffs);
		free(virtq->pbuffs);
		return -ENOMEM;
	}

	if (virtio_allocVirtqDesc(virtq)) {
		virtio_freeVirtq(virtq);
		return -ENOMEM;
	}

	virtq->buff_size = VIRTIO_BUFF_SIZE;

	memset(virtq->desc, 0, _PAGE_SIZE);
	memset(virtq->avail, 0, _PAGE_SIZE);
	memset(virtq->used, 0, _PAGE_SIZE);
	return EOK;
}


static int virtio_pciSetVirtq(virtio_pci_device_t *dev, struct virtq *virtq, uint16_t idx, uint16_t size)
{
	int res;

	if ((res = virtio_allocVirtq(virtq, idx, size)))
		return res;

	if ((res = virtio_pciInitVirtq(dev, virtq))) {
		virtio_freeVirtq(virtq);
		return res;
	}
	return EOK;
}


static int virtio_pciNetSetVirtq(virtio_pci_net_device_t *dev)
{
	int res;

	if ((res = virtio_pciSetVirtq(&dev->virtio_pci_dev, &dev->rx, 0, VIRTQ_MAX_SIZE)))
		return res;


	if ((res = virtio_pciSetVirtq(&dev->virtio_pci_dev, &dev->tx, 1, VIRTQ_MAX_SIZE)))
		return res;

	/* turn off interrupt for tx */
	dev->tx.avail->flags = VIRTQ_AVAIL_F_NO_INTERRUPT;

	return EOK;
}


static void virtio_pciNetNotify(virtio_pci_net_device_t *dev, struct virtq *virtq)
{
	uint32_t base;

	base = (uint32_t)VIRTIO_PCI(dev)->pci_dev.resources[0].base;

	if (VIRTIO_PCI(dev)->legacy)
		outw((void *)(base + VIRTIO_CFG_VQ_NOTI), virtq->index);
	else
		*virtq->notify_addr = virtq->index;
	WMB();
}

static uint8_t virtio_pciGetIsrStatus(virtio_pci_device_t *dev);

static err_t virtio_netifOutput(struct netif *netif, struct pbuf *p)
{
	virtio_pci_net_device_t *dev = (virtio_pci_net_device_t *)netif->state;
	struct virtq *tx = &dev->tx;
	uint32_t tot_len, avail, len = 0;
	struct virtio_net_hdr *hdr;

	mutexLock(dev->tx_lock);
	avail = tx->avail->idx;
	TRACE("output avail %u used %u", avail, tx->used->idx % tx->size);
	if ((avail + 1) % tx->size == tx->used->idx % tx->size) {
		/* tx ring is full. TODO: handle it */
		DTRACE("tx full");
		return -ERANGE;
	}

	if (p->tot_len > VIRTIO_BUFF_SIZE - dev->net_hdr_size) {
		/* TODO: handle it */
		DTRACE("pbuf too big");
		return -ERANGE;
	}

	tot_len = p->tot_len;
	len = 0;
	memset((void *)(tx->vbuffs[avail % tx->size]), 0, VIRTIO_BUFF_SIZE);
	hdr = (struct virtio_net_hdr *)tx->vbuffs[avail % tx->size];
	hdr->flags = 0;
	hdr->gso_type = VIRTIO_NET_HDR_GSO_NONE;
	hdr->num_buffers = 0;

	while (tot_len) {

		memcpy((void *)(tx->vbuffs[avail % tx->size] + dev->net_hdr_size + len), p->payload, p->len);
		tot_len -= p->len;
		len += p->len;
		if (tot_len) {
			p = p->next;
			if (!p) {
				DTRACE("unexpected pbuf end");
				mutexUnlock(dev->tx_lock);
				return -EINVAL;
			}
		}
	}

	if (len < 60)
		len = 60;
	len += dev->net_hdr_size;

/*	int i;
	printf("transmit pkt %u\n", len);
	for (i = 0; i < len; i++) {
		if (i && !(i % 12))
			printf("\n");
		printf ("0x%02x ", *(uint8_t *)(tx->vbuffs[avail % tx->size] + i));
	}
*/
	WMB();
	RMB();
	tx->desc[avail % tx->size].addr = tx->pbuffs[avail % tx->size];
	tx->desc[avail % tx->size].len = len;
	tx->desc[avail % tx->size].flags = 0;
	tx->avail->ring[avail % tx->size] = avail % tx->size;
	
	WMB();
	RMB();
	tx->avail->idx++;
	WMB();
	RMB();
	mutexUnlock(dev->tx_lock);

	if (!tx->used->flags)
		virtio_pciNetNotify(dev, tx);

	return ERR_OK;
}


static void virtio_freePbuf(struct pbuf *p)
{
	memset(p->payload, 0, VIRTIO_BUFF_SIZE);
	mem_free(p);
	return;
}


static void virtio_netRefillRx(virtio_pci_net_device_t *dev)
{
	struct virtio_net_hdr *hdr;
	struct pbuf_custom *pc;
	struct pbuf *p;
	struct virtq *rx = &dev->rx;
	uint16_t used;

	used = rx->used->idx;
	while ((rx->last) % rx->size != used % rx->size) {
		TRACE("incoming used idx %u last id %u packet id %u len %u", used, rx->last, rx->used->ring[rx->last % rx->size].id, rx->used->ring[rx->last % rx->size].len);

		if (VIRTIO_DEV(dev)->features & VIRTIO_NET_F_MRG_RXBUF) {
			hdr = (struct virtio_net_hdr *)rx->vbuffs[rx->last % rx->size];
			if (hdr->num_buffers > 1)
				DTRACE("DANGER DANGER - SPLIT PACKET");
		}

		pc = mem_malloc(sizeof(*pc));
		pc->custom_free_function = virtio_freePbuf;
		//TRACE("vbuff 0x%p", rx->vbuffs[rx->last % rx->size] + 12);
		p = pbuf_alloced_custom(PBUF_RAW, 
				rx->used->ring[rx->last % rx->size].len - dev->net_hdr_size,
				PBUF_REF, pc,
				(void *)rx->vbuffs[rx->last % rx->size] + dev->net_hdr_size,
				VIRTIO_BUFF_SIZE - dev->net_hdr_size);

		if (p == NULL) {
			DTRACE("pbuf alloc failed");
			mem_free(pc);
			return;
		}
/*
		uint16_t i;
		printf("received pbuf %u\n", p->tot_len);
		for (i = 0; i < p->tot_len; i++) {
			if (i && !(i % 12))
				printf("\n");
			printf ("0x%02x ", *(uint8_t *)(p->payload + i));
		}
*/

		if (dev->netif->input(p, dev->netif) != ERR_OK) {
			DTRACE("error on netif input");
			mem_free(pc);
		}
		rx->desc[rx->last % rx->size].flags = VIRTQ_DESC_F_WRITE;
		rx->last++;
		used = rx->used->idx;
	}
	WMB();
	RMB();
	rx->avail->idx++;
	WMB();
	RMB();
	if (!rx->used->flags)
		virtio_pciNetNotify(dev, rx);
}


static void virtio_netFillRx(virtio_pci_net_device_t *dev)
{
	struct virtq *rx = &dev->rx;
	uint16_t avail;

	/* rx is empty */
	if (rx->used->idx % rx->size == rx->avail->idx % rx->size) {
		avail = rx->used->idx;
		do {
			/* prep rx buffs */
			rx->desc[avail % rx->size].addr = rx->pbuffs[avail % rx->size] & 0xFFFFFFFF;
			rx->desc[avail % rx->size].len = VIRTIO_BUFF_SIZE;
			rx->desc[avail % rx->size].flags = VIRTQ_DESC_F_WRITE;
			rx->avail->ring[avail % rx->size] = avail % rx->size;
			avail++;
		} while ((avail) % rx->size != rx->used->idx % rx->size);

		WMB();
		RMB();
		rx->avail->idx = avail - 1 % rx->size;
		MB();
		RMB();

		if (!rx->used->flags)
			virtio_pciNetNotify(dev, rx);
	}
}


static void virtio_pciSetStatus(virtio_pci_device_t *dev, const uint8_t status)
{
	uint32_t base;

	base = (uint32_t)VIRTIO_PCI(dev)->pci_dev.resources[0].base;
	if (dev->legacy) {
		outb((void *)(base + VIRTIO_CFG_DEVICE_STATUS), status);
		RMB();
		if (status == VIRTIO_RST) {
			while(inb((void *)(base + VIRTIO_CFG_DEVICE_STATUS))) sleep(100000);
		}
	} else {
		dev->virtio_dev.common_cfg->device_status = status;
		if (status == VIRTIO_RST) {
			WMB();
			while (dev->virtio_dev.common_cfg->device_status) sleep(100000);
		}
	}
	WMB();
}


static int virtio_pciInitDevice(virtio_pci_device_t *dev)
{
	int i;
	unsigned int base, size, idx;

	TRACE("%s DEVICE", dev->pci_dev.revision ? "MODERN" : "LEGACY");
	if (!dev->pci_dev.revision)
		dev->legacy = 1;
	else
		dev->legacy = 0;

	memset(dev->bar, 0, sizeof(dev->bar));

	/* init bars */
	for (i = 0; i < 6; i++) {
		/* check if bar is used */
		if (dev->pci_dev.resources[i].base && dev->pci_dev.resources[i].limit) {
			TRACE("BAR[%d] = b 0x%lx f 0x%x l 0x%lx", i, dev->pci_dev.resources[i].base,
				dev->pci_dev.resources[i].flags, dev->pci_dev.resources[i].limit);
			/* check if it is mm bar */
			if (!(dev->pci_dev.resources[i].flags & 1)) {

				base = dev->pci_dev.resources[i].base;
				size = dev->pci_dev.resources[i].limit;
				idx = i;

				/* check if bar is 64 bit */
				if (dev->pci_dev.resources[i].flags & (1 << 2)) {

					/* panic check - it should not happen */
					if (i >= 5)
						return -EINVAL;

					/* it can be 64 bit address but it may fit to 32-bit address space if
					* upper bits are not set and base + size won't cause uint overflow */
					if (dev->pci_dev.resources[i + 1].base || base > base + size)
						return -ENOTSUP;

					/* skip next bar */
					i++;
				}

				/* map the bar */
				size = (size + (_PAGE_SIZE - 1)) & ~(_PAGE_SIZE - 1);
				dev->bar[idx] = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_DEVICE | MAP_UNCACHED, FD_PHYSMEM, base);

				if (!dev->bar[idx])
					return -ENOMEM;

				/* if there is mm bar we assume device is transitional */
				//if (dev->legacy)
				//	dev->legacy = 0;
			}
		}
	}

	if (!dev->legacy) {
		/* get common caps */
		if (virtio_pciGetCap(dev, VIRTIO_PCI_CAP_COMMON_CFG, (void **)&dev->virtio_dev.common_cfg, sizeof(struct virtio_pci_common_cfg))) {
			DTRACE("common config error");
			return -EINVAL;
		}

		/* get isr */
		dev->virtio_dev.isr.size = 1;
		if (virtio_pciGetCap(dev, VIRTIO_PCI_CAP_ISR_CFG, (void **)&dev->virtio_dev.isr.base, dev->virtio_dev.isr.size)) {
			DTRACE("isr config error");
			return -EINVAL;
		}

		if (virtio_pciGetCap(dev, VIRTIO_PCI_CAP_NOTIFY_CFG, (void **)&dev->virtio_dev.notify_cap, sizeof(struct virtio_pci_notify_cap))) {
			DTRACE("noti config error");
			return -EINVAL;
		}
	}

	RMB();
	virtio_pciSetStatus(dev, VIRTIO_RST);
	MB();
	RMB();
	virtio_pciSetStatus(dev, VIRTIO_ACK);
	MB();
	RMB();
	virtio_pciSetStatus(dev, VIRTIO_DRV);
	MB();
	RMB();
	return EOK;
}


static uint8_t virtio_pciGetIsrStatus(virtio_pci_device_t *dev)
{
	uint32_t base;

	if (!dev->legacy)
		return *dev->virtio_dev.isr.base;

	base = (uint32_t)dev->pci_dev.resources[0].base;
	return inb((void *)(base + VIRTIO_CFG_ISR_STATUS));
}


static int virtio_irqHandler(unsigned int irq, void *virtio_pci_net_dev)
{
	virtio_pci_net_device_t *dev = (virtio_pci_net_device_t *)virtio_pci_net_dev;
	/* read the satus */
	dev->isr_status	= virtio_pciGetIsrStatus(VIRTIO_PCI(dev));
	/* diable interrupts */
	dev->rx.avail->flags |= VIRTQ_AVAIL_F_NO_INTERRUPT;
	return 0;
}


static void virtio_irqThread(void *virtio_pci_net_dev)
{
	virtio_pci_net_device_t *dev = (virtio_pci_net_device_t *)virtio_pci_net_dev;

	while (1) {
		mutexLock(dev->rx_lock);
		while (!dev->isr_status) {
			condWait(dev->rx_cond, dev->rx_lock, 0);
		}

		virtio_netRefillRx(dev);

		dev->isr_status = 0;
		dev->rx.avail->flags &= ~VIRTQ_AVAIL_F_NO_INTERRUPT;
		WMB();
		mutexUnlock(dev->rx_lock);
	}
}


static int virtio_pciNetCompleteInit(virtio_pci_net_device_t *dev)
{
	int res;
	uint32_t features;

	if (virtio_pciGetCap(VIRTIO_PCI(dev), VIRTIO_PCI_CAP_DEVICE_CFG, (void **)&dev->net_cfg, sizeof(struct virtio_pci_net_config))) {
		DTRACE("net config error");
		VIRTIO_DEV(dev)->common_cfg->device_status = VIRTIO_FAILED;
		return -EINVAL;
	}

	VIRTIO_DEV(dev)->common_cfg->device_feature_select = 0;
	VIRTIO_DEV(dev)->common_cfg->driver_feature_select = 0;
	features = VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS;
	MB();

	if (!(VIRTIO_PCI(dev)->pci_dev.revision) && !(features & VIRTIO_NET_F_MRG_RXBUF))
		dev->net_hdr_size = VIRTIO_NET_HDR_SIZE_LEGACY;
	else
		dev->net_hdr_size = VIRTIO_NET_HDR_SIZE;

	TRACE("features 0x%x", VIRTIO_DEV(dev)->common_cfg->device_feature);
	if ((VIRTIO_DEV(dev)->common_cfg->device_feature & features) != features) {
		DTRACE("Unsupported device");
		VIRTIO_DEV(dev)->common_cfg->device_status = VIRTIO_FAILED;
		return -ENOTSUP;
	}

	VIRTIO_DEV(dev)->common_cfg->driver_feature = features;
	VIRTIO_DEV(dev)->common_cfg->device_status = VIRTIO_FEAT_OK;
	MB();
	if (VIRTIO_DEV(dev)->common_cfg->device_status != VIRTIO_FEAT_OK) {
		DTRACE("Cannot support this device");
		VIRTIO_DEV(dev)->common_cfg->device_status = VIRTIO_FAILED;
		return -ENOSYS;
	}

	/* set virtqueues */
	res = virtio_pciNetSetVirtq(dev);
	return res;
}


static int virtio_pciNetCompleteInitLegacy(virtio_pci_net_device_t *dev)
{
	uint32_t feature, offset, base = (uint32_t)VIRTIO_PCI(dev)->pci_dev.resources[0].base;
	char *tx, *rx;

	feature = inl((void *)(base + VIRTIO_CFG_DEVICE_FEATURE));
	VIRTIO_DEV(dev)->features = VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS | VIRTIO_NET_F_MRG_RXBUF;

	VIRTIO_DEV(dev)->features &= feature;

	TRACE("DEVICE FEATURES 0x%x", feature);
	if (!(VIRTIO_DEV(dev)->features & VIRTIO_NET_F_MRG_RXBUF))
		dev->net_hdr_size = VIRTIO_NET_HDR_SIZE_LEGACY;
	else
		dev->net_hdr_size = VIRTIO_NET_HDR_SIZE;

	outl((void *)(base + VIRTIO_CFG_DRIVER_FEATURE), VIRTIO_DEV(dev)->features);
	MB();
	TRACE("negotiated features 0x%x should be 0x%llx", inl((void *)(base + VIRTIO_CFG_DRIVER_FEATURE)), VIRTIO_DEV(dev)->features);

	rx = mmap(NULL, 3 * _PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_UNCACHED | MAP_ANONYMOUS | MAP_CONTIGUOUS, -1, 0);
	tx = mmap(NULL, 3 * _PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_UNCACHED | MAP_ANONYMOUS | MAP_CONTIGUOUS, -1, 0);

	if (!rx || !tx) {
		DTRACE("virtq mmap failed");
		munmap(rx, 3 * _PAGE_SIZE);
		munmap(tx, 3 * _PAGE_SIZE);
		return -ENOMEM;
	}

	memset(rx, 0, 3 * _PAGE_SIZE);
	memset(tx, 0, 3 * _PAGE_SIZE);

	dev->rx.desc = (struct virtq_desc *)rx;
	dev->rx.avail = (struct virtq_avail *)(rx + _PAGE_SIZE);
	dev->rx.used = (struct virtq_used *)(rx + 2 * _PAGE_SIZE);

	TRACE("rx addr check desc 0x%p avail 0x%p used 0x%p", (void *)va2pa(dev->rx.desc),
		(void *)va2pa(dev->rx.avail), (void *)va2pa(dev->rx.used));

	dev->tx.desc = (struct virtq_desc *)tx;
	dev->tx.avail = (struct virtq_avail *)(tx + _PAGE_SIZE);
	dev->tx.used = (struct virtq_used *)(tx + 2 * _PAGE_SIZE);

	TRACE("tx addr check desc 0x%p avail 0x%p used 0x%p", (void *)va2pa(dev->tx.desc),
		(void *)va2pa(dev->tx.avail), (void *)va2pa(dev->tx.used));

	dev->tx.avail->flags = VIRTQ_AVAIL_F_NO_INTERRUPT;

	dev->rx.index = 0;
	dev->tx.index = 1;

	dev->rx.size = VIRTQ_LEGACY_MAX_SIZE;
	dev->tx.size = VIRTQ_LEGACY_MAX_SIZE;

	dev->rx.vbuffs = calloc(VIRTQ_LEGACY_MAX_SIZE, sizeof(addr_t));
	dev->rx.pbuffs = calloc(VIRTQ_LEGACY_MAX_SIZE, sizeof(addr_t));
	dev->tx.vbuffs = calloc(VIRTQ_LEGACY_MAX_SIZE, sizeof(addr_t));
	dev->tx.pbuffs = calloc(VIRTQ_LEGACY_MAX_SIZE, sizeof(addr_t));

	dev->rx.last = 0;
	dev->tx.last = 0;

	if (virtio_allocVirtqDesc(&dev->rx) || virtio_allocVirtqDesc(&dev->tx)) {
		/* TODO: handle it nicely */
		DTRACE("virtq desc alloc failed");
		return -ENOMEM;
	}

	/* get device specific config */
	dev->net_cfg = malloc(sizeof(struct virtio_pci_net_config));
	if (!dev->net_cfg) {
		DTRACE("net cfg alloc failed");
		return -ENOMEM;
	}

	offset = VIRTIO_CFG_DEVICE_SPEC;
	dev->net_cfg->mac[0] = inb((void *)(base + offset++));
	dev->net_cfg->mac[1] = inb((void *)(base + offset++));
	dev->net_cfg->mac[2] = inb((void *)(base + offset++));
	dev->net_cfg->mac[3] = inb((void *)(base + offset++));
	dev->net_cfg->mac[4] = inb((void *)(base + offset++));
	dev->net_cfg->mac[5] = inb((void *)(base + offset++));
	dev->net_cfg->status = inw((void *)(base + offset));
//	offset +=2;
//	dev->net_cfg->max_virtqueue_pairs = inw((void *)(base + offset));
//	offset +=2;
//	dev->net_cfg->mtu = inw((void *)(base + offset));

	RMB();
	outw((void *)(base + VIRTIO_CFG_VQ_SEL), 0);
	WMB();
	RMB();
	outl((void *)(base + VIRTIO_CFG_VQ_ADDR), va2pa(rx) / _PAGE_SIZE);
	WMB();
	RMB();
	outw((void *)(base + VIRTIO_CFG_VQ_SEL), 1);
	WMB();
	RMB();
	outl((void *)(base + VIRTIO_CFG_VQ_ADDR), va2pa(tx) / _PAGE_SIZE);
	WMB();
	RMB();
	return EOK;
}


static int virtio_pciNetInitDevice(virtio_pci_net_device_t *dev)
{
	int res;

	if ((res = virtio_pciInitDevice(VIRTIO_PCI(dev))))
		return res;

	if (!VIRTIO_PCI(dev)->legacy) {
		if ((res = virtio_pciNetCompleteInit(dev))) {
			DTRACE("COMPLETE INIT FAILED");
			return res;
		}
	}
	else if ((res = virtio_pciNetCompleteInitLegacy(dev))) {
		DTRACE("COMPLETE INIT FAILED");
		return res;
	}

	/* fill rx buffer */
	virtio_netFillRx(dev);

	condCreate(&dev->rx_cond);
	mutexCreate(&dev->rx_lock);
	mutexCreate(&dev->tx_lock);

	beginthread(virtio_irqThread, 0, (void *)dev->irqStack, sizeof(dev->irqStack), dev);
	interrupt(VIRTIO_PCI(dev)->pci_dev.irq, virtio_irqHandler, (void *)dev, dev->rx_cond, &dev->inth);

	/* tell the device that we are ready for action */
	MB();
	RMB();
	virtio_pciSetStatus(VIRTIO_PCI(dev), VIRTIO_DRV_OK);
	MB();
	return res;
}


static int virtio_netifInit(struct netif *netif, char *cfg)
{
	int i, res = -ENODEV;
	virtio_pci_net_device_t *net_dev;
	platformctl_t pctl = { 0 };

	netif->linkoutput = virtio_netifOutput;

	net_dev = netif->state;
	net_dev->netif = netif;

	pctl.pci.cap_list = &net_dev->virtio_pci_dev.pci_cap_list;

	pctl.action = pctl_get;
	pctl.type = pctl_pci;

	for (i = 0; i < sizeof(virtio_pci_tbl)/sizeof(virtio_pci_tbl[0]); i++) {
		pctl.pci.id = virtio_pci_tbl[i];
		if ((res = platformctl(&pctl)) != EOK)
			continue;

		net_dev->virtio_pci_dev.pci_dev = pctl.pci.dev;

		if ((res = virtio_pciNetInitDevice(net_dev)))
			return res;

		break;
	}

	memcpy(net_dev->netif->hwaddr, net_dev->net_cfg->mac, net_dev->netif->hwaddr_len);

	net_dev->netif->mtu = 1500;

	DTRACE("virtio init %s [ %d ]", !res ? "OK" : "FAILED", res);
	return res;
}


static netif_driver_t virtio_drv = {
	.init = virtio_netifInit,
	.state_sz = sizeof(virtio_pci_net_device_t),
	.state_align = _Alignof(virtio_pci_net_device_t),
	.name = "virtio",
};


__constructor__(1000)
void register_driver_virtio(void)
{
	register_netif_driver(&virtio_drv);
}