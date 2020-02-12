/*
 * Phoenix-RTOS
 *
 * common virtio net device
 *
 * Copyright 2019 Phoenix Systems
 * Author: Kamil Amanowicz
 *
 * %LICENSE%
 */
#ifndef _LIBVIRTIO_H_
#define _LIBVIRTIO_H_

#include <stdint.h>
#include <arch/ia32/io.h>
#include <phoenix/arch/ia32.h>

/* device status - little misleading since some of them are set by a driver*/
#define VIRTIO_RST 				0
#define VIRTIO_ACK 				1
#define VIRTIO_DRV 				2
#define VIRTIO_FAILED 			128
#define VIRTIO_FEAT_OK 			8
#define VIRTIO_DRV_OK 			4
#define VIRTIO_DEV_NEEDS_RST 	64

/* virtio pci vendor id */
#define VIRTIO_PCI_VENDOR_ID 			0x1AF4

/* virtio pci net device id */
#define VIRTIO_PCI_DEV_ID_NET 			0x1041


/* virtio pci transitional net device id */
#define VIRTIO_PCI_TRANS_DEV_ID_NET 	0x1000

/* configuration types */
/* common configuration */
#define VIRTIO_PCI_CAP_COMMON_CFG 		1
/* notifications */
#define VIRTIO_PCI_CAP_NOTIFY_CFG 		2
/* ISR status */
#define VIRTIO_PCI_CAP_ISR_CFG 			3
/* device specific configuration */
#define VIRTIO_PCI_CAP_DEVICE_CFG		4
/* PCI configuration access */
#define VIRTIO_PCI_CAP_PCI_CFG			5


typedef pci_id_t virtio_pci_id_t;


struct virtio_pci_cap {
	uint8_t cap_vndr; 	/* Generic PCI field: PCI_CAP_ID_VNDR */
	uint8_t cap_next; 	/* Generic PCI field: next ptr. */
	uint8_t cap_len; 	/* Generic PCI field: capability length */
	uint8_t cfg_type; 	/* Identifies the structure. */
	uint8_t bar; 		/* Where to find it. */
	uint8_t padding[3]; /* Pad to full dword. */
	uint32_t offset; 	/* Offset within bar. */
	uint32_t length; 	/* Length of the structure, in bytes. */
}__attribute__((packed));


struct virtio_pci_common_cfg {
	/* About the whole device. */
	uint32_t device_feature_select; 	/* read-write */
	uint32_t device_feature; 			/* read-only for driver */
	uint32_t driver_feature_select; 	/* read-write */
	uint32_t driver_feature; 			/* read-write */
	uint16_t msix_config; 				/* read-write */
	uint16_t num_queues; 				/* read-only for driver */
	uint8_t device_status; 				/* read-write */
	uint8_t config_generation; 			/* read-only for driver */

	/* About a specific virtqueue. */
	uint16_t queue_select; 				/* read-write */
	uint16_t queue_size; 				/* read-write */
	uint16_t queue_msix_vector; 		/* read-write */
	uint16_t queue_enable; 				/* read-write */
	uint16_t queue_notify_off; 			/* read-only for driver */
	uint64_t queue_desc;  				/* read-write */
	uint64_t queue_driver; 				/* read-write */
	uint64_t queue_device; 				/* read-write */
} __attribute__((packed));


struct virtio_pci_notify_cap {
	struct virtio_pci_cap cap;
	uint32_t notify_off_multiplier; /* Multiplier for queue_notify_off. */
} __attribute__((packed));


struct virtio_pci_cfg_cap {
	struct virtio_pci_cap cap;
	uint8_t pci_cfg_data[4]; 		/* Data for BAR access. */
} __attribute__((packed));;


typedef struct {
	/* common virtio caps */
	volatile struct virtio_pci_common_cfg *common_cfg;
	volatile struct virtio_pci_notify_cap *notify_cap;
	volatile struct virtio_pci_cfg_cap  *cfg_cap;
	struct {
		volatile uint8_t *base;
		uint32_t size;
	} isr;
	uint64_t features;
} virtio_device_t;


#define VIRTIO_CFG_DEVICE_FEATURE 	0
#define VIRTIO_CFG_DRIVER_FEATURE 	4
#define VIRTIO_CFG_VQ_ADDR 			8
#define VIRTIO_CFG_VQ_SIZE 			12
#define VIRTIO_CFG_VQ_SEL			14
#define VIRTIO_CFG_VQ_NOTI			16
#define VIRTIO_CFG_DEVICE_STATUS	18
#define VIRTIO_CFG_ISR_STATUS		19
#define VIRTIO_CFG_DEVICE_SPEC		20


typedef struct {
	virtio_device_t virtio_dev;
	/* pci stuff */
	pci_device_t pci_dev;
	pci_cap_list_t pci_cap_list;
	void *bar[6];

	uint8_t legacy;

} virtio_pci_device_t;


/* virtqueue */

struct virtq_desc {
	volatile uint64_t addr;
	volatile uint32_t len;
/* This marks a buffer as continuing via the next field. */
#define VIRTQ_DESC_F_NEXT 1
/* This marks a buffer as device write-only (otherwise device read-only). */
#define VIRTQ_DESC_F_WRITE 2
/* This means the buffer contains a list of buffer descriptors. */
#define VIRTQ_DESC_F_INDIRECT 4
	volatile uint16_t flags;
	volatile uint16_t next;
}__attribute__((packed));

#define VIRTQ_MAX_SIZE 256

struct virtq_avail {
#define VIRTQ_AVAIL_F_NO_INTERRUPT      1
	volatile uint16_t flags;
	volatile uint16_t idx;
	volatile uint16_t ring[VIRTQ_MAX_SIZE];
	volatile uint16_t used_event; /* Only if VIRTIO_F_EVENT_IDX */
} __attribute__((packed));

/* le32 is used here for ids for padding reasons. */
struct virtq_used_elem {
	/* Index of start of used descriptor chain. */
	uint32_t id;
	/* Total length of the descriptor chain which was used (written to) */
	uint32_t len;
} __attribute__((packed));

struct virtq_used {
#define VIRTQ_USED_F_NO_NOTIFY  1
	volatile uint16_t flags;
	volatile uint16_t idx;
	volatile struct virtq_used_elem ring[VIRTQ_MAX_SIZE];
	volatile uint16_t avail_event; /* Only if VIRTIO_F_EVENT_IDX */
} __attribute__((packed));

struct virtq {
	struct virtq_desc *desc;
	struct virtq_avail *avail;
	struct virtq_used *used;

	uint16_t index;
	uint16_t size;
	uint16_t last;
	volatile uint16_t *notify_addr;

	uint32_t buff_size;
	uint32_t buff_cnt;
	uint32_t buff_avail;
	addr_t  *pbuffs;
	addr_t  *vbuffs;
};

/* virtio net */

/* feature bits */
#define VIRTIO_NET_F_CSUM 					(1 << 0)
#define VIRTIO_NET_F_GUEST_CSUM 			(1 << 1)
#define VIRTIO_NET_F_CTRL_GUEST_OFFLOADS 	(1 << 2)
#define VIRTIO_NET_F_MTU 					(1 << 3)
#define VIRTIO_NET_F_MAC 					(1 << 5)
#define VIRTIO_NET_F_GUEST_TSO4 			(1 << 7)
#define VIRTIO_NET_F_GUEST_TSO6 			(1 << 8)
#define VIRTIO_NET_F_GUEST_ECN 				(1 << 9)
#define VIRTIO_NET_F_GUEST_UFO 				(1 << 10)
#define VIRTIO_NET_F_HOST_TSO4 				(1 << 11)
#define VIRTIO_NET_F_HOST_TSO6 				(1 << 12)
#define VIRTIO_NET_F_HOST_ENC 				(1 << 13)
#define VIRTIO_NET_F_HOST_UFO 				(1 << 14)
#define VIRTIO_NET_F_MRG_RXBUF 				(1 << 15)
#define VIRTIO_NET_F_STATUS 				(1 << 16)
#define VIRTIO_NET_F_CTRL_VQ 				(1 << 17)
#define VIRTIO_NET_F_CTRL_RX 				(1 << 18)
#define VIRTIO_NET_F_CTRL_VLAN 				(1 << 19)
#define VIRTIO_NET_F_GUEST_ANNOUNCE 		(1 << 21)
#define VIRTIO_NET_F_MQ 					(1 << 22)
#define VIRTIO_NET_F_RSC_EXT 				(1LL << 61)
#define VIRTIO_NET_F_STANDBY 				(1LL << 62)

/* status */
#define VIRTIO_NET_S_LINK_UP     1
#define VIRTIO_NET_S_ANNOUNCE    2

#define VIRTIO_NET_HDR_SIZE 		12
#define VIRTIO_NET_HDR_SIZE_LEGACY 	10

struct virtio_net_hdr {
#define VIRTIO_NET_HDR_F_NEEDS_CSUM    1
#define VIRTIO_NET_HDR_F_DATA_VALID    2
#define VIRTIO_NET_HDR_F_RSC_INFO      4
	uint8_t flags;
#define VIRTIO_NET_HDR_GSO_NONE        0
#define VIRTIO_NET_HDR_GSO_TCPV4       1
#define VIRTIO_NET_HDR_GSO_UDP         3
#define VIRTIO_NET_HDR_GSO_TCPV6       4
#define VIRTIO_NET_HDR_GSO_ECN      0x80
    uint8_t gso_type;
	uint16_t hdr_len;
	uint16_t gso_size;
	uint16_t csum_start;
	uint16_t csum_offset;
	uint16_t num_buffers;
} __attribute__((packed));

#endif /* _LIBVIRTIO_H_ */