/*
 * Phoenix-RTOS --- networking stack
 *
 * GRETH network module driver
 *
 * Copyright 2025 Phoenix Systems
 * Author: Andrzej Tlomak
 *
 * %LICENSE%
 */

#ifndef NET_GRETH_REGS_H_
#define NET_GRETH_REGS_H_

#include <stdint.h>

#define BIT(i)           (1u << (i))                                        /* bitmask for single bit */
#define BITS(start, end) (((1u << ((end) - (start) + 1u)) - 1u) << (start)) /* bitmask for bits in provided range (inclusive) */

struct greth_regs {
	uint32_t CTRL;                      /* 0x00 Control register */
#define GRETH_CTRL_EA      BIT(31)      /* 1 if EDCL is available */
#define GRETH_CTRL_BS_MASK BITS(28, 30) /* EDCL buffer size (1 = 2 KiB) */
#define GRETH_CTRL_GA      BIT(27)      /* Gigabit MAC available */
#define GRETH_CTRL_MA      BIT(26)      /* MDIO interrupts enabled */
#define GRETH_CTRL_MC      BIT(25)      /* Multicast available */
#define GRETH_CTRL_ED      BIT(14)      /* Disable EDCL (0 = enabled) */
#define GRETH_CTRL_RD      BIT(13)      /* RAM debug (always 0, write no effect) */
#define GRETH_CTRL_DD      BIT(12)      /* Disable duplex detection FSM */
#define GRETH_CTRL_ME      BIT(11)      /* Enable multicast reception */
#define GRETH_CTRL_PI      BIT(10)      /* PHY status IRQ enable */
#define GRETH_CTRL_BM      BIT(9)       /* Burstmode (only for 1000M half-duplex) */
#define GRETH_CTRL_GB      BIT(8)       /* Set 1000 Mbit mode */
#define GRETH_CTRL_SP      BIT(7)       /* Speed: 0 = 10Mbit, 1 = 100Mbit */
#define GRETH_CTRL_RS      BIT(6)       /* Reset core (self-clearing) */
#define GRETH_CTRL_PM      BIT(5)       /* Promiscuous mode */
#define GRETH_CTRL_FD      BIT(4)       /* Full duplex */
#define GRETH_CTRL_RI      BIT(3)       /* Receiver interrupt enable */
#define GRETH_CTRL_TI      BIT(2)       /* Transmitter interrupt enable */
#define GRETH_CTRL_RE      BIT(1)       /* Receiver enable */
#define GRETH_CTRL_TE      BIT(0)       /* Transmitter enable */
	uint32_t STAT;                      /* Status/Interrupt-source register */
#define GRETH_STAT_PS BIT(8)            /* PHY status change detected */
#define GRETH_STAT_IA BIT(7)            /* Invalid address received */
#define GRETH_STAT_TS BIT(6)            /* Packet too small */
#define GRETH_STAT_TA BIT(5)            /* TX AHB error */
#define GRETH_STAT_RA BIT(4)            /* RX AHB error */
#define GRETH_STAT_TI BIT(3)            /* TX successful */
#define GRETH_STAT_RI BIT(2)            /* RX successful */
#define GRETH_STAT_TE BIT(1)            /* TX error */
#define GRETH_STAT_RE BIT(0)            /* RX error */
	uint32_t MAC_MSB;                   /* MAC Address MSB */
	uint32_t MAC_LSB;                   /* MAC Address LSB */
	uint32_t MDIO;                      /* MDIO Control/Status */
#define GRETH_MDIO_DATA_SHIFT    (16)
#define GRETH_MDIO_DATA_MASK     BITS(GRETH_MDIO_DATA_SHIFT, 31)    /* data */
#define GRETH_MDIO_PHYADDR_SHIFT (11)                               /* PHY address of GBIT 0 */
#define GRETH_MDIO_PHYADDR_MASK  BITS(GRETH_MDIO_PHYADDR_SHIFT, 15) /* PHY address of GBIT 0 */
#define GRETH_MDIO_REGADDR_SHIFT (6)
#define GRETH_MDIO_REGADDR_MASK  BITS(GRETH_MDIO_REGADDR_SHIFT, 10)
#define GRETH_MDIO_BUSY          BIT(3)
#define GRETH_MDIO_READ          BIT(1)
#define GRETH_MDIO_WRITE         BIT(0)
	uint32_t TX_DESC_PTR; /* 0x14 Transmit descriptor pointer */
#define GRETH_TX_DESC_BASEADDR_SHIFT (10)
#define GRETH_TX_DESC_BASEADDR_MASK  BITS(GRETH_TX_DESC_BASEADDR_SHIFT, 31) /* TX descriptor base address */
#define GRETH_TX_DESC_DESCPNT_SHIFT  (3)
#define GRETH_TX_DESC_DESCPNT_MASK   BITS(GRETH_TX_DESC_DESCPNT_SHIFT, 9) /* TX descriptor pointer */
	uint32_t RX_DESC_PTR;                                                 /* 0x18 Receiver descriptor pointer */
#define GRETH_RX_DESC_BASEADDR_SHIFT (10)
#define GRETH_RX_DESC_BASEADDR_MASK  BITS(GRETH_RX_DESC_BASEADDR_SHIFT, 31) /* TX descriptor base address */
#define GRETH_RX_DESC_DESCPNT_SHIFT  (3)
#define GRETH_RX_DESC_DESCPNT_MASK   BITS(GRETH_RX_DESC_DESCPNT_SHIFT, 9) /* TX descriptor pointer */
	uint32_t EDCL_IP;                                                     /* 0x1C EDCL IP */
	uint32_t HASH_MSB;                                                    /* 0x20 Hash table MSB */
	uint32_t HASH_LSB;                                                    /* 0x24 Hash table LSB */
	uint32_t EDCL_MAC_MSB;                                                /* 0x28 EDCL MAC address MSB */
	uint32_t EDCL_MAC_LSB;                                                /* 0x2C EDCL MAC address LSB */
};

typedef struct {
	uint32_t flags;
	uint32_t addr;
} greth_buf_desc_t;

/* TX desc. flags */
#define GRETH_DESC_TX_UC BIT(20) /* UDP checksum */
#define GRETH_DESC_TX_TC BIT(19) /* TCP checksum */
#define GRETH_DESC_TX_IC BIT(18) /* IP checksum */
#define GRETH_DESC_TX_MO BIT(17) /* More descriptors (SG I/O) */
#define GRETH_DESC_TX_LC BIT(16) /* Late collision */
#define GRETH_DESC_TX_AL BIT(15) /* Attempt limit error */
#define GRETH_DESC_TX_UE BIT(14) /* Underrun error */

/* RX descriptor flags */
#define GRETH_DESC_RX_MC BIT(26) /* Multicast address */
#define GRETH_DESC_RX_IF BIT(25) /* IP fragment detected */
#define GRETH_DESC_RX_TR BIT(24) /* TCP checksum error */
#define GRETH_DESC_RX_TD BIT(23) /* TCP packet detected */
#define GRETH_DESC_RX_UR BIT(22) /* UDP checksum error */
#define GRETH_DESC_RX_UD BIT(21) /* UDP packet detected */
#define GRETH_DESC_RX_IR BIT(20) /* IP checksum error */
#define GRETH_DESC_RX_ID BIT(19) /* IP packet detected */
#define GRETH_DESC_RX_LE BIT(18) /* Length/type error */
#define GRETH_DESC_RX_OE BIT(17) /* FIFO overrun error */
#define GRETH_DESC_RX_CE BIT(16) /* CRC error */
#define GRETH_DESC_RX_FT BIT(15) /* Frame too long */
#define GRETH_DESC_RX_AE BIT(14) /* Alignment error */

/* common desc. flags */
#define GRETH_DESC_IE        BIT(13)                        /* Interrupt enable */
#define GRETH_DESC_WR        BIT(12)                        /* Wrap */
#define GRETH_DESC_EN        BIT(11)                        /* Enable descriptor */
#define GRETH_DESC_LEN_SHIFT (0)                            /* LEN */
#define GRETH_DESC_LEN_MASK  BITS(GRETH_DESC_LEN_SHIFT, 10) /* LEN */

#endif
