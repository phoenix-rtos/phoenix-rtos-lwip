/*
 * Phoenix-RTOS --- networking stack
 *
 * RTL8139C+ NIC register and structure definitions
 *
 * Copyright 2017 Phoenix Systems
 * Author: Michał Mirosław
 *
 * %LICENSE%
 */
#ifndef NET_RTL8139CP_REGS_H_
#define NET_RTL8139CP_REGS_H_

#include <stdint.h>


typedef struct {
	uint32_t l, h;
} u64_split;


struct rtl_regs {
	/* 0x00 */
	uint32_t		IDR[2];		// node ID (MAC address)
	uint32_t		MAR[2];		// multicast filter
	/* 0x10 */
	u64_split	DTCCR;		// stats dump command
	const uint32_t	rsvd1[2];
	/* 0x20 */
	u64_split	TNPDS;		// tx desc table (normal) addr
	u64_split	THPDS;		// tx desc table (prio) addr
	/* 0x30 */
	const uint32_t	rsvd2;
	const uint16_t	ERBCR;
	const uint8_t	ERSR;
	uint8_t		CR;
#define RTL_CMD_RESET		0x10
#define RTL_CMD_RX_ENABLE	0x08
#define RTL_CMD_TX_ENABLE	0x04
#define RTL_CMD_RX_EMPTY	0x01
	const uint16_t	rsvd3[2];
	uint16_t		IMR, ISR;	// interrupt mask and status
#define RTL_INT_ROK		0x0001
#define RTL_INT_TOK		0x0004
#define RTL_INT_RX_MISS		0x0010
#define RTL_INT_LINK		0x0020
#define RTL_INT_TX_EMPTY	0x0080
#define RTL_INT_TX_POLL		0x0100
#define RTL_INT_TIMER		0x4000
#define RTL_INT_SERR		0x8000

#define RTL_INT_RX		(RTL_INT_ROK | RTL_INT_RX_MISS)
#define RTL_INT_TX		(RTL_INT_TOK | RTL_INT_TX_EMPTY | RTL_INT_TX_POLL)
	/* 0x40 */
	uint32_t		TCR;		// tx config
#define RTL_HW_VERID			0x7c800000
#define RTL_TX_LOOPBACK			0x00060000
#define RTL_TX_INHIBIT_FCS		0x00010000
#define RTL_TX_DMA_BURST		0x00000700	// log2(burst / 16) [0..7]
#define RTL_TX_DMA_BURST_SHIFT		8
	uint32_t		RCR;		// rx config
#define RTL_RX_DMA_BURST		0x00000700	// log2(burst / 16) [2..4]
#define RTL_RX_DMA_BURST_SHIFT		8
#define RTL_RX_FTH			0x0000E000
#define RTL_RX_BCAST			0x00000008
#define RTL_RX_MCAST			0x00000004
#define RTL_RX_UCAST			0x00000002
#define RTL_RX_UCAST_ALL		0x00000001
	uint32_t		TCTR;		// gp-timer
	uint32_t		MPC;		// packets missed counter
#define RTL_MPC_MASK 		0xFFFFFFa
	/* 0x50 */
	uint8_t		EECR;		// EEPROM (93C46/93C56) command register
	uint8_t		CONFIG0;
	uint8_t		CONFIG1;
	const uint8_t	rsvd4;
	uint32_t		TIMERINT;	// timer interrupt enable
	uint8_t		MSR;		// media status
	uint8_t		CONFIG3;
	uint8_t		CONFIG4;
	const uint8_t	rsvd5;
	uint16_t		MULINT;		// multiple-packet interrupt config (FIXME)
	const uint8_t	RERID;		// PCI revision ID
	const uint8_t	rsvd6;
	/* 0x60 */
	const uint16_t	rsvd7;
	uint16_t		BMCR;
	const uint16_t	BMSR;
	uint16_t		ANAR;
	const uint16_t	ANLPAR;
	const uint16_t	ANER;
	const uint16_t	DIS;		// disconnect counter
	const uint16_t	FCSC;		// false carrier sense counter
	/* 0x70 */
	uint16_t		NWAYTR;		// N-way test
	const uint16_t	REC;		// RX counter
	uint16_t		CSCR;		// CS config
	const uint16_t 	rsvd8;
	uint32_t		PHY1_PARM;	// PHY param 1
	uint32_t		TW_PARM;	// Twister param
	/* 0x80 */
	uint8_t		PHY2_PARM;	// PHY param 2
	const uint8_t 	rsvd9;
	const uint16_t 	TDOKLADDR;	// tx done addr
	uint8_t 		WAKE_CRC[8];	// CRCs for wakeup frames
	/* 0x8C */
	u64_split 	WAKE_FRAME[8];	// wakeup frame byte masks
	/* 0xCC */
	uint8_t		WAKE_LCRC[8];	// MSBs of CRC-16 / last masked byte value for wakeup frames
	uint32_t		FLASH;		// flash memory access
	uint8_t		CONFIG5;
	uint8_t		TPPOLL;		// TX trigger
#define RTL_POLL_HPQ		0x80
#define RTL_POLL_NPQ		0x40
#define RTL_POLL_FSWINT		0x01
	const uint16_t	rsvd10[3];
	/* 0xE0 */
	uint16_t		CPCR;		// C+ mode
#define RTL_CMD_RX_VLAN		0x0040
#define RTL_CMD_RX_CSUM		0x0020
#define RTL_CMD_PCI_DAC		0x0010
#define RTL_CMD_PCI_MULRW	0x0008
#define RTL_CMD_RX_MODE_CP	0x0002
#define RTL_CMD_TX_MODE_CP	0x0001
	const uint16_t	rsvd11;
	u64_split	RDSAR;		// rx desc table addr
	uint8_t		ETTHR;		// early tx threshold
	uint8_t		rsvd12[3];
	/* 0xF0 */
	const uint32_t	rsvd13[4];	// CardBus specific
};


typedef struct
{
	uint32_t cmd;
	uint32_t offload;
	u64_split addr;
} rtl_buf_desc_t;


#define RTL_DESC_OWN		0x80000000	// owned by card
#define RTL_DESC_EOR		0x40000000	// end-of-ring marker
#define RTL_DESC_FS		0x20000000	// first segment (split packet)
#define RTL_DESC_LS		0x10000000	// last segment (split packet)

#define RXCMD_ERR_FAE		0x08000000	// frame alignment error
#define RXCMD_MCAST		0x04000000	// muticast frame
#define RXCMD_UCAST		0x02000000	// own unicast frame (DA matching card's)
#define RXCMD_BCAST		0x01000000	// broadcast frame
#define RXCMD_ERR_BO		0x00800000	// buffer overflow (frame truncated?)
#define RXCMD_ERR_FO		0x00400000	// FIFO overflow (frame truncated?)
#define RXCMD_ERR_RWT		0x00200000	// long frame truncated (to 4096B)
#define RXCMD_ERR_RX		0x00100000	// frame errors = CRC | RUNT | RWT | FAE  [v. SG_LAST]
#define RXCMD_ERR_RUNT		0x00080000	// runt frame (<64B incl. FCS)  [RCR.AR==1]
#define RXCMD_ERR_CRC		0x00040000	// frame with bad FCS		[RCR.AER==1]
#define RXCMD_PROTO_MASK	0x00030000	// IPv4 frame: 0: no, 1: TCP, 2: UDP, 3: other
#define RXCMD_ERR_IPCSUM	0x00008000	// bad IPv4 csum
#define RXCMD_ERR_UDPSUM	0x00004000	// bad UDP csum
#define RXCMD_ERR_TCPSUM	0x00002000	// bad TCP csum
#define RXCMD_SZ_MASK		0x00001fff	// buf size (4kB max)

#define TXCMD_TSO		0x08000000	// TCP segmentation
#define TXCMD_TSO_MSS_MASK	0x07ff0000	// TCP MSS
#define TXCMD_TSO_MSS_SHIFT	16
#define TXCMD_IP_CSUM		0x00040000	// IP header checksum
#define TXCMD_UDP_CSUM		0x00020000	// UDP checksum
#define TXCMD_TCP_CSUM		0x00010000	// TCP checksum
#define TXCMD_SZ_MASK		0x0000ffff	// buf size


#define RTL_OFL_VLAN		0x00010000	// VLAN tag stripped
#define RTL_OFL_VLAN_TAG	0x0000ffff	// VLAN tag


#endif /* NET_RTL8139CP_REGS_H_ */
