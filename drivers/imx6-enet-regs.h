/*
 * Phoenix-RTOS --- networking stack
 *
 * i.MX 6ULL built-in ENET register and structure definitions
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * %LICENSE%
 */
#ifndef NET_IMX6_ENET_REGS_H_
#define NET_IMX6_ENET_REGS_H_

#include <stdint.h>

// iMX6UL / iMX6ULL:
//	ENET1: base 0x0218_8000  irq 150  (@AIPS-2)
//	ENET2: base 0x020B_4000  irq 152  (@AIPS-1)
// all register accesses are required to be U32

typedef struct {
	uint32_t S, C;	// 1588 control/status + compare capture
} timer_control_t;

#define R_RESERVED(b, e) uint32_t rsvd_##b##_##e[(e - b)/4]
#define BIT(i) (1u << (i))

struct enet_regs {
	R_RESERVED(0x000, 0x004);
	uint32_t		EIR, EIMR;	// irq event, irq mask
#define ENET_IRQ_BABR		BIT(30)		// babbling receive error
#define ENET_IRQ_BABT		BIT(29)		// babbling transmit error
#define ENET_IRQ_GRA		BIT(28)		// graceful stop complete (tx)
#define ENET_IRQ_TXF		BIT(27)		// frame txed
#define ENET_IRQ_TXB		BIT(26)		// tx buffer updated
#define ENET_IRQ_RXF		BIT(25)		// frame rxed
#define ENET_IRQ_RXB		BIT(24)		// rx buffer updated (excl. last in frame)
#define ENET_IRQ_MII		BIT(23)		// MII transfer complete
#define ENET_IRQ_EBERR		BIT(22)		// system bus error (ECR.ETHEREN forced clear)
#define ENET_IRQ_LC		BIT(21)		// late collission
#define ENET_IRQ_RL		BIT(20)		// tx collision retry limit hit for a frame (frame dropped)
#define ENET_IRQ_UN		BIT(19)		// TX FIFO underrun
#define ENET_IRQ_PLR		BIT(18)		// rxed frame for which payload length check failed 
#define ENET_IRQ_WAKEUP		BIT(17)		// woke up by magic packet
#define ENET_IRQ_TS_AVAIL	BIT(16)		// ATSTMP valid after transmit
#define ENET_IRQ_TS_TIMER	BIT(15)		// timer wrapped
	R_RESERVED(0x00C, 0x010);
	uint32_t		RDAR, TDAR;	// RX/TX new desc trigger command
	R_RESERVED(0x018, 0x024);
	uint32_t		ECR;		// ethernet control	[desc format, endiannes, reset, ...]
#define	ENET_ECR_REG_MAGIC	0x70000000
#define	ENET_ECR_DBSWP		BIT(8)
#define	ENET_ECR_DBGEN		BIT(6)
#define	ENET_ECR_EN1588		BIT(4)
#define	ENET_ECR_SLEEP		BIT(3)
#define	ENET_ECR_MAGICEN	BIT(2)
#define	ENET_ECR_ETHEREN	BIT(1)
#define	ENET_ECR_RESET		BIT(0)
	R_RESERVED(0x028, 0x040);
	uint32_t		MMFR, MSCR;	// MII control
#define ENET_MSCR_HOLDTIME_SHIFT	8
#define ENET_MSCR_HOLDTIME_MASK		0x700
#define ENET_MSCR_DIS_PRE		BIT(7)
#define ENET_MSCR_SPEED_SHIFT		1
#define ENET_MSCR_SPEED_MASK		0x7E
	R_RESERVED(0x048, 0x064);
	uint32_t		MIBC;		// MIB control
	R_RESERVED(0x068, 0x084);
	uint32_t		RCR;		// RX control
#define	ENET_RCR_GRS		BIT(31)		// [ro] RX stopped
#define	ENET_RCR_NLC		BIT(30)		// payloach check enable
#define	ENET_RCR_MAX_FL_SHIFT	16
#define	ENET_RCR_MAX_FL_MASK	((BIT(14)-1) << ENET_RCR_MAX_FL_SHIFT)
#define	ENET_RCR_CFEN		BIT(15)		// disard non-PAUSE MAC control frames
#define	ENET_RCR_CRCFWD		BIT(14)		// strip FCS from received frame data
#define	ENET_RCR_PAUFWD		BIT(13)		// forward PAUSE frames to user
#define	ENET_RCR_PADEN		BIT(12)		// remove padding for short packets (forces CRCFWD=1)
#define	ENET_RCR_RMII_10T	BIT(9)		// RMII 10Mbps mode (vs 100Mbps when clear)
#define	ENET_RCR_RMII_MODE	BIT(8)		// RMII mode (vs MII when clear)
#define	ENET_RCR_FCE		BIT(5)		// process incoming PAUSE frames (iow. enable flow control for tx)
#define	ENET_RCR_BR_REJ		BIT(4)		// discard broadcast frames (unless in PROMISC)
#define	ENET_RCR_PROM		BIT(3)		// PROMISC mode (== receive-all)
#define	ENET_RCR_MII_MODE	BIT(2)		// MII mode (required to be set)
#define	ENET_RCR_DRT		BIT(1)		// half-duplex mode
#define	ENET_RCR_LOOP		BIT(0)		// MII loopback mode (requires: MII_MODE=1, RMII_MODE=0, DRT=0, clocks for MII provided)
	R_RESERVED(0x088, 0x0C4);
	uint32_t		TCR;		// TX control
#define	ENET_TCR_CRCFWD		BIT(9)		// don't ever append FCS to transmitted frame data
#define	ENET_TCR_ADDINS		BIT(8)		// overwrite SA with node's address (set in PALR+PAUR)
#define	ENET_TCR_RFC_PAUSE	BIT(4)		// (ro) TX is being held after PAUSE frame received
#define	ENET_TCR_TFC_PAUSE	BIT(3)		// (auto-clears) trigger transmission of PAUSE frame
#define	ENET_TCR_FDEN		BIT(2)		// full-duplex mode (== ignore CS and COL on transmit)
#define	ENET_TCR_GTS		BIT(0)		// stop transmit (after current frame transmission ends)
	R_RESERVED(0x0C8, 0x0E4);
	uint32_t		PALR, PAUR;	// MAC address
	uint32_t		OPD;		// pause duration (for TXed pauses)
	uint32_t		TXIC;		// TX irq coalescing
	R_RESERVED(0x0F4, 0x100);
	uint32_t		RXIC;		// RX irq coalescing
	R_RESERVED(0x104, 0x118);
	uint32_t		IAUR, IALR;	// unicast MAC hash-filter	[6 MSB from CRC-32]
	uint32_t		GAUR, GALR;	// multicast MAC hash-filter
	R_RESERVED(0x128, 0x144);
	uint32_t		TFWR;		// TX FIFO control (cut-through vs store-and-forward on TX)
	R_RESERVED(0x148, 0x180);
	uint32_t		RDSR;		// RX descriptor ring address [64-bit aligned; preferred: cacheline(64B)-aligned]
	uint32_t		TDSR;		// TX descriptor ring address [as above]
	uint32_t		MRBR;		// RX max buffer size [always includes FCS; 14-bit, 16B-aligned]
	R_RESERVED(0x18C, 0x190);
	uint32_t		RSFL, RSEM;	// RX FIFO control (cut-through vs store-and-forward on RX)
	uint32_t		RAEM, RAFL;
	uint32_t		TSEM, TAEM;	// TX FIFO control (cut-through vs store-and-forward on TX)
	uint32_t		TAFL;
	uint32_t		TIPG;		// TX inter-packet-gap (in bytes; valid: 8-26, def: 12)
	uint32_t		FTRL;		// RX frame truncation length (14-bit, def: 2kB-1)
	R_RESERVED(0x1B4, 0x1C0);
	uint32_t		TACC;		// TX accel control [don't change during transfers to TX FIFO -> TX quiescent / paused]
#define ENET_TACC_PROCHK	BIT(4)		// global force?
#define ENET_TACC_IPCHK		BIT(3)		// global force?
#define ENET_TACC_SHIFT16	BIT(0)		// skip 2-byte padding before ethernet header
	uint32_t		RACC;		// RX accel control
#define ENET_RACC_SHIFT16	BIT(7)		// add 2-byte padding before ethernet header
#define ENET_RACC_LINEDIS	BIT(6)		// discard errnoneous frames
#define ENET_RACC_PRODIS	BIT(2)		// discard frames with TCP/UDP/ICMP checksum error
#define ENET_RACC_IPDIS		BIT(1)		// discard frames with IPv4 checksum error
#define ENET_RACC_PADREM	BIT(0)		// remove ethernet payload padding from short IP frames
	R_RESERVED(0x1C8, 0x200);
	uint32_t		stats[64];	// various stats counters (32-bit each)
#define ENET_VALID_COUTERS	0x01FFFFFE1FFFFFFFull
	R_RESERVED(0x300, 0x400);
	uint32_t		ATCR;		// timer command
	uint32_t		ATVR;		// timer value
	uint32_t		ATOFF;		// timer limit (wrap / on-shot event)
	uint32_t		ATPER;		// timer period
	uint32_t		ATCOR;		// timer correction clocks (additional increment every this ts_clk cycles)
	uint32_t		ATINC;		// timer increment (base increment value per ts_clk, correction increment value)
	uint32_t		ATSTMP;		// last TX timestamp (for last frame with TxBD[TS] set)
	R_RESERVED(0x41C, 0x604);
	uint32_t		TGSR;		// timer flags (channel 0-3)
	timer_control_t	TC_R[4];	// timer flags (channel 0-3)
	R_RESERVED(0x628, 0x800);
};

#undef R_RESERVED


// XXX: clear reserved/unused descriptor fields
typedef struct
{
	uint16_t len;	// for last frag = whole frame size? (TBV)
	uint16_t flags;
	uint32_t addr;	// 64B-aligned buffer [size = TRUNC_FL ?]
} enet_short_desc_t;

typedef struct
{
	// first 3 same as enet_short_desc_t
	uint16_t len, flags;
	uint32_t addr;
	uint16_t xflags, yflags;
	uint16_t csum, proto;	// csum: IP payload (iow excluding IP header)
	uint16_t rsvd1, dflags;
	uint32_t timestamp;
	uint32_t rsvd2;
	uint32_t rsvd3;
} enet_long_desc_t;


// desc.flags

#define ENET_DESC_OWN		0x8000	// E/R: owned by MAC
#define ENET_DESC_SOFT1		0x4000	// RO1: software mark, bit #1
#define ENET_DESC_WRAP		0x2000	// W: next descr. index: wrap to zero
#define ENET_DESC_SOFT2		0x1000	// RO1: software mark, bit #1
#define ENET_DESC_LAST		0x0800	// L: last frame fragment

#define ENET_RXD_M		0x0100	// M: valid when promiscuous: set when address would not match normally
#define ENET_RXD_BCAST		0x0080	// BC: DA == broadcast
#define ENET_RXD_MCAST		0x0040	// MC: DA != broadcast && DA is multicast
#define ENET_RXD_OVERMTU	0x0020	// LG: frame size > MTU [RCR.MAX_FL]
#define ENET_RXD_CRCBERR	0x0010	// NO: non-byte frame size, and bad-CRC or PHY error [CR = 0]
#define ENET_RXD_CRCERR		0x0004	// CR: byte-aligned frame size, and bad-CRC or PHY error
#define ENET_RXD_FIFOOVR	0x0002	// OV: RX FIFO overrun (frame truncated)
#define ENET_RXD_TRUNC		0x0001	// TR: frame was truncated (at TRUNC_FL bytes)

#define ENET_TXD_TXCRC		0x0400	// TC: append CRC [0 = CRC included in last buffer data] [valid when L=1]


// desc.xflags

#define ENET_RXDX_VPCP_MASK	0xE000	// VPCP: VLAN PCP
#define ENET_RXDX_IPERR		0x0020	// ICE: IP header csum error or non-IP
#define ENET_RXDX_CSUMERR	0x0010	// PCR: protocol csum error or unknown protocol
#define ENET_RXDX_VLAN		0x0004	// VLAN: VLAN present
#define ENET_RXDX_IPV6		0x0002	// IPV6: frame contains IPv6
#define ENET_RXDX_FRAG		0x0001	// FARG: frame contains fragmented IPv4

#define ENET_TXDX_TXERR		0x8000	// TXE: TX error [HW, valid when L=1]
#define ENET_TXDX_UDFLOW	0x2000	// UE: TX FIFO underflow [HW, valid when L=1]
#define ENET_TXDX_XCOL		0x1000	// EE: excess collisions [HW, valid when L=1]
#define ENET_TXDX_MXERR		0x0800	// FE: error during DMA [HW, valid when L=1]
#define ENET_TXDX_LCOL		0x0400	// LCE: late collision [HW, valid when L=1]
#define ENET_TXDX_OVFLOW	0x0200	// OE: TX FIFO overflow [HW, valid when L=1]
#define ENET_TXDX_TSERR		0x0100	// TSE: timestamp error (wrong frame type) [HW, valid when L=1]


// desc.yflags

#define ENET_RXDY_MACERR	0x8000	// ME: MAC error (eg. RX FIFO overflow)
#define ENET_RXDY_PHYERR	0x0400	// PE: PHY error (invalid PHY symbol - bad PHY encoding)
#define ENET_RXDY_COL		0x0200	// CE: collision detected (half-duplex)
#define ENET_RXDY_UCAST		0x0100	// UC: DA == unicast
#define ENET_RXDY_INT		0x0080	// INT: [set by SW] trigger RXB/RXF interrupt [dma_int_rxb / dma_int_rxfevent]

#define ENET_TXDY_INT		0x4000	// INT: [set by SW] trigger interrupt [valid for all L; must be same for whole frame]
#define ENET_TXDY_TSTAMP	0x2000	// TS: [set by SW] generate a timestamp frame [valid for all L; must be same for whole frame]
#define ENET_TXDY_L4CSUM	0x1000	// PINS: [set by SW] calc checksum for L4 [valid for all L; must be same for whole frame]
#define ENET_TXDY_IPCSUM	0x0800	// IINS: [set by SW] calc checksum for IP [valid for all L; must be same for whole frame]


// desc.dflags

#define ENET_XDESC_DONE		0x8000	// BDU: last buffer update (for all for this frame ?) finished by DMA HW


// rxdesc.proto

#define ENET_PROTO_HLEN_MASK	0xF800	// N of 32-bit words in IP+L4 headers (incl. options); 0 if non-IP or invalid header
#define ENET_PROTO_TYPE_MASK	0x00FF	// L4 proto num (valid when ICE == 0)

#endif /* NET_IMX6_ENET_REGS_H_ */
