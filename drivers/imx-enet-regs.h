/*
 * Phoenix-RTOS --- networking stack
 *
 * i.MX 6ULL/RT106x/RT117x built-in ENET register and structure definitions
 *
 * Copyright 2018, 2024 Phoenix Systems
 * Author: Michał Mirosław, Julian Uziembło
 *
 * %LICENSE%
 */
#ifndef NET_IMX_ENET_REGS_H_
#define NET_IMX_ENET_REGS_H_

#include <stdint.h>
/*
 * ENET registers must be read and written with 32-bit accesses
 *
 * i.MX RT106x:
 * ENET  base: 0x402D8000  irq 130  (@AIPS-1)
 * ENET2 base: 0x402D4000  irq 152  (@AIPS-4)
 *
 * i.MX RT117x:
 * ENET    base: 0x40424000 irq 153 (@AIPS-2)
 * ENET-1G base: 0x40420000 irq 157 (@AIPS-2)
 *
 * iMX6UL / iMX6ULL:
 * ENET1: base 0x02188000  irq 150  (@AIPS-2)
 * ENET2: base 0x020B4000  irq 152  (@AIPS-1)
 */


#define R_RESERVED(start, end) uint32_t rsvd_##start##_##end[(end - start) / sizeof(uint32_t)] /* reserved address */
#define BIT(i)                 (1u << (i))                                                     /* bitmask for single bit */
#define BITS(start, end)       (((1u << ((end) - (start) + 1u)) - 1u) << (start))              /* bitmask for bits in provided range (inclusive) */

struct enet_regs {
	R_RESERVED(0x000, 0x004);
	uint32_t EIR;                 /* irq event */
	uint32_t EIMR;                /* irq mask */
#define ENET_IRQ_BABR     BIT(30) /* babbling receive error */
#define ENET_IRQ_BABT     BIT(29) /* babbling transmit error */
#define ENET_IRQ_GRA      BIT(28) /* graceful stop complete (tx) */
#define ENET_IRQ_TXF      BIT(27) /* frame txed */
#define ENET_IRQ_TXB      BIT(26) /* tx buffer updated */
#define ENET_IRQ_RXF      BIT(25) /* frame rxed */
#define ENET_IRQ_RXB      BIT(24) /* rx buffer updated (excl. last in frame) */
#define ENET_IRQ_MII      BIT(23) /* MII transfer complete */
#define ENET_IRQ_EBERR    BIT(22) /* system bus error (ECR.ETHEREN forced clear) */
#define ENET_IRQ_LC       BIT(21) /* late collision */
#define ENET_IRQ_RL       BIT(20) /* tx collision retry limit hit for a frame (frame dropped) */
#define ENET_IRQ_UN       BIT(19) /* TX FIFO underrun */
#define ENET_IRQ_PLR      BIT(18) /* rxed frame for which payload length check failed */
#define ENET_IRQ_WAKEUP   BIT(17) /* woke up by magic packet */
#define ENET_IRQ_TS_AVAIL BIT(16) /* ATSTMP valid after transmit */
#define ENET_IRQ_TS_TIMER BIT(15) /* timer wrapped */
	R_RESERVED(0x00C, 0x010);
	uint32_t RDAR; /* RX new desc trigger command */
#define ENET_RDAR_RDAR BIT(24)
	uint32_t TDAR; /* TX new desc trigger command */
#define ENET_TDAR_TDAR BIT(24)
	R_RESERVED(0x018, 0x024);
	uint32_t ECR;                     /* ethernet control	[desc format, endianness, reset, ...] */
#define ENET_ECR_MAGIC_VAL 0x70000000 /* Magic number that has to be written to ECR on every write (imxrt106x: RM 41.5.1.6.4) */
#define ENET_ECR_DBSWP     BIT(8)
#define ENET_ECR_DBGEN     BIT(6)
#define ENET_ECR_SPEED     BIT(5)
#define ENET_ECR_EN1588    BIT(4)
#define ENET_ECR_SLEEP     BIT(3)
#define ENET_ECR_MAGICEN   BIT(2)
#define ENET_ECR_ETHEREN   BIT(1)
#define ENET_ECR_RESET     BIT(0)
	R_RESERVED(0x028, 0x040);
	uint32_t MMFR; /* MII control */
#define ENET_MMFR_ST_SHIFT        (30)
#define ENET_MMFR_ST_MASK         BITS(ENET_MMFR_ST_SHIFT, 31) /* Start of frame delimiter */
#define ENET_MMFR_ST_CLAUSE45_VAL (0)                          /* default value of ST field for Clause45 MDIO frames */
#define ENET_MMFR_ST_CLAUSE22_VAL (1)                          /* default value of ST field for Clause22 MDIO frames */
#define ENET_MMFR_OP_SHIFT        (28)
#define ENET_MMFR_OP_WRITE_VAL    (1) /* MDIO write opcode */
#define ENET_MMFR_OP_READ_VAL     (2) /* MDIO read opcode */
#define ENET_MMFR_OP_ADDR         (0)
#define ENET_MMFR_OP_MASK         BITS(ENET_MMFR_OP_SHIFT, 29) /* Opcode */
#define ENET_MMFR_PA_SHIFT        (23)
#define ENET_MMFR_PA_MASK         BITS(ENET_MMFR_PA_SHIFT, 27) /* PHY addr */
#define ENET_MMFR_RA_SHIFT        (18)
#define ENET_MMFR_RA_MASK         BITS(ENET_MMFR_RA_SHIFT, 22) /* reg addr */
#define ENET_MMFR_TA_SHIFT        (16)
#define ENET_MMFR_TA_VAL          (2)                          /* TA value */
#define ENET_MMFR_TA_MASK         BITS(ENET_MMFR_TA_SHIFT, 17) /* turn around time */
#define ENET_MMFR_DATA_SHIFT      (0)
#define ENET_MMFR_DATA_MASK       BITS(ENET_MMFR_DATA_SHIFT, 15) /* data */
	uint32_t MSCR;                                               /* MII speed */
#define ENET_MSCR_HOLDTIME_SHIFT  (8)
#define ENET_MSCR_HOLDTIME_MASK   BITS(ENET_MSCR_HOLDTIME_SHIFT, 10)
#define ENET_MSCR_DIS_PRE         BIT(7)
#define ENET_MSCR_MII_SPEED_SHIFT (1)
#define ENET_MSCR_MII_SPEED_MASK  BITS(ENET_MSCR_MII_SPEED_SHIFT, 6)
	R_RESERVED(0x048, 0x064);
	uint32_t MIBC; /* MIB control */
#define ENET_MIBC_MIB_DIS   BIT(31)
#define ENET_MIBC_MIB_IDLE  BIT(30)
#define ENET_MIBC_MIB_CLEAR BIT(29)
	R_RESERVED(0x068, 0x084);
	uint32_t RCR;                             /* RX control */
#define ENET_RCR_GRS                  BIT(31) /* [ro] RX stopped */
#define ENET_RCR_NLC                  BIT(30) /* payloach check enable */
#define ENET_RCR_MAX_FL_SHIFT         (16)
#define ENET_RCR_MAX_FL_WITH_VLAN_VAL (1522)       /* recommended val from RM (with VLAN) */
#define ENET_RCR_MAX_FL_NO_VLAN_VAL   (1518)       /* recommended val from RM (no VLAN) */
#define ENET_RCR_MAX_FL_MASK          BITS(16, 29) /* max RX frame length */
#define ENET_RCR_CFEN                 BIT(15)      /* discard non-PAUSE MAC control frames */
#define ENET_RCR_CRCFWD               BIT(14)      /* strip FCS from received frame data */
#define ENET_RCR_PAUFWD               BIT(13)      /* forward PAUSE frames to user */
#define ENET_RCR_PADEN                BIT(12)      /* remove padding for short packets (forces CRCFWD=1) */
#define ENET_RCR_RMII_10T             BIT(9)       /* RMII 10Mbps mode (vs 100Mbps when clear) */
#define ENET_RCR_RMII_MODE            BIT(8)       /* RMII mode (vs MII when clear) */
#define ENET_RCR_RGMII_EN             BIT(6)       /* RGMII mode */
#define ENET_RCR_FCE                  BIT(5)       /* process incoming PAUSE frames (iow. enable flow control for tx) */
#define ENET_RCR_BR_REJ               BIT(4)       /* discard broadcast frames (unless in PROMISC) */
#define ENET_RCR_PROM                 BIT(3)       /* PROMISC mode (== receive-all) */
#define ENET_RCR_MII_MODE             BIT(2)       /* MII mode (required to be set) */
#define ENET_RCR_DRT                  BIT(1)       /* half-duplex mode */
#define ENET_RCR_LOOP                 BIT(0)       /* MII loopback mode (requires: MII_MODE=1, RMII_MODE=0, DRT=0, clocks for MII provided) */
	R_RESERVED(0x088, 0x0C4);
	uint32_t TCR;                 /* TX control */
#define ENET_TCR_CRCFWD    BIT(9) /* don't ever append FCS to transmitted frame data */
#define ENET_TCR_ADDINS    BIT(8) /* overwrite SA with node's address (set in PALR+PAUR) */
#define ENET_TCR_RFC_PAUSE BIT(4) /* (ro) TX is being held after PAUSE frame received */
#define ENET_TCR_TFC_PAUSE BIT(3) /* (auto-clears) trigger transmission of PAUSE frame */
#define ENET_TCR_FDEN      BIT(2) /* full-duplex mode (== ignore CS and COL on transmit) */
#define ENET_TCR_GTS       BIT(0) /* stop transmit (after current frame transmission ends) */
	R_RESERVED(0x0C8, 0x0E4);
	uint32_t PALR; /* MAC address lower bytes */
	uint32_t PAUR; /* MAC address upper bytes + EtherType for PAUSE frames */
#define ENET_PAUR_TYPE_MASK      BITS(0, 15)
#define ENET_PAUR_TYPE_RESET_VAL (0x8808)
	uint32_t OPD;  /* pause duration (for TXed pauses) */
	uint32_t TXIC; /* TX irq coalescing */
#if defined(__CPU_IMX6ULL) || defined(__CPU_IMXRT106X)
	R_RESERVED(0x0F4, 0x100);
#elif defined(__CPU_IMXRT117X)
	uint32_t TXIC1;
	uint32_t TXIC2;
	R_RESERVED(0x0FC, 0x100);
#else
#error "Unsupported TARGET"
#endif
	uint32_t RXIC; /* RX irq coalescing */
#if defined(__CPU_IMX6ULL) || defined(__CPU_IMXRT106X)
	R_RESERVED(0x104, 0x118);
#elif defined(__CPU_IMXRT117X)
	uint32_t RXIC1;
	uint32_t RXIC2;
	R_RESERVED(0x10C, 0x118);
#else
#error "Unsupported TARGET"
#endif
	uint32_t IAUR; /* Upper 32 bits of 64 bit hashtable for unicast address recognition */
	uint32_t IALR; /* Lower 32 bits of 64 bit hashtable for unicast address recognition */
	uint32_t GAUR; /* Upper 32 bits of 64 bit hashtable for multicast address recognition */
	uint32_t GALR; /* Lower 32 bits of 64 bit hashtable for multicast address recognition */
	R_RESERVED(0x128, 0x144);
	uint32_t TFWR; /* TX FIFO control (cut-through vs store-and-forward on TX) */
#if defined(__CPU_IMXRT106X) || defined(__CPU_IMX6ULL)
	R_RESERVED(0x148, 0x180);
#elif defined(__CPU_IMXRT117X)
	R_RESERVED(0x148, 0x160);
	uint32_t RDSR1;
	uint32_t TDSR1;
	uint32_t MRBR1;
	uint32_t RDSR2;
	uint32_t TDSR2;
	uint32_t MRBR2;
	R_RESERVED(0x178, 0x180);
#else
#error "Unsupported TARGET"
#endif
	uint32_t RDSR; /* RX descriptor ring address [64-bit aligned; preferred: cacheline(64B)-aligned] */
	uint32_t TDSR; /* TX descriptor ring address [as above] */
	uint32_t MRBR; /* RX max buffer size [always includes FCS; 14-bit, 16B-aligned] */
	R_RESERVED(0x18C, 0x190);
	uint32_t RSFL, RSEM; /* RX FIFO control (cut-through vs store-and-forward on RX) */
	uint32_t RAEM, RAFL;
	uint32_t TSEM, TAEM; /* TX FIFO control (cut-through vs store-and-forward on TX) */
	uint32_t TAFL;
	uint32_t TIPG; /* TX inter-packet-gap (in bytes; valid: 8-26, def: 12) */
	uint32_t FTRL; /* RX frame truncation length (14-bit, def: 2kB-1) */
	R_RESERVED(0x1B4, 0x1C0);
	uint32_t TACC;               /* TX accel control [don't change during transfers to TX FIFO -> TX quiescent / paused] */
#define ENET_TACC_PROCHK  BIT(4) /* global force? */
#define ENET_TACC_IPCHK   BIT(3) /* global force? */
#define ENET_TACC_SHIFT16 BIT(0) /* skip 2-byte padding before ethernet header */
	uint32_t RACC;               /* RX accel control */
#define ENET_RACC_SHIFT16 BIT(7) /* add 2-byte padding before ethernet header */
#define ENET_RACC_LINEDIS BIT(6) /* discard errnoneous frames */
#define ENET_RACC_PRODIS  BIT(2) /* discard frames with TCP/UDP/ICMP checksum error */
#define ENET_RACC_IPDIS   BIT(1) /* discard frames with IPv4 checksum error */
#define ENET_RACC_PADREM  BIT(0) /* remove ethernet payload padding from short IP frames */
#if defined(__CPU_IMXRT106X) || defined(__CPU_IMX6ULL)
	R_RESERVED(0x01c8, 0x0200);
#elif defined(__CPU_IMXRT117X)
	uint32_t RCMR1;
	uint32_t RCMR2;
	R_RESERVED(0x01d0, 0x01d8);
	uint32_t DMA1CFG;
	uint32_t DMA2CFG;
	uint32_t RDAR1;
	uint32_t TDAR1;
	uint32_t RDAR2;
	uint32_t TDAR2;
	uint32_t QOS;
	R_RESERVED(0x01f4, 0x0200);
#else
#error "Unsupported TARGET"
#endif

	union {
		uint32_t rawstats[64]; /* various stats counters (32-bit each) */
		struct {
#if defined(__CPU_IMX6ULL) || defined(__CPU_IMXRT117X)
#define ENET_VALID_COUTERS 0x01FFFFFE1FFFFFFFull
			uint32_t RMON_T_DROP; /* Count of frames not cntd correctly */

#elif defined(__CPU_IMXRT106X)

#define ENET_VALID_COUNTER 0x01FFFDFE3FFBFFFEull
			R_RESERVED(0x0200, 0x0204);

#else

#error "Unsupported TARGET"

#endif
			uint32_t RMON_T_PACKETS;     /* RMON TX packet count */
			uint32_t RMON_T_BC_PKT;      /* RMON TX broadcast pkts */
			uint32_t RMON_T_MC_PKT;      /* RMON TX multicast pkts */
			uint32_t RMON_T_CRC_ALIGN;   /* RMON TX pkts with CRC align err */
			uint32_t RMON_T_UNDERSIZE;   /* RMON TX pkts < 64 bytes, good CRC */
			uint32_t RMON_T_OVERSIZE;    /* RMON TX pkts > MAX_FL bytes good CRC */
			uint32_t RMON_T_FRAG;        /* RMON TX pkts < 64 bytes, bad CRC */
			uint32_t RMON_T_JAB;         /* RMON TX pkts > MAX_FL bytes, bad CRC */
			uint32_t RMON_T_COL;         /* RMON TX collision count */
			uint32_t RMON_T_P64;         /* RMON TX 64 byte pkts */
			uint32_t RMON_T_P65TO127;    /* RMON TX 65 to 127 byte pkts */
			uint32_t RMON_T_P128TO255;   /* RMON TX 128 to 255 byte pkts */
			uint32_t RMON_T_P256TO511;   /* RMON TX 256 to 511 byte pkts */
			uint32_t RMON_T_P512TO1023;  /* RMON TX 512 to 1023 byte pkts */
			uint32_t RMON_T_P1024TO2047; /* RMON TX 1024 to 2047 byte pkts */
			uint32_t RMON_T_P_GTE2048;   /* RMON TX pkts > 2048 bytes */
			uint32_t RMON_T_OCTETS;      /* RMON TX octets */
#if defined(__CPU_IMX6ULL) || defined(__CPU_IMXRT117X)
			uint32_t IEEE_T_DROP; /* Count of frames not counted correctly */

#elif defined(__CPU_IMXRT106X)

			R_RESERVED(0x0248, 0x024c);

#else

#error "Unsupported TARGET"

#endif
			uint32_t IEEE_T_FRAME_OK;  /* Frames tx'd OK */
			uint32_t IEEE_T_1COL;      /* Frames tx'd with single collision */
			uint32_t IEEE_T_MCOL;      /* Frames tx'd with multiple collision */
			uint32_t IEEE_T_DEF;       /* Frames tx'd after deferral delay */
			uint32_t IEEE_T_LCOL;      /* Frames tx'd with late collision */
			uint32_t IEEE_T_EXCOL;     /* Frames tx'd with excessive collisions */
			uint32_t IEEE_T_MACERR;    /* Frames tx'd with TX FIFO underrun */
			uint32_t IEEE_T_CSERR;     /* Frames tx'd with carrier sense err */
			uint32_t IEEE_T_SQE;       /* Frames tx'd with SQE err */
			uint32_t IEEE_T_FDXFC;     /* Flow control pause frames tx'd */
			uint32_t IEEE_T_OCTETS_OK; /* Octet count for frames tx'd w/o err */
			R_RESERVED(0x0278, 0x0284);
			uint32_t RMON_R_PACKETS;   /* RMON RX packet count */
			uint32_t RMON_R_BC_PKT;    /* RMON RX broadcast pkts */
			uint32_t RMON_R_MC_PKT;    /* RMON RX multicast pkts */
			uint32_t RMON_R_CRC_ALIGN; /* RMON RX pkts with CRC alignment err */
			uint32_t RMON_R_UNDERSIZE; /* RMON RX pkts < 64 bytes, good CRC */
			uint32_t RMON_R_OVERSIZE;  /* RMON RX pkts > MAX_FL bytes good CRC */
			uint32_t RMON_R_FRAG;      /* RMON RX pkts < 64 bytes, bad CRC */
			uint32_t RMON_R_JAB;       /* RMON RX pkts > MAX_FL bytes, bad CRC */
			R_RESERVED(0x02a4, 0x02a8);
			uint32_t RMON_R_P64;         /* RMON RX 64 byte pkts */
			uint32_t RMON_R_P65TO127;    /* RMON RX 65 to 127 byte pkts */
			uint32_t RMON_R_P128TO255;   /* RMON RX 128 to 255 byte pkts */
			uint32_t RMON_R_P256TO511;   /* RMON RX 256 to 511 byte pkts */
			uint32_t RMON_R_P512TO1023;  /* RMON RX 512 to 1023 byte pkts */
			uint32_t RMON_R_P1024TO2047; /* RMON RX 1024 to 2047 byte pkts */
			uint32_t RMON_R_P_GTE2048;   /* RMON RX pkts > 2048 bytes */
			uint32_t RMON_R_OCTETS;      /* RMON RX octets */
			uint32_t IEEE_R_DROP;        /* Count frames not counted correctly */
			uint32_t IEEE_R_FRAME_OK;    /* Frames rx'd OK */
			uint32_t IEEE_R_CRC;         /* Frames rx'd with CRC err */
			uint32_t IEEE_R_ALIGN;       /* Frames rx'd with alignment err */
			uint32_t IEEE_R_MACERR;      /* Receive FIFO overflow count */
			uint32_t IEEE_R_FDXFC;       /* Flow control pause frames rx'd */
			uint32_t IEEE_R_OCTETS_OK;   /* Octet cnt for frames rx'd w/o err */
			R_RESERVED(0x02e4, 0x300);
		} stats;
	};
	R_RESERVED(0x300, 0x400);
	uint32_t ATCR;   /* timer command */
	uint32_t ATVR;   /* timer value */
	uint32_t ATOFF;  /* timer limit (wrap / on-shot event) */
	uint32_t ATPER;  /* timer period */
	uint32_t ATCOR;  /* timer correction clocks (additional increment every this ts_clk cycles) */
	uint32_t ATINC;  /* timer increment (base increment value per ts_clk, correction increment value) */
	uint32_t ATSTMP; /* last TX timestamp (for last frame with TxBD[TS] set) */
	R_RESERVED(0x41C, 0x604);
	uint32_t TGSR; /* timer flags (channel 0-3) */
	uint32_t TCSR0;
	uint32_t TCCR0;
	uint32_t TCSR1;
	uint32_t TCCR1;
	uint32_t TCSR2;
	uint32_t TCCR2;
	uint32_t TCSR3;
	uint32_t TCCR3;
	R_RESERVED(0x628, 0x800);
};

#undef R_RESERVED


/* XXX: clear reserved/unused descriptor fields */
typedef struct
{
	uint16_t len; /* for last frag = whole frame size? (TBV) */
	uint16_t flags;
	uint32_t addr; /* 64B-aligned buffer [size = TRUNC_FL ?] */
} enet_legacy_desc_t;

typedef struct
{
	/* first 3 same as enet_legacy_desc_t */
	union {
		struct {
			uint16_t len;
			uint16_t flags;
			uint32_t addr;
		};
		enet_legacy_desc_t legacy;
	};
	uint16_t xflags, yflags;
	uint16_t csum, proto; /* csum: IP payload (iow excluding IP header) */
	uint16_t rsvd1, dflags;
	uint32_t timestamp;
	uint32_t rsvd2;
	uint32_t rsvd3;
} enet_enhanced_desc_t;


/* desc.flags */

#define ENET_DESC_RDY   BIT(15) /* E/R: owned by MAC */
#define ENET_DESC_SOFT1 BIT(14) /* RO1: software mark, bit #1 */
#define ENET_DESC_WRAP  BIT(13) /* W: next descr. index: wrap to zero */
#define ENET_DESC_SOFT2 BIT(12) /* RO1: software mark, bit #1 */
#define ENET_DESC_LAST  BIT(11) /* L: last frame fragment */

#define ENET_RXD_M       BIT(8) /* M: valid when promiscuous: set when address would not match normally */
#define ENET_RXD_BCAST   BIT(7) /* BC: DA == broadcast */
#define ENET_RXD_MCAST   BIT(6) /* MC: DA != broadcast && DA is multicast */
#define ENET_RXD_OVERMTU BIT(5) /* LG: frame size > MTU [RCR.MAX_FL] */
#define ENET_RXD_CRCBERR BIT(4) /* NO: non-byte frame size, and bad-CRC or PHY error [CR = 0] */
#define ENET_RXD_CRCERR  BIT(2) /* CR: byte-aligned frame size, and bad-CRC or PHY error */
#define ENET_RXD_FIFOOVR BIT(1) /* OV: RX FIFO overrun (frame truncated) */
#define ENET_RXD_TRUNC   BIT(0) /* TR: frame was truncated (at TRUNC_FL bytes) */

#define ENET_TXD_TXCRC BIT(10) /* TC: append CRC [0 = CRC included in last buffer data] [valid when L=1] */


/* desc.xflags */

#define ENET_RXDX_VPCP_MASK BITS(13, 15) /* VPCP: VLAN PCP */
#define ENET_RXDX_IPERR     BIT(5)       /* ICE: IP header csum error or non-IP */
#define ENET_RXDX_CSUMERR   BIT(4)       /* PCR: protocol csum error or unknown protocol */
#define ENET_RXDX_VLAN      BIT(2)       /* VLAN: VLAN present */
#define ENET_RXDX_IPV6      BIT(1)       /* IPV6: frame contains IPv6 */
#define ENET_RXDX_FRAG      BIT(0)       /* FARG: frame contains fragmented IPv4 */

#define ENET_TXDX_TXERR  BIT(15) /* TXE: TX error [HW, valid when L=1] */
#define ENET_TXDX_UDFLOW BIT(13) /* UE: TX FIFO underflow [HW, valid when L=1] */
#define ENET_TXDX_XCOL   BIT(12) /* EE: excess collisions [HW, valid when L=1] */
#define ENET_TXDX_MXERR  BIT(11) /* FE: error during DMA [HW, valid when L=1] */
#define ENET_TXDX_LCOL   BIT(10) /* LCE: late collision [HW, valid when L=1] */
#define ENET_TXDX_OVFLOW BIT(9)  /* OE: TX FIFO overflow [HW, valid when L=1] */
#define ENET_TXDX_TSERR  BIT(8)  /* TSE: timestamp error (wrong frame type) [HW, valid when L=1] */


/* desc.yflags */

#define ENET_RXDY_MACERR BIT(15) /* ME: MAC error (eg. RX FIFO overflow) */
#define ENET_RXDY_PHYERR BIT(10) /* PE: PHY error (invalid PHY symbol - bad PHY encoding) */
#define ENET_RXDY_COL    BIT(9)  /* CE: collision detected (half-duplex) */
#define ENET_RXDY_UCAST  BIT(8)  /* UC: DA == unicast */
#define ENET_RXDY_INT    BIT(7)  /* INT: [set by SW] trigger RXB/RXF interrupt [dma_int_rxb / dma_int_rxfevent] */

#define ENET_TXDY_INT    BIT(14) /* INT: [set by SW] trigger interrupt [valid for all L; must be same for whole frame] */
#define ENET_TXDY_TSTAMP BIT(13) /* TS: [set by SW] generate a timestamp frame [valid for all L; must be same for whole frame] */
#define ENET_TXDY_L4CSUM BIT(12) /* PINS: [set by SW] calc checksum for L4 [valid for all L; must be same for whole frame] */
#define ENET_TXDY_IPCSUM BIT(11) /* IINS: [set by SW] calc checksum for IP [valid for all L; must be same for whole frame] */


/* desc.dflags */

#define ENET_XDESC_DONE BIT(15) /* BDU: last buffer update (for all for this frame ?) finished by DMA HW */


/* rxdesc.proto */

#define ENET_PROTO_HLEN_MASK BITS(11, 15) /* N of 32-bit words in IP+L4 headers (incl. options); 0 if non-IP or invalid header */
#define ENET_PROTO_TYPE_MASK BITS(0, 7)   /* L4 proto num (valid when ICE == 0) */

#endif /* NET_IMX_ENET_REGS_H_ */
