/*
 * Phoenix-RTOS --- networking stack
 *
 * iMX 6ULL/RT106x/RT117x ENET network module driver
 *
 * Copyright 2018, 2024 Phoenix Systems
 * Author: Michał Mirosław, Julian Uziembło
 *
 * %LICENSE%
 */
#include "arch/cc.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "netif-driver.h"
#include "bdring.h"
#include "ephy.h"
#include "physmmap.h"
#include "res-create.h"
#include "imx-enet-regs.h"

#include <sys/interrupt.h>
#include <sys/platform.h>
#include <sys/threads.h>
#include <stdatomic.h>
#include <endian.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ENET_DEBUG    0
#define MDIO_DEBUG    0
#define ENET_SELFTEST 0

#define ENET_MAX_PKT_SZ               1984 /* DMA aligned */
#define ENET_USE_ENHANCED_DESCRIPTORS 0
#define ENET_RMII_MODE                1
#define ENET_ENABLE_FLOW_CONTROL      1
#define ENET_PROMISC_MODE             0
#define ENET_ENABLE_RX_PAD_REMOVE     1
#define ENET_DIS_RX_ON_TX             1 /* usually: 0 in half-duplex, 1 in full-duplex */
#define ENET_MDC_ALWAYS_ON            1 /* NOTE: should be always ON, otherwise unreliable*/

#define MDIO_TIMEOUT 0

#if defined(__CPU_IMXRT106X)

#include <phoenix/arch/armv7m/imxrt/10xx/imxrt10xx.h>

#define ENET_ADDR_ENET1   (0x402D8000)
#define OCOTP_MEMORY_ADDR (0x401F4000)

#define OCOTP_UID1_OFFSET (0x420)
#define OCOTP_MAC0_OFFSET (0x620)
#define OCOTP_MAC1_OFFSET (0x630)
#define OCOTP_MAC_OFFSET  (0x640)
#define OCOTP_REV_OFFSET  (0x670)

#define ENET_CLK_KHZ (132000)

#define ENET_RX_RING_SIZE 8
#define ENET_TX_RING_SIZE 8

#elif defined(__CPU_IMXRT117X)

#include <phoenix/arch/armv7m/imxrt/11xx/imxrt1170.h>
#include "hw-debug.h"

#define ENET_ADDR_ENET1   (0x40424000)
#define ENET_ADDR_ENET_1G (0x40420000)
#define OCOTP_MEMORY_ADDR (0x40CAC000)

#define OCOTP_UID1_OFFSET (0x910)
#define OCOTP_MAC0_OFFSET (0xA80)
#define OCOTP_MAC1_OFFSET (0xAA0)
#define OCOTP_MAC_OFFSET  (0xAC0)
#define OCOTP_REV_OFFSET  (0x920)

#define ENET_RGMII_MODE 1

#define ENET_CLK_KHZ      (250 * 1000) /* NOTE: MDIO seems to not be working properly with the true ENET_CLK speed? */
#define ENET_RX_RING_SIZE 4
#define ENET_TX_RING_SIZE 4

#elif defined(__CPU_IMX6ULL)

#include <phoenix/arch/armv7a/imx6ull/imx6ull.h>
#include "hw-debug.h"

#define ENET_ADDR_ENET1   (0x02188000)
#define ENET_ADDR_ENET2   (0x020B4000)
#define OCOTP_MEMORY_ADDR (0x021bc000)

#define OCOTP_UID1_OFFSET (0x420)
#define OCOTP_MAC0_OFFSET (0x620)
#define OCOTP_MAC1_OFFSET (0x630)
#define OCOTP_MAC_OFFSET  (0x640)
#define OCOTP_REV_OFFSET  (0x670)

#define ENET_CLK_KHZ (66000 /* IPG */) /* BT_FREQ=0 */

#define ENET_RX_RING_SIZE 64
#define ENET_TX_RING_SIZE 64

#else
#error "Unsupported TARGET"
#endif

#if ENET_USE_ENHANCED_DESCRIPTORS
typedef enet_enhanced_desc_t enet_buf_desc_t;
#else
typedef enet_legacy_desc_t enet_buf_desc_t;
#endif

typedef struct {
	volatile struct enet_regs *mmio;

	struct netif *netif;
	volatile atomic_uint drv_exit;

#define PRIV_RESOURCES(s) &(s)->irq_lock, 3, ~0x03
	handle_t irq_lock, tx_lock;

	handle_t irq_cond, irq_handle;

	union {
		struct {
			net_bufdesc_ring_t rx, tx;
		};
		net_bufdesc_ring_t rings[2];
	};

	addr_t dev_phys_addr;
	uint32_t mscr;

	eth_phy_state_t phy;

#if ENET_SELFTEST
	struct {
#define SELFTEST_RESOURCES(s) &(s)->selfTest.rx_lock, 2, ~0x1
		handle_t rx_lock;
		handle_t rx_cond;
		unsigned int rx_valid; /* -1: received invalid packet, 0: no packet received, 1: received valid packet */
	} selfTest;
#endif

	uint32_t irq_stack[1024] __attribute__((aligned(16)));
} enet_state_t;


enum { EV_BUS_ERROR = 0x01 };


#define enet_printf(state, fmt, ...) printf("lwip: enet@%08x: " fmt "\n", state->dev_phys_addr, ##__VA_ARGS__)

#if ENET_DEBUG
#define enet_debug_printf(state, fmt, ...) enet_printf(state, fmt, ##__VA_ARGS__)
#else
#define enet_debug_printf(state, fmt, ...)
#endif


static int enet_reset(enet_state_t *state, time_t timeout)
{
	time_t now, when;

	enet_debug_printf(state, "Resetting device...");

	gettime(&now, NULL);
	when = now + timeout;

	/* trigger and wait for reset */
	state->mmio->ECR = ENET_ECR_MAGIC_VAL | ENET_ECR_RESET;
	do {
		usleep(100);
		if (timeout != 0) {
			gettime(&now, NULL);
			if (now >= when) {
				enet_printf(state, "Couldn't reset device: timeout");
				return -ETIMEDOUT;
			}
		}
	} while ((state->mmio->ECR & ENET_ECR_ETHEREN) != 0);
	enet_debug_printf(state, "Reset done.");

	state->mmio->IAUR = 0;
	state->mmio->IALR = 0;
	state->mmio->GAUR = 0;
	state->mmio->GALR = 0;

	return 0;
}


static void enet_start(enet_state_t *state)
{
	//	addr_t ecr_pa = (addr_t)&((struct enet_regs *)state->phys)->ECR;
	// FIXME: last_will(ECR = ENET_ECR_MAGIC_VAL | ENET_ECR_RESET);

	state->mmio->MRBR = ENET_MAX_PKT_SZ;
	state->mmio->FTRL = BIT(14) - 1;  // FIXME: truncation to just above link MTU

	uint32_t rcr = ENET_RCR_MAX_FL_NO_VLAN_VAL << ENET_RCR_MAX_FL_SHIFT |
			ENET_RCR_CRCFWD | ENET_RCR_PAUFWD |
#if ENET_ENABLE_RX_PAD_REMOVE
			ENET_RCR_PADEN |
#endif
#if ENET_RMII_MODE
			ENET_RCR_RMII_MODE |
#endif
#if ENET_ENABLE_FLOW_CONTROL
			ENET_RCR_FCE |
#endif
#if ENET_PROMISC_MODE
			ENET_RCR_PROM |
#endif
			ENET_RCR_MII_MODE;

#if defined(ENET_ADDR_ENET_1G) && ENET_RGMII_MODE
	if (state->dev_phys_addr == ENET_ADDR_ENET_1G) {
		rcr = (rcr & ~ENET_RCR_RMII_MODE) | ENET_RCR_RGMII_EN;
	}
#endif
	state->mmio->RCR = rcr;
	/* RCR */

	state->mmio->RACC =
#if ETH_PAD_SIZE == 2
			ENET_RACC_SHIFT16 |
#elif ETH_PAD_SIZE != 0
#error "Unsupported ETH_PAD_SIZE"
#endif
#if !ENET_PROMISC_MODE
			ENET_RACC_LINEDIS | ENET_RACC_PRODIS | ENET_RACC_IPDIS |
#endif
			ENET_RACC_PADREM;

#if ETH_PAD_SIZE == 2
	state->mmio->TACC = ENET_TACC_SHIFT16;
#elif ETH_PAD_SIZE == 0
	state->mmio->TACC = 0;
#else
#error "Unsupported ETH_PAD_SIZE"
#endif

	state->mmio->TCR = ENET_TCR_FDEN;

	mutexLock(state->irq_lock);
	state->mmio->EIMR |= ENET_IRQ_EBERR;
	mutexUnlock(state->irq_lock);

	state->mmio->ECR = ENET_ECR_MAGIC_VAL |
#if ENET_USE_ENHANCED_DESCRIPTORS
			ENET_ECR_EN1588 |
#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN
			ENET_ECR_DBSWP |
#endif
			ENET_ECR_ETHEREN;

	/* trigger HW RX */
	state->mmio->RDAR = ENET_RDAR_RDAR;

#if defined(__CPU_IMX6ULL)
	enet_debug_printf(state, "regs:   ECR   ,  EIMR  ,  TACC  ,  RACC  ,  TCR   ,  RCR   ,  MRBR  ,  FTRL  ");
	enet_debug_printf(state, "regs: %08x %08x %08x %08x %08x %08x %08x %08x",
			state->mmio->ECR, state->mmio->EIMR, state->mmio->TACC, state->mmio->RACC,
			state->mmio->TCR, state->mmio->RCR, state->mmio->MRBR, state->mmio->FTRL);
	enet_debug_printf(state, "regs:   PLL6  ,  CCGR0 ,  GPR1  ,TXCLKMUX,TXCLKPAD,RCLK1SID,OSC24-M0,OSC24-LP");
	enet_debug_printf(state, "regs: %08x %08x %08x %08x %08x %08x %08x %08x",
			hwdebug_read(0x20c80e0), hwdebug_read(0x20c4068), hwdebug_read(0x20e4004), hwdebug_read(0x20e00dc),
			hwdebug_read(0x20e0368), hwdebug_read(0x20e0574), hwdebug_read(0x20c8150), hwdebug_read(0x20c8270));
#endif
}


static int enet_readFusedMac(uint32_t *buf, volatile uint32_t *ocotp_mem)
{
	buf[0] = ocotp_mem[OCOTP_MAC0_OFFSET / sizeof(*ocotp_mem)];
	buf[1] = ocotp_mem[OCOTP_MAC1_OFFSET / sizeof(*ocotp_mem)];
	buf[2] = ocotp_mem[OCOTP_MAC_OFFSET / sizeof(*ocotp_mem)];

	return 0;
}


static uint32_t enet_readCpuId(volatile uint32_t *ocotp_mem)
{
	uint32_t res = 0;

	/* use CFG1: wafer no + x/y coordinate */
	res = ocotp_mem[OCOTP_UID1_OFFSET / sizeof(*ocotp_mem)];

	return res;
}


static inline uint8_t enet_getByte(uint32_t v, int i)
{
	return (v >> (i * 8)) & 0xFF;
}


static uint8_t enet_readBoardRev(volatile uint32_t *ocotp_mem)
{
	uint32_t res = 0;

	/* note: keep in sync with imx6ull-otp */
	res = ocotp_mem[OCOTP_REV_OFFSET / sizeof(*ocotp_mem)];

	return (res >> 24) + 1;
}


static void enet_readCardMac(enet_state_t *state, volatile uint32_t *ocotp_mem)
{
	static const struct eth_addr zero_eth = { { 0, 0, 0, 0, 0, 0 } };

	uint32_t buf[3];
	uint8_t *mac;

	mac = (void *)&state->netif->hwaddr;

	if (state->dev_phys_addr == ENET_ADDR_ENET1 && enet_readFusedMac(buf, ocotp_mem) == 0) {
		mac[0] = enet_getByte(buf[1], 1);
		mac[1] = enet_getByte(buf[1], 0);
		mac[2] = enet_getByte(buf[0], 3);
		mac[3] = enet_getByte(buf[0], 2);
		mac[4] = enet_getByte(buf[0], 1);
		mac[5] = enet_getByte(buf[0], 0);
	}
#if defined(ENET_ADDR_ENET2)
	else if (state->dev_phys_addr == ENET_ADDR_ENET2 && enet_readFusedMac(buf, ocotp_mem) == 0) {
		mac[0] = enet_getByte(buf[2], 3);
		mac[1] = enet_getByte(buf[2], 2);
		mac[2] = enet_getByte(buf[2], 1);
		mac[3] = enet_getByte(buf[2], 0);
		mac[4] = enet_getByte(buf[1], 3);
		mac[5] = enet_getByte(buf[1], 2);
	}
#endif
#if defined(ENET_ADDR_ENET_1G)
	else if (state->dev_phys_addr == ENET_ADDR_ENET_1G && enet_readFusedMac(buf, ocotp_mem) == 0) {
		mac[0] = enet_getByte(buf[2], 3);
		mac[1] = enet_getByte(buf[2], 2);
		mac[2] = enet_getByte(buf[2], 1);
		mac[3] = enet_getByte(buf[2], 0);
		mac[4] = enet_getByte(buf[1], 3);
		mac[5] = enet_getByte(buf[1], 2);
	}
#endif
	else {
		buf[0] = state->mmio->PALR;
		buf[1] = state->mmio->PAUR;

		mac[0] = enet_getByte(buf[0], 3);
		mac[1] = enet_getByte(buf[0], 2);
		mac[2] = enet_getByte(buf[0], 1);
		mac[3] = enet_getByte(buf[0], 0);
		mac[4] = enet_getByte(buf[1], 3);
		mac[5] = enet_getByte(buf[1], 2);
	}

	if (memcmp(mac, &zero_eth.addr, ETH_HWADDR_LEN) == 0) {
		uint32_t cpuId = enet_readCpuId(ocotp_mem);
		enet_debug_printf(state, "MAC address from CPUID");
		mac[0] = 0x02;
		mac[1] = (cpuId >> 24) & 0xFF;
		mac[2] = (cpuId >> 16) & 0xFF;
		mac[3] = (cpuId >> 8) & 0xFF;
		mac[4] = (cpuId >> 0) & 0xFF;
#if defined(__CPU_IMXRT117X)
		mac[5] = state->dev_phys_addr >> 12;
#else
		mac[5] = state->dev_phys_addr >> 16;
#endif
	}

	state->mmio->PALR = be32toh(*(uint32_t *)mac);
	state->mmio->PAUR = (be16toh(*(uint16_t *)(mac + 4)) << 16) | ENET_PAUR_TYPE_RESET_VAL;
}


static void enet_showCardId(enet_state_t *state)
{
	uint8_t *mac = (void *)&state->netif->hwaddr;
	enet_printf(state, "initialized, MAC=%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}


static size_t enet_nextRxBufferSize(const net_bufdesc_ring_t *ring, size_t i)
{
	volatile enet_buf_desc_t *desc = (volatile enet_buf_desc_t *)ring->ring + i;
	size_t sz;

#if 0 && ENET_USE_ENHANCED_DESCRIPTORS
	if ((desc->dflags & ENET_XDESC_DONE) == 0) {
		return 0;
	}
#endif

	if ((desc->flags & ENET_DESC_RDY) != 0) {
		return 0;
	}

	sz = desc->len;
	if (sz == 0) {  // FIXME: hw bug?
		sz = 1;
		printf("lwip: enet: WARNING: This message indicates a potential HW bug:\n");
		printf("lwip: enet: HW provided invalid size: %zu. Setting size to 1\n", sz);
	}
	return sz;
}


static bool enet_pktRxFinished(const net_bufdesc_ring_t *ring, size_t i)
{
	volatile enet_buf_desc_t *desc = (volatile enet_buf_desc_t *)ring->ring + i;

	return ((desc->flags & ENET_DESC_LAST) != 0u);
}


static void enet_fillRxDesc(const net_bufdesc_ring_t *ring, size_t i, addr_t pa, size_t sz, unsigned seg)
{
	volatile enet_buf_desc_t *desc = (volatile enet_buf_desc_t *)ring->ring + i;
	unsigned wrap = desc == (volatile enet_buf_desc_t *)ring->ring + ring->last ? ENET_DESC_WRAP : 0;

	desc->len = sz - ETH_PAD_SIZE;
	desc->addr = pa;
#if ENET_USE_ENHANCED_DESCRIPTORS
	desc->yflags = ENET_RXDY_INT;
#endif

	atomic_thread_fence(memory_order_seq_cst);
	desc->flags = ENET_DESC_RDY | wrap;
	atomic_thread_fence(memory_order_seq_cst);
}


static bool enet_nextTxDone(const net_bufdesc_ring_t *ring, size_t i)
{
	volatile enet_buf_desc_t *desc = (volatile enet_buf_desc_t *)ring->ring + i;

	return ((desc->flags & ENET_DESC_RDY) == 0u);
}


static void enet_fillTxDesc(const net_bufdesc_ring_t *ring, size_t i, addr_t pa, size_t sz, unsigned seg)
{
	volatile enet_buf_desc_t *desc = (volatile enet_buf_desc_t *)ring->ring + i;
	unsigned flags;

	flags = ENET_DESC_RDY | ENET_TXD_TXCRC;
	flags |= (i == ring->last) ? ENET_DESC_WRAP : 0;
	flags |= ((seg & BDRING_SEG_LAST) != 0) ? ENET_DESC_LAST : 0;

	desc->len = sz;
	desc->addr = pa;

#if ENET_USE_ENHANCED_DESCRIPTORS
	unsigned yflags = ENET_TXDY_INT;

	// FIXME
	/*
		if ((oflags & OFLAG_CSUM_IPV4) != 0) {
			yflags |= ENET_TXDY_IPCSUM;
		}
		if ((oflags & (OFLAG_CSUM_UDP | OFLAG_CSUM_TCP)) != 0) {
			yflags |= ENET_TXDY_L4CSUM;
		}
	*/

	desc->yflags = yflags;
#endif

	atomic_thread_fence(memory_order_seq_cst);
	desc->flags = flags;
	atomic_thread_fence(memory_order_seq_cst);
}


static const net_bufdesc_ops_t enet_ring_ops = {
	.nextRxBufferSize = enet_nextRxBufferSize,
	.pktRxFinished = enet_pktRxFinished,
	.fillRxDesc = enet_fillRxDesc,
	.nextTxDone = enet_nextTxDone,
	.fillTxDesc = enet_fillTxDesc,
	.desc_size = sizeof(enet_buf_desc_t),
	.pkt_buf_sz = ENET_MAX_PKT_SZ,
	.ring_alignment = 64,
	.max_tx_frag = 0xFFFF,
};

static const size_t enet_ring_sizes[] = { ENET_RX_RING_SIZE, ENET_TX_RING_SIZE };


static int enet_initRings(enet_state_t *state)
{
	int err;

	err = net_initRings(state->rings, enet_ring_sizes, sizeof(state->rings) / sizeof(*state->rings), &enet_ring_ops);
	if (err != 0) {
		return err;
	}

	state->mmio->RDSR = state->rx.phys;
	state->mmio->TDSR = state->tx.phys;

	return 0;
}


static int enet_irqHandler(unsigned irq, void *arg)
{
	uint32_t events;
	enet_state_t *state = arg;

	events = state->mmio->EIR & (ENET_IRQ_RXF | ENET_IRQ_TXF | ENET_IRQ_EBERR);
	state->mmio->EIMR &= ~(ENET_IRQ_RXF | ENET_IRQ_TXF);

	if ((events & ENET_IRQ_EBERR) != 0) {
		atomic_fetch_or(&state->drv_exit, EV_BUS_ERROR);
	}

	return 0;
}


static void enet_irqThread(void *arg)
{
	enet_state_t *state = arg;
	size_t rx_done = 0;
	unsigned exit;

	mutexLock(state->irq_lock);
	exit = atomic_load(&state->drv_exit);
	while (exit == 0) {
		state->mmio->EIR = ENET_IRQ_RXF;
		rx_done = net_receivePackets(&state->rx, state->netif);
		if (rx_done > 0 || net_rxFullyFilled(&state->rx) == 0) {
			net_refillRx(&state->rx);
			state->mmio->RDAR = ENET_RDAR_RDAR;
		}

		state->mmio->EIR = ENET_IRQ_TXF;
		net_reapTxFinished(&state->tx);

		if ((state->mmio->EIR & (ENET_IRQ_RXF | ENET_IRQ_TXF)) == 0) {
			state->mmio->EIMR |= ENET_IRQ_RXF | ENET_IRQ_TXF;
			condWait(state->irq_cond, state->irq_lock, 0);
		}
		exit = atomic_load(&state->drv_exit);
	}
	mutexUnlock(state->irq_lock);

	if ((exit & EV_BUS_ERROR) != 0) {
		enet_printf(state, "HW signalled memory bus error -- device halted");
	}

	endthread();
}


static int enet_mdioSetup(void *arg, unsigned max_khz, unsigned min_hold_ns, unsigned opt_preamble)
{
	enet_state_t *state = arg;
	int speed, hold;
#if ENET_DEBUG
	bool changed = 0;
#endif
	/* mdc_freq = enet_clk / 2 / (MDIO_SPEED + 1) */

	speed = (ENET_CLK_KHZ / 2 + max_khz - 1) / max_khz - 1;
	if (speed < 1) {
		speed = 1;
	}
	if (speed > (ENET_MSCR_MII_SPEED_MASK >> ENET_MSCR_MII_SPEED_SHIFT)) {
		speed = ENET_MSCR_MII_SPEED_MASK;
	}
	else {
		speed <<= ENET_MSCR_MII_SPEED_SHIFT;
	}
	if (speed > (state->mscr & ENET_MSCR_MII_SPEED_MASK)) {
		state->mscr &= ~ENET_MSCR_MII_SPEED_MASK;
		state->mscr |= speed;
#if ENET_DEBUG
		changed = 1;
#endif
	}

	/* hold can be at most 8 internal module clock cycles */
	if (min_hold_ns < (8 * 1000 * 1000 /* == 8 internal module clock cycles */) / ENET_CLK_KHZ) {
		hold = ((int64_t)min_hold_ns * ENET_CLK_KHZ + ((1000 * 1000) - 1)) / (1000 * 1000) - 1;
	}
	else {
		hold = ENET_MSCR_HOLDTIME_MASK >> ENET_MSCR_HOLDTIME_SHIFT;
	}

	if (hold < 0) {
		hold = 0;
	}
	else if (hold > (ENET_MSCR_HOLDTIME_MASK >> ENET_MSCR_HOLDTIME_SHIFT)) {
		hold = ENET_MSCR_HOLDTIME_MASK;
	}
	else {
		hold <<= ENET_MSCR_HOLDTIME_SHIFT;
	}

	if (hold > (state->mscr & ENET_MSCR_HOLDTIME_MASK)) {
		state->mscr &= ~ENET_MSCR_HOLDTIME_MASK;
		state->mscr |= hold;
#if ENET_DEBUG
		changed = 1;
#endif
	}

	if (opt_preamble == 0 && (state->mscr & ENET_MSCR_DIS_PRE) != 0) {
		state->mscr &= ~ENET_MSCR_DIS_PRE;
#if ENET_DEBUG
		changed = 1;
#endif
	}

#if ENET_DEBUG
	if (changed) {
		speed = (state->mscr & ENET_MSCR_MII_SPEED_MASK) >> ENET_MSCR_MII_SPEED_SHIFT;
		hold = (state->mscr & ENET_MSCR_HOLDTIME_MASK) >> ENET_MSCR_HOLDTIME_SHIFT;
		enet_printf(state, "mdio: speed %u (%u kHz), hold %u (%u ns), %s preamble",
				speed, ENET_CLK_KHZ / 2 / (speed + 1),
				hold, (hold + 1) * 1000000 / ENET_CLK_KHZ,
				((state->mscr & ENET_MSCR_DIS_PRE) != 0) ? "no" : "with");
	}
#endif

#if ENET_MDC_ALWAYS_ON
	state->mmio->MSCR = state->mscr;
#endif

	return 0;
}


static int enet_mdioWait(enet_state_t *state, time_t timeout)
{
	if (timeout != 0) {
		time_t now, when;
		gettime(&now, NULL);
		when = now + timeout;

		while ((state->mmio->EIR & ENET_IRQ_MII) == 0) {
			gettime(&now, NULL);
			if (now >= when) {
				enet_debug_printf(state, "enet_mdioWait: timeout");
				return -ETIMEDOUT;
			}
			usleep(10);
		}
	}
	else {
		while ((state->mmio->EIR & ENET_IRQ_MII) == 0)
			/* relax */;
	}

	state->mmio->EIR = ENET_IRQ_MII;

	return 0;
}


static inline const char *enet_mdioOpToString(unsigned op)
{
	switch (op) {
		case ENET_MMFR_OP_READ_VAL:
			return "READ";
		case ENET_MMFR_OP_WRITE_VAL:
			return "WRITE";
		default:
			return "UNDEFINED";
	}
}


static uint16_t enet_mdioIO(enet_state_t *state, unsigned addr, unsigned reg, unsigned val, unsigned op)
{
#if MDIO_DEBUG
	enet_printf(state, "mdio: op %s, addr=0x%08x, reg=0x%08x, val=0x%04x", enet_mdioOpToString(op), addr, reg, val);
#endif

#if !ENET_MDC_ALWAYS_ON
	state->mmio->MSCR = state->mscr;
#endif

	uint32_t mmfr = 0;

	/* clause 45 */
	if ((addr & NETDEV_MDIO_CLAUSE45) != 0) {
		/* ST */
		mmfr |= ENET_MMFR_ST_CLAUSE45_VAL;

		uint32_t dev = ((addr & NETDEV_MDIO_A_MASK) << 18) |
				((addr & NETDEV_MDIO_B_MASK) << (23 - 8));
		mmfr = (ENET_MMFR_OP_ADDR << ENET_MMFR_OP_SHIFT) | /* extended MDIO data r/w */
				(ENET_MMFR_TA_VAL << ENET_MMFR_TA_SHIFT) | dev | (reg & 0xFFFF);

		state->mmio->MMFR = mmfr;
		if (enet_mdioWait(state, MDIO_TIMEOUT) < 0) {
			enet_printf(state, "WARN: MDIO %s operation timeout", enet_mdioOpToString(op));
		}

		mmfr = (op << ENET_MMFR_OP_SHIFT) | dev | /* standard MDIO data r/w */
				ENET_MMFR_TA_VAL << ENET_MMFR_TA_SHIFT | ((op == ENET_MMFR_OP_READ_VAL) ? 0 : val & ENET_MMFR_DATA_MASK);
	}
	/* clause 22 */
	else {
		mmfr = (ENET_MMFR_ST_CLAUSE22_VAL << ENET_MMFR_ST_SHIFT) |                          /* ST */
				((op << ENET_MMFR_OP_SHIFT) & ENET_MMFR_OP_MASK) |                          /* OP */
				(((addr & NETDEV_MDIO_A_MASK) << ENET_MMFR_PA_SHIFT) & ENET_MMFR_PA_MASK) | /* PA - PHY addr */
				(((reg & NETDEV_MDIO_A_MASK) << ENET_MMFR_RA_SHIFT) & ENET_MMFR_RA_MASK) |  /* RA - reg addr */
				ENET_MMFR_TA_VAL << ENET_MMFR_TA_SHIFT |                                    /* TA */
				((op == ENET_MMFR_OP_READ_VAL) ? 0 : val & ENET_MMFR_DATA_MASK);            /* DATA */
	}

	state->mmio->MMFR = mmfr;
	if (enet_mdioWait(state, MDIO_TIMEOUT) < 0) {
		enet_printf(state, "WARN: MDIO %s operation timeout", enet_mdioOpToString(op));
	}

	val = state->mmio->MMFR & ENET_MMFR_DATA_MASK;

#if !ENET_MDC_ALWAYS_ON
	state->mmio->MSCR = 0;
#endif

	return val;
}


static uint16_t enet_mdioRead(void *arg, unsigned addr, uint16_t reg)
{
	enet_state_t *state = arg;
	return enet_mdioIO(state, addr, reg, 0, ENET_MMFR_OP_READ_VAL);
}


static void enet_mdioWrite(void *arg, unsigned addr, uint16_t reg, uint16_t val)
{
	enet_state_t *state = arg;
	(void)enet_mdioIO(state, addr, reg, val, ENET_MMFR_OP_WRITE_VAL);
}


static const mdio_bus_ops_t enet_mdio_ops = {
	enet_mdioSetup,
	enet_mdioRead,
	enet_mdioWrite,
};


static int platformctl_seq(const platformctl_t pctl[], size_t n)
{
	int err;

	for (int i = 0; i < n; i++) {
		platformctl_t current_pctl = pctl[i];
		err = platformctl(&current_pctl);
		if (err < 0) {
			return err;
		}
	}

	return 0;
}


static inline void enet_warnUnsupportedDeviceAddr(enet_state_t *state)
{
	enet_printf(state, "Unsupported device address 0x%08x\n", state->dev_phys_addr);
	enet_printf(state, "Supported addresses:\n");
#if defined(ENET_ADDR_ENET1)
	printf("\tENET1=0x%08x\n", ENET_ADDR_ENET1);
#endif
#if defined(ENET_ADDR_ENET2)
	printf("\tENET2=0x%08x\n", ENET_ADDR_ENET2);
#endif
#if defined(ENET_ADDR_ENET_1G)
	printf("\tENET_1G=0x%08x\n", ENET_ADDR_ENET_1G);
#endif
}


/*
 * Configure MDIO pins for the required ENET module
 */
static int enet_initMDIO(enet_state_t *state)
{
	int err;

#if defined(__CPU_IMXRT106X)

	const platformctl_t pctl_enet[] = {
		/* 0: GPIO_AD_B1_05_ALT1, 1: GPIO_EMC_41_ALT4, 2: GPIO_B1_15_ALT0 */
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_mdio, 1 } },

		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_emc_40, 0, 2, 1, 1, 0, 3, 5, 1 } }, /* enet_mdc */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_emc_41, 0, 2, 1, 1, 1, 0, 5, 1 } }, /* enet_mdio */

		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_emc_40, 0, 4 } }, /* enet_mdc */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_emc_41, 0, 4 } }, /* enet_mdio */
	};
	if (state->dev_phys_addr != ENET_ADDR_ENET1) {
		enet_warnUnsupportedDeviceAddr(state);
		return -ENODEV;
	}
	err = platformctl_seq(pctl_enet, sizeof(pctl_enet) / sizeof(*pctl_enet));

#elif defined(__CPU_IMXRT117X)

	const platformctl_t pctl_enet[] = {
		// IOMUXC.DAISY
		// 0: GPIO_EMC_B2_20_ALT1, 1: GPIO_AD_33_ALT3
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_mac0_mdio, 1 } },

		// IOMUXC.MUX
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_ad_32, 0, 3 } },  // mdc
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_ad_33, 0, 3 } },  // mdio

		// IOMUXC.PAD
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_ad_32, .sre = 0, .dse = 1, .pue = 1, .pus = 0, .ode = 0 } },  // mdc
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_ad_33, .sre = 0, .dse = 1, .pue = 1, .pus = 0, .ode = 0 } },  // mdio
	};
	const platformctl_t pctl_enet_1g[] = {
		/* 0: GPIO_EMC_B1_41_ALT7, 1: GPIO_EMC_B2_20_ALT2, 2: GPIO_AD_17_ALT9, 3: GPIO_AD_33_ALT9 */
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_1g_mac0_mdio, 1 } },

		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_emc_b2_19, 0, 2 } }, /* mdc */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_emc_b2_20, 0, 2 } }, /* mdio */

		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_emc_b2_19, .pus = 1, .pue = 1, .ode = 0, .dse = 0 } }, /* mdc */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_emc_b2_20, .pus = 1, .pue = 1, .ode = 0, .dse = 0 } }, /* mdio */
	};

	if (state->dev_phys_addr == ENET_ADDR_ENET1) {
		err = platformctl_seq(pctl_enet, sizeof(pctl_enet) / sizeof(*pctl_enet));
	}
	else if (state->dev_phys_addr == ENET_ADDR_ENET_1G) {
		err = platformctl_seq(pctl_enet_1g, sizeof(pctl_enet_1g) / sizeof(*pctl_enet_1g));
	}
	else {
		enet_warnUnsupportedDeviceAddr(state);
		return -ENODEV;
	}

#elif defined(__CPU_IMX6ULL)

	const platformctl_t pctl_enet1[] = {
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet1_mac0mdio, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio1_06, 0, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio1_07, 0, 0 } },
	};
	const platformctl_t pctl_enet2[] = {
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet2_mac0mdio, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio1_06, 0, 1 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio1_07, 0, 1 } },
	};

	if (state->dev_phys_addr == ENET_ADDR_ENET1) {
		err = platformctl_seq(pctl_enet1, sizeof(pctl_enet1) / sizeof(*pctl_enet1));
	}
	else if (state->dev_phys_addr == ENET_ADDR_ENET2) {
		err = platformctl_seq(pctl_enet2, sizeof(pctl_enet2) / sizeof(*pctl_enet2));
	}
	else {
		enet_warnUnsupportedDeviceAddr(state);
		return -ENODEV;
	}

#else

#error "Unsupported TARGET"

#endif

	if (err < 0) {
		enet_printf(state, "Couldn't configure MDIO pins");
		return err;
	}

	state->mscr = (1 << ENET_MSCR_MII_SPEED_SHIFT) | ENET_MSCR_DIS_PRE;

	return 0;
}


/*
 * Enable clock for the required ENET module
 */
static int enet_clockEnable(enet_state_t *state)
{
	int err;
#if defined(__CPU_IMXRT106X)

	const platformctl_t pctl_enet_clock = {
		pctl_set, pctl_devclock, .devclock = { pctl_clk_enet, clk_state_run_wait }
	};
	if (state->dev_phys_addr != ENET_ADDR_ENET1) {
		enet_warnUnsupportedDeviceAddr(state);
		return -ENODEV;
	}
	err = platformctl_seq(&pctl_enet_clock, 1);

#elif defined(__CPU_IMXRT117X)

	const platformctl_t pctl_enet_clock[] = {
		/* mux: 4: SYS PLL1DIV2	*/
		{ pctl_set, pctl_devclock, .devclock = { .dev = pctl_clk_enet1, .mux = 4, .div = 9, .state = 1 } },
		{ pctl_set, pctl_iogpr, .iogpr = { .field = 4, .val = (1 << 1) } } /* ENET1 RMII TX clk output enable */
	};
	const platformctl_t pctl_enet_1g_clock[] = {
		/* mux: 4: SYS PLL1DIV2 */
		{ pctl_set, pctl_devclock, .devclock = { .dev = pctl_clk_enet2, .mux = 4, .div = 3, .state = 1 } },
		{ pctl_set, pctl_iogpr, .iogpr = { .field = 5, .val = (1 << 2) } }, /* ENET1G RGMII TX clk output enable */
	};

	if (state->dev_phys_addr == ENET_ADDR_ENET1) {
		err = platformctl_seq(pctl_enet_clock, sizeof(pctl_enet_clock) / sizeof(*pctl_enet_clock));
	}
	else if (state->dev_phys_addr == ENET_ADDR_ENET_1G) {
		err = platformctl_seq(pctl_enet_1g_clock, sizeof(pctl_enet_1g_clock) / sizeof(*pctl_enet_1g_clock));
	}
	else {
		enet_warnUnsupportedDeviceAddr(state);
		return -ENODEV;
	}

	enet_debug_printf(state, "SYS_PLL1_CTRL = 0x%08x", hwdebug_read(0x40c842c0));

#elif defined(__CPU_IMX6ULL)

	const platformctl_t pctl_enet_clock = {
		pctl_set, pctl_devclock, .devclock = { pctl_clk_enet, 3 }
	};
	if (state->dev_phys_addr != ENET_ADDR_ENET1 && state->dev_phys_addr != ENET_ADDR_ENET2) {
		enet_warnUnsupportedDeviceAddr(state);
		return -ENODEV;
	}
	err = platformctl_seq(&pctl_enet_clock, 1);

#else

#error "Unsupported TARGET"

#endif

	if (err < 0) {
		enet_printf(state, "Couldn't enable ENET clocks");
	}
	return err;
}


/*
 * Set pin config for the required ENET module
 */
static int enet_pinConfig(enet_state_t *state)
{
	int err;

#if defined(__CPU_IMXRT106X)

	const platformctl_t pctl_enet[] = {
		/* IOMUXC.GPR (RM 11.3.2) */
		/* 0: ENET1_TX ref clk driven by ref_enetpll (ENET_REF_CLK1), 1: ENET1_TX */
		/* ref clock from ENET_T1_CLK */
		{ pctl_set, pctl_iogpr, .iogpr = { pctl_gpr_enet1_clk_sel, 0 } },
		/* 0: disabled, 1: enabled */
		{ pctl_set, pctl_iogpr, .iogpr = { pctl_gpr_enet1_tx_clk_dir, 1 } },
		/* 0: ipg_clk gated when no IPS access, 1: ipg_clk always ON */
		{ pctl_set, pctl_iogpr, .iogpr = { pctl_gpr_enet_ipg_clk_s_en, 1 } },
		/* 0: GPIO1, 1: GPIO6 */
		{ pctl_set, pctl_iogpr, .iogpr = { pctl_gpr_gpio_mux1_gpio_sel, 0 } },

		/* IOMUXC.DAISY (RM 11.3.6) */
		/* 0: GPIO_EMC_26_ALT3, 1: GPIO_B1_11_ALT3 */
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_rxerr, 1 } },
		/* 0: GPIO_EMC_23_ALT3, 1: GPIO_B1_06_ALT3 */
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_rxen, 1 } },
		/* 0: GPIO_EMC_19_ALT3, 1: GPIO_B1_05_ALT3 */
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet1_rxdata, 1 } },
		/* 0: GPIO_B0_00_ALT3, 1: GPIO_B1_04_ALT3 */
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet0_rxdata, 1 } },
		/* 0: GPIO_EMC_25_ALT24, 1: GPIO_B1_10_ALT6 */
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_ipg_clk_rmi, 1 } },

		/* IOMUXC.PAD */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_b1_04, 0, 2, 1, 1, 0, 3, 6, 1 } }, /* enet1_rx0 */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_b1_05, 0, 2, 1, 1, 0, 3, 6, 1 } }, /* enet1_rx1 */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_b1_06, 0, 2, 1, 1, 0, 3, 6, 1 } }, /* enet1_rx_en (crs_dv) */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_b1_07, 0, 2, 1, 1, 0, 3, 6, 1 } }, /* enet1_tx0 */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_b1_08, 0, 2, 1, 1, 0, 3, 6, 1 } }, /* enet1_tx1 */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_b1_09, 0, 2, 1, 1, 0, 3, 6, 1 } }, /* enet1_txen */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_b1_10, 0, 0, 0, 0, 0, 3, 6, 1 } }, /* enet1_txclk */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_b1_11, 0, 2, 1, 1, 0, 3, 6, 1 } }, /* enet1_rxer */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_ad_b0_10, 0, 2, 1, 1, 0, 2, 4, 1 } }, /* irq */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_ad_b0_09, 0, 2, 1, 1, 0, 2, 6, 1 } }, /* rst */

		// IOMUXC.MUX
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_04, 0, 3 } },    /* enet1_rx0 */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_05, 0, 3 } },    /* enet1_rx1 */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_06, 0, 3 } },    /* enet1_rx_en (crs_dv) */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_07, 0, 3 } },    /* enet1_tx0 */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_08, 0, 3 } },    /* enet1_tx1 */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_09, 0, 3 } },    /* enet1_txen */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_10, 1, 6 } },    /* enet_ref_clk */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_11, 0, 3 } },    /* enet1_rxer */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_ad_b0_10, 0, 5 } }, /* irq (enet_int) */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_ad_b0_09, 0, 5 } }, /* rst (enet_rst) */
	};
	if (state->dev_phys_addr != ENET_ADDR_ENET1) {
		enet_warnUnsupportedDeviceAddr(state);
		return -ENODEV;
	}
	err = platformctl_seq(pctl_enet, sizeof(pctl_enet) / sizeof(*pctl_enet));

#elif defined(__CPU_IMXRT117X)

	static const platformctl_t pctl_enet[] = {
		// IOMUXC.DAISY
		// 0: GPIO_AD_29_ALT3, 1: GPIO_DISP_B2_05_ALT1
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_mac0_txclk, 1 } },
		// 0: GPIO_AD_25_ALT3, 1: GPIO_DISP_B2_09_ALT1
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_mac0_rxerr, 1 } },
		// 0: GPIO_EMC_B2_24_ALT3, 1: GPIO_SD_B2_08_ALT1
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_mac0_rxen, 1 } },  // AKA: enet_crs_dv
		// 0: GPIO_AD_27_ALT3, 1: GPIO_DISP_B2_07_ALT1
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_mac0_rxdata_1, 1 } },
		// 0: GPIO_AD_26_ALT3, 1: GPIO_DISP_B2_06_ALT1
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_mac0_rxdata_0, 1 } },
		// 0: GPIO_AD_29_ALT2, 1: GPIO_DISP_B2_05_ALT2, 2: GPIO_DISP_B2_13_ALT4
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_ipg_clk_rmii, 1 } },

		// IOMUXC.MUX
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b2_02, 0, 1 } },  // enet1_txd0
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b2_03, 0, 1 } },  // enet1_txd1
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b2_04, 0, 1 } },  // enet1_txen
		// 1: ENET_TX_CLK, 2: ENET_REF_CLK1
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b2_05, 1, 2 } },  // enet_ref_clk (txclk)
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b2_06, 1, 1 } },  // enet1_rxd0
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b2_07, 1, 1 } },  // enet1_rxd1
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b2_08, 0, 1 } },  // enet1_rx_en (crs_dv)
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b2_09, 0, 1 } },  // enet1_rxer
		// 5: GPIO_MUX3_IO11, 10: GPIO9_IO11
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_ad_12, 0, 10 } },  // irq (enet_int)
		// 5: GPIO_MUX6_IO12, 10: GPIO12_IO12
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_lpsr_12, 0, 10 } },  // rst (enet_rst)

		// IOMUXC.PAD
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b2_02, .pue = 0, .pus = 0, .ode = 0, .dse = 1, .sre = 0 } },  // enet_txd0
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b2_03, .pue = 0, .pus = 0, .ode = 0, .dse = 1, .sre = 0 } },  // enet_txd1
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b2_04, .pue = 0, .pus = 0, .ode = 0, .dse = 1, .sre = 0 } },  // enet_txen
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b2_05, .pue = 0, .pus = 0, .ode = 0, .dse = 1, .sre = 1 } },  // enet_txclk
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b2_06, .pue = 1, .pus = 0, .ode = 0, .dse = 1, .sre = 0 } },  // enet_rxd0
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b2_07, .pue = 1, .pus = 0, .ode = 0, .dse = 1, .sre = 0 } },  // enet_rxd1
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b2_08, .pue = 1, .pus = 0, .ode = 0, .dse = 1, .sre = 0 } },  // enet_rx_en (crs_dv)
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b2_09, .pue = 1, .pus = 0, .ode = 0, .dse = 1, .sre = 0 } },  // enet_rxer

		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_ad_12, .pue = 1, .pus = 0, .ode = 0, .dse = 1, .sre = 0 } },  // irq
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_lpsr_12, .pue = 1, .pus = 1, .ode = 0, .dse = 1, .sre = 0 } },  // rst
	};
	static const platformctl_t pctl_enet_1g[] = {
		/* IOMUXC.DAISY */
		/* 0: GPIO_EMC_B2_17_ALT2, 1: GPIO_SD_B2_00_ALT2, 2: GPIO_DISP_B1_00_ALT1 */
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_1g_mac0_rxen, 2 } },
		/* 0: GPIO_EMC_B2_05_ALT7, 1: GPIO_SD_B2_01_ALT2, 2: GPIO_DISP_B1_01_ALT1 */
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_1g_mac0_rxclk, 2 } },
		/* 0: GPIO_EMC_B2_07_ALT7, 1: GPIO_SD_B2_05_ALT2, 2: GPIO_DISP_B1_05_ALT1 */
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_1g_mac0_rxdata_3, 2 } },
		/* 0: GPIO_EMC_B2_08_ALT7, 1: GPIO_SD_B2_04_ALT2, 2: GPIO_DISP_B1_04_ALT1 */
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_1g_mac0_rxdata_2, 2 } },
		/* 0: GPIO_EMC_B2_16_ALT2, 1: GPIO_SD_B2_03_ALT2, 2: GPIO_DISP_B1_03_ALT1 */
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_1g_mac0_rxdata_1, 2 } },
		/* 0: GPIO_EMC_B2_15_ALT2, 1: GPIO_SD_B2_02_ALT2, 2: GPIO_DISP_B1_02_ALT1 */
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_1g_mac0_rxdata_0, 2 } },
		/* 0: GPIO_EMC_B2_14_ALT2, 1: GPIO_SD_B2_11_ALT2, 2: GPIO_DISP_B1_11_ALT1 */
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_1g_mac0_txclk, 2 } },

		/* IOMUXC.MUX */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b1_00, 0, 1 } }, /* enet_rgmii_rx_en */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b1_01, 0, 1 } }, /* enet_rgmii_rxc */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b1_02, 0, 1 } }, /* enet_rgmii_rxd0 */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b1_03, 0, 1 } }, /* enet_rgmii_rxd1 */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b1_04, 0, 1 } }, /* enet_rgmii_rxd2 */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b1_05, 0, 1 } }, /* enet_rgmii_rxd3 */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b1_06, 0, 1 } }, /* enet_rgmii_txd3 */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b1_07, 0, 1 } }, /* enet_rgmii_txd2 */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b1_08, 0, 1 } }, /* enet_rgmii_txd1 */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b1_09, 0, 1 } }, /* enet_rgmii_txd0 */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b1_10, 0, 1 } }, /* enet_rgmii_tx_en */
		/* 1: ENET_1G_TX_CLK_IO, 2: ENET_1G_REF_CLK */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b1_11, 0, 1 } }, /* enet_rgmii_txc */
		/* 5: GPIO_MUX5_IO13, 10: GPIO11_IO13 */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b2_12, 0, 10 } }, /* irq (enet_int) */
		/* 10: GPIO11_IO14 */
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_disp_b2_13, 0, 10 } }, /* rst (enet_rst) */

		/* IOMUXC.PAD */
		/* PULL:
			if (pue == 0)      PULL = 3;
			else if (pus != 0) PULL = 1;
			else               PULL = 2;
		   PDRV = dse
		   no sre
		*/
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b1_00, .pue = 1, .pus = 1, .ode = 0, .dse = 0 } }, /* enet_rxen */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b1_01, .pue = 1, .pus = 1, .ode = 0, .dse = 0 } }, /* enet_rxclk */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b1_02, .pue = 1, .pus = 1, .ode = 0, .dse = 0 } }, /* enet_rxdata_0 */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b1_03, .pue = 1, .pus = 1, .ode = 0, .dse = 0 } }, /* enet_rxdata_1 */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b1_04, .pue = 1, .pus = 1, .ode = 0, .dse = 0 } }, /* enet_rxdata_2 */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b1_05, .pue = 1, .pus = 1, .ode = 0, .dse = 0 } }, /* enet_rxdata_3 */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b1_06, .pue = 0, .pus = 0, .ode = 0, .dse = 0 } }, /* enet_txdata_3 */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b1_07, .pue = 0, .pus = 0, .ode = 0, .dse = 0 } }, /* enet_txdata_2 */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b1_08, .pue = 0, .pus = 0, .ode = 0, .dse = 0 } }, /* enet_txdata_1 */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b1_09, .pue = 0, .pus = 0, .ode = 0, .dse = 0 } }, /* enet_txdata_0 */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b1_10, .pue = 0, .pus = 0, .ode = 0, .dse = 0 } }, /* enet_txen */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b1_11, .pue = 0, .pus = 0, .ode = 0, .dse = 0 } }, /* enet_txclk */

		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b2_12, .pue = 1, .pus = 0, .ode = 0, .dse = 0, .sre = 0 } }, /* irq */
		{ pctl_set, pctl_iopad,
			.iopad = { pctl_pad_gpio_disp_b2_13, .pue = 1, .pus = 0, .ode = 0, .dse = 0, .sre = 0 } }, /* rst */
	};

	if (state->dev_phys_addr == ENET_ADDR_ENET1) {
		err = platformctl_seq(pctl_enet, sizeof(pctl_enet) / sizeof(*pctl_enet));
	}
	else if (state->dev_phys_addr == ENET_ADDR_ENET_1G) {
		err = platformctl_seq(pctl_enet_1g, sizeof(pctl_enet_1g) / sizeof(*pctl_enet_1g));
	}
	else {
		enet_warnUnsupportedDeviceAddr(state);
		return -ENODEV;
	}

#elif defined(__CPU_IMX6ULL)

	const platformctl_t pctl_enet1[] = {
		{ pctl_set, pctl_iogpr, .iogpr = { pctl_gpr_enet1_clk, 0 } },
		{ pctl_set, pctl_iogpr, .iogpr = { pctl_gpr_enet1_tx, 1 } },
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet1_refclk1, 2 } },
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_enet1_rx0, 1, 2, 1, 1, 0, 2, 6, 0 } },
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_enet1_rx1, 1, 2, 1, 1, 0, 2, 6, 0 } },
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_enet1_rxen, 1, 2, 1, 1, 0, 2, 6, 0 } },
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_enet1_rxer, 1, 2, 1, 1, 0, 2, 6, 0 } },
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_enet1_tx0, 1, 2, 1, 1, 0, 2, 6, 0 } },
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_enet1_tx1, 1, 2, 1, 1, 0, 2, 6, 0 } },
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_enet1_txen, 1, 2, 1, 1, 0, 2, 6, 0 } },
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_enet1_txclk, 1, 0, 0, 0, 0, 0, 6, 1 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_enet1_rx0, 0, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_enet1_rx1, 0, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_enet1_rxen, 0, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_enet1_rxer, 0, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_enet1_tx0, 0, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_enet1_tx1, 0, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_enet1_txen, 0, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_enet1_txclk, 1, 4 } },
		// SION(1) = enable clk loopback to ENET module?
		// (RX does not work without it)
	};
	static const platformctl_t pctl_enet2[] = {
		{ pctl_set, pctl_iogpr, .iogpr = { pctl_gpr_enet2_clk, 0 } },
		{ pctl_set, pctl_iogpr, .iogpr = { pctl_gpr_enet2_tx, 1 } },
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet2_refclk2, 2 } },
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_enet2_rx0, 1, 2, 1, 1, 0, 2, 6, 0 } },
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_enet2_rx1, 1, 2, 1, 1, 0, 2, 6, 0 } },
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_enet2_rxen, 1, 2, 1, 1, 0, 2, 6, 0 } },
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_enet2_rxer, 1, 2, 1, 1, 0, 2, 6, 0 } },
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_enet2_tx0, 1, 2, 1, 1, 0, 2, 6, 0 } },
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_enet2_tx1, 1, 2, 1, 1, 0, 2, 6, 0 } },
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_enet2_txen, 1, 2, 1, 1, 0, 2, 6, 0 } },
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_enet2_txclk, 1, 0, 0, 0, 0, 0, 6, 1 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_enet2_rx0, 0, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_enet2_rx1, 0, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_enet2_rxen, 0, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_enet2_rxer, 0, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_enet2_tx0, 0, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_enet2_tx1, 0, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_enet2_txen, 0, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_enet2_txclk, 1, 4 } },
	};

	if (state->dev_phys_addr == ENET_ADDR_ENET1) {
		err = platformctl_seq(pctl_enet1, sizeof(pctl_enet1) / sizeof(*pctl_enet1));
	}
	else if (state->dev_phys_addr == ENET_ADDR_ENET2) {
		err = platformctl_seq(pctl_enet2, sizeof(pctl_enet2) / sizeof(*pctl_enet2));
	}
	else {
		enet_warnUnsupportedDeviceAddr(state);
		return -ENODEV;
	}

#else

#error "Unsupported TARGET"

#endif

	if (err < 0) {
		enet_printf(state, "Couldn't configure ENET pins");
		return err;
	}

	uint16_t rcr =
#if ENET_RMII_MODE
			ENET_RCR_RMII_MODE |
#endif
			ENET_RCR_MII_MODE;
#if defined(ENET_ADDR_ENET_1G) && ENET_RGMII_MODE
	if (state->dev_phys_addr == ENET_ADDR_ENET_1G) {
		rcr = (rcr & ~ENET_RCR_RMII_MODE) | ENET_RCR_RGMII_EN;
	}
#endif
	state->mmio->RCR = rcr;

	return 0;
}


static int enet_initDevice(enet_state_t *state, int irq, bool mdio, volatile uint32_t *ocotp_mem)
{
	// FIXME: cleanup on error
	int err;

	state->mmio = physmmap(state->dev_phys_addr, 0x1000);
	if (state->mmio == MAP_FAILED) {
		enet_printf(state, "enet_initDevice: no memory");
		return -ENOMEM;
	}

	err = create_mutexcond_bulk(PRIV_RESOURCES(state));
	if (err != 0) {
		return err;
	}

	atomic_init(&state->drv_exit, 0x0);

	err = enet_clockEnable(state);
	if (err < 0) {
		return err;
	}
	enet_debug_printf(state, "Enabled clock");

	err = enet_reset(state, 100 * 1000);
	if (err < 0) {
		return err;
	}

	enet_readCardMac(state, ocotp_mem);

	err = enet_pinConfig(state);
	if (err != 0) {
		enet_debug_printf(state, "Couldn't configure pins: %s (%d)", strerror(-err), err);
		return err;
	}
	else {
		enet_debug_printf(state, "Pins configured");
	}

	if (mdio) {
		err = enet_initMDIO(state);
		if (err < 0) {
			return err;
		}
		enet_debug_printf(state, "Initialized MDIO");
	}

	err = enet_initRings(state);
	if (err != 0) {
		return err;
	}
	enet_debug_printf(state, "Initialized ENET Rings");

	enet_debug_printf(state, "mmio 0x%x irq %d", state->dev_phys_addr, irq);

	err = interrupt(irq, enet_irqHandler, state, state->irq_cond, &state->irq_handle);
	if (err != 0) {
		enet_printf(state, "Couldn't register interrupt handler: %s (%d)", strerror(-err), err);
		return err;
	}
	enet_debug_printf(state, "Interrupt handler initialized successfully");

	err = beginthread(enet_irqThread, 4, state->irq_stack, sizeof(state->irq_stack), state);
	if (err != 0) {
		enet_printf(state, "Couldn't begin interrupt thread: %s (%d)", strerror(-err), err);
		return err;
	}

	if (mdio) {
		err = register_mdio_bus(&enet_mdio_ops, state);
		if (err < 0) {
			enet_printf(state, "Can't register MDIO bus:  %s (%d)", strerror(-err), err);
			return err;
		}

		enet_debug_printf(state, "MDIO bus %d", err);
	}

	net_refillRx(&state->rx);
	enet_start(state);

	enet_showCardId(state);

	return 0;
}


static err_t enet_netifOutput(struct netif *netif, struct pbuf *p)
{
	enet_state_t *state = netif->state;
	size_t nf;

	if (ETH_PAD_SIZE != 2) {
		(void)pbuf_header(p, -ETH_PAD_SIZE); /* drop the padding word */
	}

	mutexLock(state->tx_lock);
	nf = net_transmitPacket(&state->tx, p);
	if (nf != 0) {
		state->mmio->TDAR = ENET_TDAR_TDAR;
	}
	mutexUnlock(state->tx_lock);

	return nf ? ERR_OK : ERR_BUF;
}

static void enet_setLinkState(void *arg, int state)
{
	struct netif *netif = arg;
	enet_state_t *priv = netif->state;
	int speed;

	if (state != 0) {
		speed = ephy_linkSpeed(&priv->phy, NULL);

#if defined(ENET_ADDR_ENET_1G)
		if (priv->dev_phys_addr == ENET_ADDR_ENET_1G) {
			if (speed == 1000) {
				priv->mmio->ECR |= ENET_ECR_SPEED;
			}
			else {
				priv->mmio->ECR &= ~ENET_ECR_SPEED;
			}
		}
#endif
		if (speed == 10) {
			priv->mmio->RCR |= ENET_RCR_RMII_10T;
		}
		else if (speed == 100) {
			priv->mmio->RCR &= ~ENET_RCR_RMII_10T;
		}

		netif_set_link_up(netif);
	}
	else {
		netif_set_link_down(netif);
	}
}


#if ENET_SELFTEST
#define _TP_DST     "dddddd"
#define _TP_SRC     "ssssss"
#define _TP_ETHTYPE "\x05\xDD" /* eth frame type 0x05DD is undefined */
#define _TP_10DIG   "0123456789"
#define TEST_PACKET _TP_DST _TP_SRC _TP_ETHTYPE \
		_TP_10DIG _TP_10DIG _TP_10DIG _TP_10DIG _TP_10DIG _TP_10DIG _TP_10DIG
#define TEST_PACKET_LEN (sizeof((TEST_PACKET)) - 1)


/* self-test RX input function */
static err_t enet_testNetifInput(struct pbuf *p, struct netif *netif)
{
	uint8_t buf[TEST_PACKET_LEN]; /* used only if pbuf is fragmented (should not happen) */
	enet_state_t *state = netif->state;

	bool is_valid_pkt = true;

	/* verify contents */
	if (p->len != (TEST_PACKET_LEN + ETH_PAD_SIZE)) {
		enet_debug_printf(state, "self-test RX: invalid packet length");
		enet_debug_printf(state, "expected: %uB", (TEST_PACKET_LEN + ETH_PAD_SIZE));
		enet_debug_printf(state, "actual:   %uB", p->len);
		is_valid_pkt = false;
	}
	uint8_t *data = pbuf_get_contiguous(p, buf, sizeof(buf), TEST_PACKET_LEN, ETH_PAD_SIZE);
	if (data == NULL || memcmp(TEST_PACKET, data, TEST_PACKET_LEN) != 0) {
#if ENET_DEBUG
		if (data == NULL) {
			data = p->payload;
		}
		enet_printf(state, "self-test RX: invalid packet contents");

		enet_printf(state, "expected:");
		for (int i = 0; i < TEST_PACKET_LEN; i++) {
			if (i != 0 && i % 16 == 0) {
				printf("\n");
			}
			printf("%02x ", TEST_PACKET[i]);
		}
		printf("\n");

		enet_printf(state, "actual:");
		for (int i = 0; i < p->len; i++) {
			if (i != 0 && i % 16 == 0) {
				printf("\n");
			}
			printf("%02x ", data[i]);
		}
		printf("\n");
#endif
		is_valid_pkt = false;
	}
	pbuf_free(p);

	mutexLock(state->selfTest.rx_lock);
	state->selfTest.rx_valid = is_valid_pkt ? 1 : -1;
	mutexUnlock(state->selfTest.rx_lock);
	condBroadcast(state->selfTest.rx_cond);

	return ERR_OK;
}


/* MACPHY self-test procedure (internal loopback) */
static int enet_phySelfTest(struct netif *netif)
{
	enet_state_t *state = netif->state;
	int err;
	bool was_addins_set;

	enet_printf(state, "Start enet phy tx/rx selftest");

	err = create_mutexcond_bulk(SELFTEST_RESOURCES(state));
	if (err != 0) {
		return err;
	}

	/* setup self-test (local loopback mode & force linkup) */
	if (ephy_enableLoopback(&state->phy, true) < 0) {
		ephy_enableLoopback(&state->phy, false);
		resourceDestroy(state->selfTest.rx_cond);
		resourceDestroy(state->selfTest.rx_lock);
		return -1;
	}

	/* enable promisicious mode to allow invalid MAC in pseudo-ETH test packet */
	state->mmio->RCR |= ENET_RCR_PROM;

	/* disable MAC address addition on TX */
	was_addins_set = (state->mmio->TCR & ENET_TCR_ADDINS) != 0;
	state->mmio->TCR &= ~ENET_TCR_ADDINS;

	/* enable MIB counters (mmio->stats) + clear stats */
	state->mmio->MIBC = 0;
	state->mmio->MIBC |= ENET_MIBC_MIB_CLEAR;
	state->mmio->MIBC &= ~ENET_MIBC_MIB_CLEAR;

	/* override netif->input */
	netif_input_fn old_input = netif->input;
	netif->input = &enet_testNetifInput;

	int ret = 0;
	do {
		struct pbuf *p = pbuf_alloc(PBUF_RAW, TEST_PACKET_LEN + ETH_PAD_SIZE, PBUF_RAM);
		memset(p->payload, 0, ETH_PAD_SIZE);
		pbuf_take_at(p, TEST_PACKET, TEST_PACKET_LEN, ETH_PAD_SIZE);

		/* try to send and receive packets */
		mutexLock(state->selfTest.rx_lock);
		state->selfTest.rx_valid = 0;
		if (enet_netifOutput(netif, p) != ERR_OK) { /* frees pbuf internally */
			enet_printf(state, "failed to send test packet");
			ret = -1;
			mutexUnlock(state->selfTest.rx_lock);
			break;
		}

		err = 0;
		while ((err != -ETIME) && (state->selfTest.rx_valid == 0)) {
			/* TX -> RX takes ~4ms, wait for 100ms just to be sure */
			err = condWait(state->selfTest.rx_cond, state->selfTest.rx_lock, 100 * 1000);
		}
		mutexUnlock(state->selfTest.rx_lock);

		enet_debug_printf(state, "stats: TX: PACKETS=%u CRC_ALIGN=%u OK=%u",
				state->mmio->stats.RMON_T_PACKETS,
				state->mmio->stats.RMON_T_CRC_ALIGN,
				state->mmio->stats.IEEE_T_FRAME_OK);

		enet_debug_printf(state, "stats: RX: PACKETS=%u CRC_ALIGN=%u OK=%u",
				state->mmio->stats.RMON_R_PACKETS,
				state->mmio->stats.RMON_R_CRC_ALIGN,
				state->mmio->stats.IEEE_R_FRAME_OK);

		if ((err < 0) || (state->selfTest.rx_valid != 1)) {
			enet_debug_printf(state, "Test failed: state->selfTest.rx_valid=%d, %s (%d)",
					state->selfTest.rx_valid, strerror(-err), err);
			ret = -1;
		}

		/* successfully received */
	} while (0);

	/* restore normal mode */
	netif->input = old_input;
	state->mmio->RCR &= ~ENET_RCR_PROM;
	if (was_addins_set) {
		state->mmio->TCR |= ENET_TCR_ADDINS;
	}
	state->mmio->MIBC = ENET_MIBC_MIB_DIS;
	ephy_enableLoopback(&state->phy, false);

	/* destroy selftest resources */
	resourceDestroy(state->selfTest.rx_cond);
	resourceDestroy(state->selfTest.rx_lock);

	return ret;
}
#endif


/* ARGS: enet:base:irq[:no-mdio][:PHY:[model:][bus.]addr[:config]] */
static int enet_netifInit(struct netif *netif, char *cfg)
{
	enet_state_t *state;
	char *p;
	int err, irq;
	bool mdio = true;
	volatile uint32_t *ocotp_mem;

	netif->linkoutput = enet_netifOutput;
	state = netif->state;
	state->netif = netif;

	if (cfg == NULL) {
		return -EINVAL;
	}

	/* base addr */
	state->dev_phys_addr = strtoul(cfg, &p, 0);
	if (*cfg == '\0' || *p++ != ':') {
		return -EINVAL;
	}

	/* irq */
	cfg = p;
	irq = strtoul(cfg, &p, 0);
	if (*cfg == '\0' || (*p != '\0' && *p++ != ':') || irq < 0) {
		return -EINVAL;
	}

	/* MDIO and PHY opts */
	cfg = NULL;
	while (p != NULL && *p != '\0') {
		cfg = strchr(p, ':');
		if (cfg != NULL) {
			*cfg++ = '\0';
		}

		if (strcmp(p, "no-mdio") == 0) {
			mdio = false;
			p = cfg;
			continue;
		}

		if (strcmp(p, "PHY") == 0) {
			break;
		}

		return -EINVAL;
	}

	ocotp_mem = physmmap(OCOTP_MEMORY_ADDR, 0x1000);
	if (ocotp_mem == MAP_FAILED) {
		return -ENOMEM;
	}

	err = enet_initDevice(state, irq, mdio, ocotp_mem);
	if (err != 0) {
		physunmap(ocotp_mem, 0x1000);
		enet_printf(state, "Failed to initialize ENET");
		return err;
	}
	enet_debug_printf(state, "Initialized ENET");

	if (cfg != NULL) {
		uint8_t board_rev = enet_readBoardRev(ocotp_mem);

		enet_debug_printf(state, "Board rev: %d (0x%x)", board_rev, board_rev);

		err = ephy_init(&state->phy, cfg, board_rev, enet_setLinkState, (void *)state->netif);
		if (err < 0) {
			enet_printf(state, "WARN: PHY init failed: %s (%d)", strerror(-err), err);
			physunmap(ocotp_mem, 0x1000);
			return err;
		}

#if ENET_SELFTEST
		err = enet_phySelfTest(netif);
		if (err < 0) {
			enet_printf(state, "WARN: PHY autotest failed");
		}
		else {
			enet_printf(state, "PHY selftest passed successfully");
		}
#endif
	}

	physunmap(ocotp_mem, 0x1000);

	return 0;
}


const char *enet_media(struct netif *netif)
{
	int full_duplex, speed;
	enet_state_t *state;
	state = netif->state;

	speed = ephy_linkSpeed(&state->phy, &full_duplex);

	switch (speed) {
		case 0:
			return "unspecified";
		case 10:
			if (full_duplex != 0) {
				return "10Mbps/full-duplex";
			}
			else {
				return "10Mbps/half-duplex";
			}
		case 100:
			if (full_duplex != 0) {
				return "100Mbps/full-duplex";
			}
			else {
				return "100Mbps/half-duplex";
			}
		case 1000:
			if (full_duplex != 0) {
				return "1000Mbps/full-duplex";
			}
			else {
				return "1000Mbps/half-duplex";
			}
		default:
			return "unrecognized";
	}
}


static netif_driver_t enet_drv = {
	.init = enet_netifInit,
	.state_sz = sizeof(enet_state_t),
	.state_align = _Alignof(enet_state_t),
	.name = "enet",
	.media = enet_media,
};


__constructor__(1000) void register_driver_enet(void)
{
	register_netif_driver(&enet_drv);
}
