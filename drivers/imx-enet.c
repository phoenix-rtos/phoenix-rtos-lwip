/*
 * Phoenix-RTOS --- networking stack
 *
 * iMX6ULL ENET network module driver
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * %LICENSE%
 */
#include "arch/cc.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "netif-driver.h"
#include "bdring.h"
#include "ephy.h"
#include "hw-debug.h"
#include "physmmap.h"
#include "res-create.h"
#include "imx-enet-regs.h"

#include <sys/interrupt.h>
#include <sys/platform.h>
#include <sys/threads.h>
#include <phoenix/arch/armv7a/imx6ull/imx6ull.h>
#include <stdatomic.h>
#include <endian.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ENET_DEBUG 0
#define MDIO_DEBUG 0

#define ENET_CLK_KHZ (66000 /* IPG */)  // BT_FREQ=0

#define ENET_USE_ENHANCED_DESCRIPTORS 0
#define ENET_RMII_MODE                1
#define ENET_ENABLE_FLOW_CONTROL      1
#define ENET_PROMISC_MODE             0
#define ENET_ENABLE_RX_PAD_REMOVE     1
#define ENET_RX_RING_SIZE             64
#define ENET_TX_RING_SIZE             64
#define ENET_BUFFER_SIZE              (2048 - 64)
#define ENET_MDC_ALWAYS_ON            1 /* NOTE: should be always ON, otherwise unreliable*/

#define OCOTP_CFG1_OFFSET (0x420)
#define OCOTP_MAC0_OFFSET (0x620)
#define OCOTP_MAC1_OFFSET (0x630)
#define OCOTP_MAC_OFFSET  (0x640)
#define OCOTP_GP2_OFFSET  (0x670)
#define OCOTP_MEMORY_ADDR (0x021bc000)

#define ENET_ADDR_ENET1 (0x02188000)
#define ENET_ADDR_ENET2 (0x020B4000)


#if ENET_USE_ENHANCED_DESCRIPTORS
typedef enet_enhanced_desc_t enet_buf_desc_t;
#else
typedef enet_legacy_desc_t enet_buf_desc_t;
#endif

typedef struct {
	volatile struct enet_regs *mmio;

	struct netif *netif;
	unsigned drv_exit;

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

	struct {
#define SELFTEST_RESOURCES(s) &(s)->selfTest.rx_lock, 2, ~0x1
		handle_t rx_lock;
		handle_t rx_cond;
		unsigned int rx_valid; /* -1: received invalid packet, 0: no packet received, 1: received valid packet */
	} selfTest;

	uint32_t irq_stack[1024] __attribute__((aligned(16))), mdio_stack[1024];
} enet_state_t;


enum {
	VDBG = 0,
	DEBUG = 1,
	NOTICE = 2,

	EV_BUS_ERROR = 0x01,
};


#if 1
#define enet_printf(state, fmt, ...) printf("lwip: enet@%08x: " fmt "\n", state->dev_phys_addr, ##__VA_ARGS__)
#else
#define enet_printf(...)
#endif


static void enet_reset(enet_state_t *state)
{
	// FIXME: timeout

	/* trigger and wait for reset */
	enet_printf(state, "Resetting device...");
	state->mmio->ECR = ENET_ECR_MAGIC_VAL | ENET_ECR_RESET;
	do {
		usleep(100);
	} while ((state->mmio->ECR & ENET_ECR_ETHEREN) != 0);
	enet_printf(state, "Reset done.");

	state->mmio->IAUR = 0;
	state->mmio->IALR = 0;
	state->mmio->GAUR = 0;
	state->mmio->GALR = 0;
}


static void enet_start(enet_state_t *state)
{
	//	addr_t ecr_pa = (addr_t)&((struct enet_regs *)state->phys)->ECR;
	// FIXME: last_will(ECR = ENET_ECR_MAGIC_VAL | ENET_ECR_RESET);

	state->mmio->MRBR = ENET_BUFFER_SIZE;  // FIXME: coerce with net_allocPktBuf()
	state->mmio->FTRL = BIT(14) - 1;       // FIXME: truncation to just above link MTU

	state->mmio->RCR = ENET_RCR_MAX_FL_NO_VLAN_VAL |
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

	state->mmio->RACC = ENET_RACC_SHIFT16 |
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
	state->mmio->RDAR = ~0u;

#if ENET_DEBUG
	enet_printf(state, "regs:   ECR   ,  EIMR  ,  TACC  ,  RACC  ,  TCR   ,  RCR   ,  MRBR  ,  FTRL  ");
	enet_printf(state, "regs: %08x %08x %08x %08x %08x %08x %08x %08x",
			state->mmio->ECR, state->mmio->EIMR, state->mmio->TACC, state->mmio->RACC,
			state->mmio->TCR, state->mmio->RCR, state->mmio->MRBR, state->mmio->FTRL);
	enet_printf(state, "regs:   PLL6  ,  CCGR0 ,  GPR1  ,TXCLKMUX,TXCLKPAD,RCLK1SID,OSC24-M0,OSC24-LP");
	enet_printf(state, "regs: %08x %08x %08x %08x %08x %08x %08x %08x",
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
	res = ocotp_mem[OCOTP_CFG1_OFFSET / sizeof(*ocotp_mem)];

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
	res = ocotp_mem[OCOTP_GP2_OFFSET / sizeof(*ocotp_mem)];

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
	else if (state->dev_phys_addr == ENET_ADDR_ENET2 && enet_readFusedMac(buf, ocotp_mem) == 0) {
		mac[0] = enet_getByte(buf[2], 3);
		mac[1] = enet_getByte(buf[2], 2);
		mac[2] = enet_getByte(buf[2], 1);
		mac[3] = enet_getByte(buf[2], 0);
		mac[4] = enet_getByte(buf[1], 3);
		mac[5] = enet_getByte(buf[1], 2);
	}
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
		mac[0] = 0x02;
		mac[1] = (cpuId >> 24) & 0xFF;
		mac[2] = (cpuId >> 16) & 0xFF;
		mac[3] = (cpuId >> 8) & 0xFF;
		mac[4] = (cpuId >> 0) & 0xFF;
		mac[5] = state->dev_phys_addr >> 16;
	}

	state->mmio->PALR = be32toh(*(uint32_t *)mac);
	state->mmio->PAUR = (be16toh(*(uint16_t *)(mac + 4)) << 16) | 0x8808;
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
	}
	return sz;
}


static int enet_pktRxFinished(const net_bufdesc_ring_t *ring, size_t i)
{
	volatile enet_buf_desc_t *desc = (volatile enet_buf_desc_t *)ring->ring + i;

	return desc->flags & ENET_DESC_LAST;
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
	atomic_store(&desc->flags, ENET_DESC_RDY | wrap);
}


static int enet_nextTxDone(const net_bufdesc_ring_t *ring, size_t i)
{
	volatile enet_buf_desc_t *desc = (volatile enet_buf_desc_t *)ring->ring + i;

	return !(desc->flags & ENET_DESC_RDY);
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

	if ((oflags & OFLAG_CSUM_IPV4) != 0) {
		desc->yflags |= ENET_TXDY_IPCSUM;
	}
	if ((oflags & (OFLAG_CSUM_UDP | OFLAG_CSUM_TCP)) != 0) {
		desc->yflags |= ENET_TXDY_L4CSUM;
	}

	desc->yflags = yflags;
#endif

	atomic_store(&desc->flags, flags);
}


static const net_bufdesc_ops_t enet_ring_ops = {
	.nextRxBufferSize = enet_nextRxBufferSize,
	.pktRxFinished = enet_pktRxFinished,
	.fillRxDesc = enet_fillRxDesc,
	.nextTxDone = enet_nextTxDone,
	.fillTxDesc = enet_fillTxDesc,
	.desc_size = sizeof(enet_buf_desc_t),
	.ring_alignment = 64,
	.pkt_buf_sz = ENET_BUFFER_SIZE,
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

	mutexLock(state->irq_lock);
	while (state->drv_exit == 0) {
		state->mmio->EIR = ENET_IRQ_RXF;
		rx_done = net_receivePackets(&state->rx, state->netif, ETH_PAD_SIZE);
		if (rx_done > 0 || net_rxFullyFilled(&state->rx) == 0) {
			net_refillRx(&state->rx, ETH_PAD_SIZE);
			state->mmio->RDAR = ~0u;
		}

		state->mmio->EIR = ENET_IRQ_TXF;
		net_reapTxFinished(&state->tx);

		if ((state->mmio->EIR & (ENET_IRQ_RXF | ENET_IRQ_TXF)) == 0) {
			state->mmio->EIMR |= ENET_IRQ_RXF | ENET_IRQ_TXF;
			condWait(state->irq_cond, state->irq_lock, 0);
		}
	}
	mutexUnlock(state->irq_lock);

	if ((state->drv_exit & EV_BUS_ERROR) != 0) {
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

	if (min_hold_ns < 8 * 1000 * 1000 / ENET_CLK_KHZ) {
		hold = (min_hold_ns * ENET_CLK_KHZ + (1000 * 1000 - 1)) / (1000 * 1000) - 1;
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


static void enet_mdioWait(enet_state_t *state)
{
	// FIXME: timeout
	while ((state->mmio->EIR & ENET_IRQ_MII) == 0)
		/* relax */;
	state->mmio->EIR = ENET_IRQ_MII;
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
		uint32_t dev = ((addr & NETDEV_MDIO_A_MASK) << 18) |
				((addr & NETDEV_MDIO_B_MASK) << (23 - 8));
		mmfr = (ENET_MMFR_OP_ADDR << ENET_MMFR_OP_SHIFT) | /* extended MDIO data r/w */
				(ENET_MMFR_TA_VAL << ENET_MMFR_TA_SHIFT) | dev | (reg & 0xFFFF);

		state->mmio->MMFR = mmfr;
		enet_mdioWait(state);

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
	enet_mdioWait(state);

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


static int enet_initMDIO(enet_state_t *state)
{
	static const platformctl_t pctl_enet1[] = {
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet1_mac0mdio, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio1_06, 0, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio1_07, 0, 0 } },
	};
	static const platformctl_t pctl_enet2[] = {
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet2_mac0mdio, 0 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio1_06, 0, 1 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio1_07, 0, 1 } },
	};

	int err;

	if (state->dev_phys_addr == ENET_ADDR_ENET1) {
		err = platformctl_seq(pctl_enet1, sizeof(pctl_enet1) / sizeof(*pctl_enet1));
	}
	else if (state->dev_phys_addr == ENET_ADDR_ENET2) {
		err = platformctl_seq(pctl_enet2, sizeof(pctl_enet2) / sizeof(*pctl_enet2));
	}
	else {
		err = 0;
	}

	if (err < 0) {
		enet_printf(state, "Couldn't configure MDIO pins");
		return err;
	}

	state->mscr = (1 << ENET_MSCR_MII_SPEED_SHIFT) | ENET_MSCR_DIS_PRE;

	return 0;
}


static int enet_clockEnable(enet_state_t *state)
{
	static const platformctl_t pctl_enet_clock = {
		pctl_set, pctl_devclock, .devclock = { pctl_clk_enet, 3 }
	};
	int err;

	err = platformctl_seq(&pctl_enet_clock, 1);
	if (err < 0) {
		enet_printf(state, "Couldn't enable ENET clock\n");
	}

	return err;
}


static int enet_pinConfig(enet_state_t *state)
{
	static const platformctl_t pctl_enet1[] = {
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

	int err;

	if (state->dev_phys_addr == ENET_ADDR_ENET1) {
		err = platformctl_seq(pctl_enet1, sizeof(pctl_enet1) / sizeof(*pctl_enet1));
	}
	else if (state->dev_phys_addr == ENET_ADDR_ENET2) {
		err = platformctl_seq(pctl_enet2, sizeof(pctl_enet2) / sizeof(*pctl_enet2));
	}
	else {
		err = 0;
	}

	if (err < 0) {
		enet_printf(state, "Couldn't configure ENET pins\n");
		return err;
	}

	state->mmio->RCR =
#if ENET_RMII_MODE
			ENET_RCR_RMII_MODE |
#endif
			ENET_RCR_MII_MODE;

	return 0;
}


static int enet_initDevice(enet_state_t *state, int irq, int mdio, volatile uint32_t *ocotp_mem)
{
	// FIXME: cleanup on error
	int err;

	state->mmio = physmmap(state->dev_phys_addr, 0x1000);
	if (state->mmio == MAP_FAILED) {
		return -ENOMEM;
	}

	err = create_mutexcond_bulk(PRIV_RESOURCES(state));
	if (err != 0) {
		return err;
	}

	err = enet_clockEnable(state);
	if (err < 0) {
		return err;
	}

	enet_reset(state);
	enet_readCardMac(state, ocotp_mem);
	enet_pinConfig(state);

	if (mdio != 0) {
		err = enet_initMDIO(state);
		if (err < 0) {
			return err;
		}
	}

	err = enet_initRings(state);
	if (err != 0) {
		return err;
	}

#if ENET_DEBUG
	enet_printf(state, "mmio 0x%x irq %d", state->dev_phys_addr, irq);
#endif

	interrupt(irq, enet_irqHandler, state, state->irq_cond, &state->irq_handle);
	beginthread(enet_irqThread, 4, state->irq_stack, sizeof(state->irq_stack), state);

	if (state->mscr != 0) {
		err = register_mdio_bus(&enet_mdio_ops, state);
		if (err < 0) {
			enet_printf(state, "Can't register MDIO bus");
			return err;
		}

		enet_printf(state, "MDIO bus %d", err);
	}

	net_refillRx(&state->rx, ETH_PAD_SIZE);
	enet_start(state);

	enet_showCardId(state);

	return 0;
}


static err_t enet_netifOutput(struct netif *netif, struct pbuf *p)
{
	enet_state_t *state = netif->state;
	size_t nf;

	if (ETH_PAD_SIZE != 2) {
		pbuf_header(p, -ETH_PAD_SIZE); /* drop the padding word */
	}

	mutexLock(state->tx_lock);
	nf = net_transmitPacket(&state->tx, p);
	if (nf != 0) {
		state->mmio->TDAR = ~0u;
	}
	mutexUnlock(state->tx_lock);

	return nf ? ERR_OK : ERR_BUF;
}

static void enet_setLinkState(void *arg, int state)
{
	struct netif *netif = arg;
	enet_state_t *priv = netif->state;
	int speed, full_duplex;

	if (state != 0) {
		speed = ephy_linkSpeed(&priv->phy, &full_duplex);

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


#define _TP_ETHTYPE "\x05\xDD" /* eth frame type 0x05DD is undefined */
#define _TP_10DIG   "0123456789"
#define TEST_PACKET "ddddddssssss" _TP_ETHTYPE \
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
		enet_printf(state, "self-test RX: invalid packet length");
		enet_printf(state, "expected: %zuB", (TEST_PACKET_LEN + ETH_PAD_SIZE));
		enet_printf(state, "actual:   %uB", p->len);
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

	/* enable MIB counters (mmio->stats) */
	state->mmio->MIBC = 0;

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

#if ENET_DEBUG
		enet_printf(state, "stats: TX: PACKETS=%u CRC_ALIGN=%u OK=%u",
				state->mmio->stats.RMON_T_PACKETS,
				state->mmio->stats.RMON_T_CRC_ALIGN,
				state->mmio->stats.IEEE_T_FRAME_OK);

		enet_printf(state, "stats: RX: PACKETS=%u CRC_ALIGN=%u OK=%u",
				state->mmio->stats.RMON_R_PACKETS,
				state->mmio->stats.RMON_R_CRC_ALIGN,
				state->mmio->stats.IEEE_R_FRAME_OK);
#endif
		if ((err < 0) || (state->selfTest.rx_valid != 1)) {
			ret = -1;
		}

		/* successfully received */
	} while (0);

	/* restore normal mode */
	netif->input = old_input;
	state->mmio->RCR &= ~ENET_RCR_PROM;
	state->mmio->MIBC = (1u << 31);
	ephy_enableLoopback(&state->phy, false);

	/* destroy selftest resources */
	resourceDestroy(state->selfTest.rx_cond);
	resourceDestroy(state->selfTest.rx_lock);

	return ret;
}


/* ARGS: enet:base:irq[:no-mdio][:PHY:[bus.]addr[:config]] */
static int enet_netifInit(struct netif *netif, char *cfg)
{
	enet_state_t *state;
	char *p;
	int err, irq, mdio = 1;
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
			mdio = 0;
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
		return err;
	}

	if (cfg != NULL) {
		uint8_t board_rev = enet_readBoardRev(ocotp_mem);

		err = ephy_init(&state->phy, cfg, board_rev, enet_setLinkState, (void *)state->netif);
		if (err < 0) {
			enet_printf(state, "WARN: PHY init failed: %s (%d)", strerror(-err), err);
			physunmap(ocotp_mem, 0x1000);
			return err;
		}

		err = enet_phySelfTest(netif);
		if (err < 0) {
			enet_printf(state, "WARN: PHY autotest failed");
		}
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
