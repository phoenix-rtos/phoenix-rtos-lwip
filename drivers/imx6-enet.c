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
#include "netif-driver.h"
#include "bdring.h"
#include "ephy.h"
#include "hw-debug.h"
#include "physmmap.h"
#include "res-create.h"
#include "imx6-enet-regs.h"

#include <sys/interrupt.h>
#include <sys/platform.h>
#include <sys/threads.h>
#include <phoenix/arch/imx6ull.h>
#include <stdatomic.h>
#include <endian.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define ENET_CLK_KHZ			(66000 /* IPG */)	// BT_FREQ=0

#define USE_ENET_EXT_DESCRIPTORS	0
#define USE_RMII			1
#define ENABLE_FLOW_CONTROL		1
#define ENABLE_PROMISC			0
#define ENABLE_RX_PAD_REMOVE		1
#define ENET_RX_RING_SIZE		64
#define ENET_TX_RING_SIZE		64
#define ENET_BUFFER_SIZE		(2048 - 64)
#define MDC_ALWAYS_ON			1
#define MDIO_DEBUG			0
/* #define ENET_VERBOSE */


#if USE_ENET_EXT_DESCRIPTORS
typedef enet_long_desc_t enet_buf_desc_t;
#else
typedef enet_short_desc_t enet_buf_desc_t;
#endif

typedef struct
{
	volatile struct enet_regs *mmio;

	struct netif *netif;
	unsigned drv_exit;

#define PRIV_RESOURCES(s) &(s)->irq_lock, 3, ~0x03
	handle_t irq_lock, tx_lock, irq_cond, irq_handle;

	net_bufdesc_ring_t rx, tx;

	addr_t devphys;
	uint32_t mscr;

	char name[32];

	eth_phy_state_t phy;

	uint32_t irq_stack[1024] __attribute__((aligned(16))), mdio_stack[1024];
} enet_priv_t;


enum {
	VDBG = 0,
	DEBUG = 1,
	NOTICE = 2,

	EV_BUS_ERROR = 0x01,
};


#if 1
static void enet_printf(enet_priv_t *state, const char *format, ...)
{
	char buf[192];
	va_list arg;

	va_start(arg, format);
	vsnprintf(buf, sizeof(buf), format, arg);
	va_end(arg);
	printf("lwip: %s %s\n", state->name, buf);
}
#else
#define enet_printf(...)
#endif


static void enet_reset(enet_priv_t *state)
{
	// FIXME: timeout

	/* trigger and wait for reset */
	enet_printf(state, "Resetting device...");
	state->mmio->ECR = ENET_ECR_REG_MAGIC | ENET_ECR_RESET;
	do usleep(100); while (state->mmio->ECR & ENET_ECR_ETHEREN);
	enet_printf(state, "Reset done.");

	state->mmio->IAUR = 0;
	state->mmio->IALR = 0;
	state->mmio->GAUR = 0;
	state->mmio->GALR = 0;
}


static void enet_start(enet_priv_t *state)
{
//	addr_t ecr_pa = (addr_t)&((struct enet_regs *)state->phys)->ECR;
	// FIXME: last_will(ECR = ENET_ECR_REG_MAGIC | ENET_ECR_RESET);

	state->mmio->MRBR = ENET_BUFFER_SIZE;	// FIXME: coerce with net_allocPktBuf()
	state->mmio->FTRL = BIT(14)-1;	// FIXME: truncation to just above link MTU

	state->mmio->RCR = (1518 << 16) |
			  ENET_RCR_CRCFWD | ENET_RCR_PAUFWD |
#if ENABLE_RX_PAD_REMOVE
			  ENET_RCR_PADEN |
#endif
#if USE_RMII
			  ENET_RCR_RMII_MODE |
#endif
#if ENABLE_FLOW_CONTROL
			  ENET_RCR_FCE |
#endif
#if ENABLE_PROMISC
			  ENET_RCR_PROM |
#endif
			  ENET_RCR_MII_MODE;
	state->mmio->RACC = ENET_RACC_SHIFT16 |
#if !ENABLE_PROMISC
			   ENET_RACC_LINEDIS | ENET_RACC_PRODIS | ENET_RACC_IPDIS |
#endif
			   ENET_RACC_PADREM;

	state->mmio->TCR = ENET_TCR_FDEN;
#if ETH_PAD_SIZE == 2
	state->mmio->TACC = ENET_TACC_SHIFT16;
#else
	state->mmio->TACC = 0;
#endif

	mutexLock(state->irq_lock);
	state->mmio->EIMR |= ENET_IRQ_EBERR;
	mutexUnlock(state->irq_lock);

	state->mmio->ECR = ENET_ECR_REG_MAGIC |
#if USE_ENET_EXT_DESCRIPTORS
			  ENET_ECR_EN1588 |
#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN
			  ENET_ECR_DBSWP |
#endif
			  ENET_ECR_ETHEREN;

	/* trigger HW RX */
	state->mmio->RDAR = ~0u;

#ifdef ENET_VERBOSE
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


static int enet_readFusedMac(uint32_t *buf)
{
	volatile uint32_t *va = physmmap(0x21bc000, 0x1000);

	if (va == MAP_FAILED)
		return -ENOMEM;

	buf[0] = va[0x100 + 4 * 0x22];
	buf[1] = va[0x100 + 4 * 0x23];
	buf[2] = va[0x100 + 4 * 0x24];

	physunmap(va, 0x1000);

	return 0;
}

static uint32_t enet_readCpuId(void)
{
	volatile uint32_t *va = physmmap(0x21bc000, 0x1000);
	uint32_t res = 0;

	if (va == MAP_FAILED)
		return 0;

	/* use CFG1: wafer no + x/y coordinate */
	res = va[0x100 + 4 * 0x02];

	physunmap(va, 0x1000);

	return res;
}


static inline uint8_t get_byte(uint32_t v, int i)
{
	return (v >> (i * 8)) & 0xFF;
}


static void enet_readCardMac(enet_priv_t *state)
{
	static const struct eth_addr zero_eth = { { 0, 0, 0, 0, 0, 0 } };

	uint32_t buf[3];
	uint8_t *mac;

	mac = (void *)&state->netif->hwaddr;

	if (state->devphys == 0x02188000 /* iMX6ULL.ENET1 */ && !enet_readFusedMac(buf)) {
		mac[0] = get_byte(buf[1], 1);
		mac[1] = get_byte(buf[1], 0);
		mac[2] = get_byte(buf[0], 3);
		mac[3] = get_byte(buf[0], 2);
		mac[4] = get_byte(buf[0], 1);
		mac[5] = get_byte(buf[0], 0);
	} else if (state->devphys == 0x020B4000 /* iMX6ULL.ENET2 */ && !enet_readFusedMac(buf)) {
		mac[0] = get_byte(buf[2], 3);
		mac[1] = get_byte(buf[2], 2);
		mac[2] = get_byte(buf[2], 1);
		mac[3] = get_byte(buf[2], 0);
		mac[4] = get_byte(buf[1], 3);
		mac[5] = get_byte(buf[1], 2);
	} else {
		buf[0] = state->mmio->PALR;
		buf[1] = state->mmio->PAUR;

		mac[0] = get_byte(buf[0], 3);
		mac[1] = get_byte(buf[0], 2);
		mac[2] = get_byte(buf[0], 1);
		mac[3] = get_byte(buf[0], 0);
		mac[4] = get_byte(buf[1], 3);
		mac[5] = get_byte(buf[1], 2);
	}

	if (memcmp(mac, &zero_eth.addr, ETH_HWADDR_LEN) == 0) {
		uint32_t cpuId = enet_readCpuId();
		mac[0] = 0x02;
		mac[1] = (cpuId >> 24) & 0xFF;
		mac[2] = (cpuId >> 16) & 0xFF;
		mac[3] = (cpuId >>  8) & 0xFF;
		mac[4] = (cpuId >>  0) & 0xFF;
		mac[5] = state->devphys >> 16;
	}

	state->mmio->PALR = be32toh(*(uint32_t *)mac);
	state->mmio->PAUR = (be16toh(*(uint16_t *)(mac + 4)) << 16) | 0x8808;
}


static void enet_showCardId(enet_priv_t *state)
{
	uint8_t *mac = (void *)&state->netif->hwaddr;
	printf("lwip: %s initialized, MAC=%02x:%02x:%02x:%02x:%02x:%02x\n", state->name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}


static size_t enet_nextRxBufferSize(const net_bufdesc_ring_t *ring, size_t i)
{
	volatile enet_buf_desc_t *desc = (volatile enet_buf_desc_t *)ring->ring + i;
	size_t sz;

#if 0 && USE_ENET_EXT_DESCRIPTORS
	if (!(desc->dflags & ENET_XDESC_DONE))
		return 0;
#endif

	if (desc->flags & ENET_DESC_OWN)
		return 0;

	sz = desc->len;
	if (!sz)	// FIXME: hw bug?
		sz = 1;
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

	desc->len = sz - 2;
	desc->addr = pa;
#if USE_ENET_EXT_DESCRIPTORS
	desc->yflags = ENET_RXDY_INT;
#endif
	atomic_store(&desc->flags, ENET_DESC_OWN | wrap);
}


static int enet_nextTxDone(const net_bufdesc_ring_t *ring, size_t i)
{
	volatile enet_buf_desc_t *desc = (volatile enet_buf_desc_t *)ring->ring + i;

	return !(desc->flags & ENET_DESC_OWN);
}


static void enet_fillTxDesc(const net_bufdesc_ring_t *ring, size_t i, addr_t pa, size_t sz, unsigned seg)
{
	volatile enet_buf_desc_t *desc = (volatile enet_buf_desc_t *)ring->ring + i;
	unsigned flags, yflags __attribute__((unused));

	flags = ENET_DESC_OWN | ENET_TXD_TXCRC;
	flags |= i == ring->last ? ENET_DESC_WRAP : 0;
	flags |= seg & BDRING_SEG_LAST ? ENET_DESC_LAST : 0;

	desc->len = sz;
	desc->addr = pa;

#if USE_ENET_EXT_DESCRIPTORS
	yflags = ENET_TXDY_INT;

	if (oflags & OFLAG_CSUM_IPV4)
		desc->yflags |= ENET_TXDY_IPCSUM;
	if (oflags & (OFLAG_CSUM_UDP | OFLAG_CSUM_TCP))
		desc->yflags |= ENET_TXDY_L4CSUM;

	desc->yflags = yflags;
#endif

	atomic_store(&desc->flags, flags);
}


static const net_bufdesc_ops_t enet_ring_ops = {
	enet_nextRxBufferSize,
	enet_pktRxFinished,
	enet_fillRxDesc,
	enet_nextTxDone,
	enet_fillTxDesc,

	/* desc_size */		sizeof(enet_buf_desc_t),
	/* ring_alignment */	64,
	/* pkt_buf_sz */	ENET_BUFFER_SIZE,
	/* max_tx_frag */	0xFFFF,
};

static const size_t enet_ring_sizes[] = { ENET_RX_RING_SIZE, ENET_TX_RING_SIZE };


static int enet_initRings(enet_priv_t *state)
{
	int err;

	err = net_initRings(&state->rx, enet_ring_sizes, 2, &enet_ring_ops);
	if (err)
		return err;

	state->mmio->RDSR = state->rx.phys;
	state->mmio->TDSR = state->tx.phys;

	return 0;
}


/* hard-IRQ handler */
static int enet_irq_handler(unsigned irq, void *arg)
{
	uint32_t events;
	enet_priv_t *state = arg;

	events = state->mmio->EIR & (ENET_IRQ_RXF | ENET_IRQ_TXF | ENET_IRQ_EBERR);
	state->mmio->EIMR &= ~(ENET_IRQ_RXF | ENET_IRQ_TXF);

	if (events & ENET_IRQ_EBERR)
		atomic_fetch_or(&state->drv_exit, EV_BUS_ERROR);

	return 0;
}


/* IRQ thread */
static void enet_irq_thread(void *arg)
{
	enet_priv_t *state = arg;
	size_t rx_done = 0;

	mutexLock(state->irq_lock);
	while (!state->drv_exit) {

		state->mmio->EIR = ENET_IRQ_RXF;
		rx_done = net_receivePackets(&state->rx, state->netif, 2);
		if (rx_done || !net_rxFullyFilled(&state->rx)) {
			net_refillRx(&state->rx, 2);
			state->mmio->RDAR = ~0u;
		}

		state->mmio->EIR = ENET_IRQ_TXF;
		net_reapTxFinished(&state->tx);

		if (!(state->mmio->EIR & (ENET_IRQ_RXF | ENET_IRQ_TXF))) {
			state->mmio->EIMR |= ENET_IRQ_RXF | ENET_IRQ_TXF;
			condWait(state->irq_cond, state->irq_lock, 0);
		}
	}
	mutexUnlock(state->irq_lock);

	if (state->drv_exit & EV_BUS_ERROR)
		enet_printf(state, "HW signalled memory bus error -- device halted");

	endthread();
}


static int enet_mdioSetup(void *arg, unsigned max_khz, unsigned min_hold_ns, unsigned opt_preamble)
{
	enet_priv_t *state = arg;
	int speed, hold, changed = 0;
	/* mdc_freq = enet_clk / 2 / (MDIO_SPEED + 1) */

	speed = (ENET_CLK_KHZ / 2 + max_khz - 1) / max_khz - 1;
	if (speed < 1)
		speed = 1;
	if (speed > (ENET_MSCR_SPEED_MASK >> ENET_MSCR_SPEED_SHIFT))
		speed = ENET_MSCR_SPEED_MASK;
	else
		speed <<= ENET_MSCR_SPEED_SHIFT;
	if (speed > (state->mscr & ENET_MSCR_SPEED_MASK)) {
		state->mscr &= ~ENET_MSCR_SPEED_MASK;
		state->mscr |= speed;
		changed = 1;
	}

	if (min_hold_ns < 8000000 / ENET_CLK_KHZ)
		hold = (min_hold_ns * ENET_CLK_KHZ + 999999) / 1000000 - 1;
	else
		hold = ENET_MSCR_HOLDTIME_MASK >> ENET_MSCR_HOLDTIME_SHIFT;

	if (hold < 0)
		hold = 0;
	else if (hold > (ENET_MSCR_HOLDTIME_MASK >> ENET_MSCR_HOLDTIME_SHIFT))
		hold = ENET_MSCR_HOLDTIME_MASK;
	else
		hold <<= ENET_MSCR_HOLDTIME_SHIFT;

	if (hold > (state->mscr & ENET_MSCR_HOLDTIME_MASK)) {
		state->mscr &= ~ENET_MSCR_HOLDTIME_MASK;
		state->mscr |= hold;
		changed = 1;
	}

	if (!opt_preamble && (state->mscr & ENET_MSCR_DIS_PRE)) {
		state->mscr &= ~ENET_MSCR_DIS_PRE;
		changed = 1;
	}

	if (changed) {
		speed = (state->mscr & ENET_MSCR_SPEED_MASK) >> ENET_MSCR_SPEED_SHIFT;
		hold = (state->mscr & ENET_MSCR_HOLDTIME_MASK) >> ENET_MSCR_HOLDTIME_SHIFT;
		enet_printf(state, "mdio: speed %u (%u kHz), hold %u (%u ns), %s preamble",
				speed, ENET_CLK_KHZ / 2 / (speed + 1),
				hold, (hold + 1) * 1000000 / ENET_CLK_KHZ,
				state->mscr & ENET_MSCR_DIS_PRE ? "no" : "with");
	}

	if (MDC_ALWAYS_ON)
		state->mmio->MSCR = state->mscr;

	return 0;
}


static void enet_mdioWait(enet_priv_t *state)
{
	// FIXME: timeout
	while (!(state->mmio->EIR & ENET_IRQ_MII))
		/* relax */;
	state->mmio->EIR = ENET_IRQ_MII;
}


static uint16_t enet_mdioIO(enet_priv_t *state, unsigned addr, unsigned reg, unsigned val, int read)
{
	state->mmio->EIR = ENET_IRQ_MII;
	if (!MDC_ALWAYS_ON)
		state->mmio->MSCR = state->mscr;

	if (addr & NETDEV_MDIO_CLAUSE45) {
		uint32_t dev = ((addr & NETDEV_MDIO_A_MASK) << 18) |
			((addr & NETDEV_MDIO_B_MASK) << (23-8));
		state->mmio->MMFR = 0x00020000 | /* extended MDIO address write */
			dev | (reg & 0xFFFF);
		enet_mdioWait(state);
		state->mmio->MMFR = (read ? 0x20020000 : 0x10020000) | /* extended MDIO data r/w */
			dev | (read ? 0 : val & 0xFFFF);
	} else { /* clause 22 */
		state->mmio->MMFR = (read ? 0x60020000 : 0x50020000) | /* standard MDIO data r/w */
			((addr & NETDEV_MDIO_A_MASK) << 23) |
			((reg & 0x1F) << 18) |
			(read ? 0 : val & 0xFFFF);
	}

	enet_mdioWait(state);
	val = state->mmio->MMFR & 0xFFFF;
	if (!MDC_ALWAYS_ON)
		state->mmio->MSCR = 0;
	return val;
}


static uint16_t enet_mdioRead(void *arg, unsigned addr, uint16_t reg)
{
	enet_priv_t *state = arg;
	uint16_t v;

	v = enet_mdioIO(state, addr, reg, 0, 1);
#if MDIO_DEBUG
	enet_printf(state, "MDIO %02x[%02x] ?= %04x", addr, reg, v);
#endif
	return v;
}


static void enet_mdioWrite(void *arg, unsigned addr, uint16_t reg, uint16_t val)
{
	enet_priv_t *state = arg;

	enet_mdioIO(state, addr, reg, val, 0);
#if MDIO_DEBUG
	enet_printf(state, "MDIO %02x[%02x] := %04x", addr, reg, val);
#endif
}


static const mdio_bus_ops_t enet_mdio_ops = {
	enet_mdioSetup,
	enet_mdioRead,
	enet_mdioWrite,
};


static int platformctl_seq(const platformctl_t *pctl, size_t n)
{
	int err = 0;

	for (; n--; ++pctl) {
		err = platformctl((platformctl_t *)pctl);
		if (err < 0)
			break;
	}

	return err;
}


static int enet_initMDIO(enet_priv_t *state)
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

	if (state->devphys == 0x02188000 /* iMX6ULL.ENET1 */)
		err = platformctl_seq(pctl_enet1, sizeof(pctl_enet1) / sizeof(*pctl_enet1));
	else if (state->devphys == 0x020B4000 /* iMX6ULL.ENET2 */)
		err = platformctl_seq(pctl_enet2, sizeof(pctl_enet2) / sizeof(*pctl_enet2));
	else
		err = 0;

	if (err < 0) {
		enet_printf(state, "Can't configure MDIO pins");
		return err;
	}

	state->mscr = (1 << ENET_MSCR_SPEED_SHIFT) | ENET_MSCR_DIS_PRE;

	return 0;
}


static int enet_clockEnable(enet_priv_t *state)
{
	static const platformctl_t pctl_enet_clock = {
		pctl_set, pctl_devclock, .devclock = { pctl_clk_enet, 3 }
	};
	int err;

	err = platformctl_seq(&pctl_enet_clock, 1);
	if (err < 0)
		enet_printf(state, "Can't enable ENET clock\n");

	return err;
}


static int enet_pinConfig(enet_priv_t *state)
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

	if (state->devphys == 0x02188000 /* iMX6ULL.ENET1 */)
		err = platformctl_seq(pctl_enet1, sizeof(pctl_enet1) / sizeof(*pctl_enet1));
	else if (state->devphys == 0x020B4000 /* iMX6ULL.ENET2 */)
		err = platformctl_seq(pctl_enet2, sizeof(pctl_enet2) / sizeof(*pctl_enet2));
	else
		err = 0;

	if (err < 0) {
		enet_printf(state, "Can't configure ENET pins\n");
		return err;
	}

	state->mmio->RCR =
#if USE_RMII
		ENET_RCR_RMII_MODE |
#endif
		ENET_RCR_MII_MODE;

	return 0;
}


static int enet_initDevice(enet_priv_t *state, int irq, int mdio)
{
	// FIXME: cleanup on error
	int err;

	snprintf(state->name, sizeof(state->name), "enet@%08x", state->devphys);

	state->mmio = physmmap(state->devphys, 0x1000);
	if (state->mmio == (void *)-1)
		return -ENODEV;

	if ((err = create_mutexcond_bulk(PRIV_RESOURCES(state))))
		return err;

	if ((err = enet_clockEnable(state)) < 0)
		return err;

	enet_reset(state);
	enet_readCardMac(state);
	enet_pinConfig(state);

	if (mdio) {
		err = enet_initMDIO(state);
		if (err < 0)
			return err;
	}

	if ((err = enet_initRings(state)))
		return err;

#ifdef ENET_VERBOSE
	enet_printf(state, "mmio 0x%x irq %d", state->devphys, irq);
#endif

	interrupt(irq, enet_irq_handler, state, state->irq_cond, &state->irq_handle);
	beginthread(enet_irq_thread, 4, state->irq_stack, sizeof(state->irq_stack), state);

	if (state->mscr) {
		err = register_mdio_bus(&enet_mdio_ops, state);
		if (err < 0) {
			enet_printf(state, "Can't register MDIO bus");
			return err;
		}

		enet_printf(state, "MDIO bus %d", err);
	}

	net_refillRx(&state->rx, 2);
	enet_start(state);

	enet_showCardId(state);

	return 0;
}


static err_t enet_netifOutput(struct netif *netif, struct pbuf *p)
{
	enet_priv_t *state = netif->state;
	size_t nf;

	if (ETH_PAD_SIZE != 2)
		pbuf_header(p, -ETH_PAD_SIZE); /* drop the padding word */

	mutexLock(state->tx_lock);
	nf = net_transmitPacket(&state->tx, p);
	if (nf)
		state->mmio->TDAR = ~0u;
	mutexUnlock(state->tx_lock);

	return nf ? ERR_OK : ERR_BUF;
}

static void enet_setLinkState(void *arg, int state)
{
	struct netif* netif = (struct netif*) arg;
	enet_priv_t *priv = netif->state;
	int speed, full_duplex;

	if (state) {
		speed = ephy_link_speed(&priv->phy, &full_duplex);

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

// ARGS: enet:base:irq[:no-mdio][:PHY:[bus.]addr[:config]]
static int enet_netifInit(struct netif *netif, char *cfg)
{
	enet_priv_t *priv;
	char *p;
	int err, irq, mdio = 1;

	netif->linkoutput = enet_netifOutput;

	priv = netif->state;
	priv->netif = netif;

	if (!cfg)
		return -EINVAL;

	priv->devphys = strtoul(cfg, &p, 0);
	if (!*cfg || *p++ != ':')
		return -EINVAL;

	irq = strtoul((cfg = p), &p, 0);
	if (!*cfg || (*p && *p++ != ':') || irq < 0)
		return -EINVAL;

	cfg = NULL;
	while (p && *p) {
		cfg = strchr(p, ':');
		if (cfg)
			*cfg++ = 0;

		if (!strcmp(p, "no-mdio")) {
			mdio = 0;
			p = cfg;
			continue;
		}

		if (!strcmp(p, "PHY"))
			break;

		return -EINVAL;
	}

	if ((err = enet_initDevice(priv, irq, mdio)))
		return err;

	if (cfg) {
		err = ephy_init(&priv->phy, cfg, enet_setLinkState, (void*) priv->netif);
		if (err)
			enet_printf(priv, "WARN: PHY init failed: %s (%d)", strerror(err), err);
	}

	return 0;
}


const char *enet_media(struct netif *netif)
{
	int full_duplex, speed;
	enet_priv_t *priv;
	priv = netif->state;

	speed = ephy_link_speed(&priv->phy, &full_duplex);

	switch (speed) {
	case 0:
		return "unspecified";
		break;
	case 10:
		if (full_duplex)
			return "10Mbps/full-duplex";
		else
			return "10Mbps/half-duplex";
		break;
	case 100:
		if (full_duplex)
			return "100Mbps/full-duplex";
		else
			return "100Mbps/half-duplex";
		break;
	case 1000:
		if (full_duplex)
			return "1000Mbps/full-duplex";
		else
			return "1000Mbps/half-duplex";
		break;
	default:
		return "unrecognized";
	}
}


static netif_driver_t enet_drv = {
	.init = enet_netifInit,
	.state_sz = sizeof(enet_priv_t),
	.state_align = _Alignof(enet_priv_t),
	.name = "enet",
	.media = enet_media,
};


__constructor__(1000)
void register_driver_enet(void)
{
	register_netif_driver(&enet_drv);
}
