/*
 * Phoenix-RTOS --- networking stack
 *
 * imxrt1064 ENET network module driver
 *
 * Copyright 2023 Phoenix Systems
 * Author: Phoenix Systems
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
#include "imxrt-enet-regs.h"

#include "common-enet.h"

#include <sys/interrupt.h>
#include <sys/platform.h>
#include <sys/threads.h>
#include <phoenix/arch/imxrt.h>
#include <stdatomic.h>
#include <endian.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define ENET_CLK_KHZ			(132000 /* IPG */)	// BT_FREQ=0

#define ENET_RX_RING_SIZE		64
#define ENET_TX_RING_SIZE		64
#define ENET_BUFFER_SIZE		(2048 - 64)
#define MDC_ALWAYS_ON			1

#if USE_ENET_EXT_DESCRIPTORS
typedef enet_long_desc_t enet_buf_desc_t;
#else
typedef enet_short_desc_t enet_buf_desc_t;
#endif

enum {
	VDBG = 0,
	DEBUG = 1,
	NOTICE = 2,

	EV_BUS_ERROR = 0x01,
};

void enet_printf(enet_priv_t *state, const char *format, ...)
{
	char buf[192];
	va_list arg;

	va_start(arg, format);
	vsnprintf(buf, sizeof(buf), format, arg);
	va_end(arg);
	printf("lwip: %s %s\n", state->name, buf);
}


void enet_reset(enet_priv_t *state)
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


void enet_start(enet_priv_t *state)
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
	enet_printf(state, "regs:   PLL6  ,  CCGR0 ,  GPR1  ,TXCLKMUX,OSC24-M0,OSC24-LP"); //enet_printf(state, "regs:   PLL6  ,  CCGR0 ,  GPR1  ,TXCLKMUX,TXCLKPAD,RCLK1SID,OSC24-M0,OSC24-LP");
	enet_printf(state, "regs: %08x %08x %08x %08x %08x %08x",
		hwdebug_read(0x400d80e0), hwdebug_read(0x400fc068), hwdebug_read(0x400ac004), hwdebug_read(0x401f8448),
		hwdebug_read(0x400d8150), hwdebug_read(0x400fc054)); //hwdebug_read(0x20e0368), hwdebug_read(0x20e0574), hwdebug_read(0x400d8150), hwdebug_read(0x400fc054));
#endif
}


void enet_showCardId(enet_priv_t *state)
{
	uint8_t *mac = (void *)&state->netif->hwaddr;
	printf("lwip: %s initialized, MAC=%02x:%02x:%02x:%02x:%02x:%02x\n", state->name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}


size_t enet_nextRxBufferSize(const net_bufdesc_ring_t *ring, size_t i)
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


int enet_pktRxFinished(const net_bufdesc_ring_t *ring, size_t i)
{
	volatile enet_buf_desc_t *desc = (volatile enet_buf_desc_t *)ring->ring + i;

	return desc->flags & ENET_DESC_LAST;
}


void enet_fillRxDesc(const net_bufdesc_ring_t *ring, size_t i, addr_t pa, size_t sz, unsigned seg)
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


int enet_nextTxDone(const net_bufdesc_ring_t *ring, size_t i)
{
	volatile enet_buf_desc_t *desc = (volatile enet_buf_desc_t *)ring->ring + i;

	return !(desc->flags & ENET_DESC_OWN);
}


void enet_fillTxDesc(const net_bufdesc_ring_t *ring, size_t i, addr_t pa, size_t sz, unsigned seg)
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


const net_bufdesc_ops_t enet_ring_ops = {
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

int enet_initRings(enet_priv_t *state)
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
int enet_irq_handler(unsigned irq, void *arg)
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
void enet_irq_thread(void *arg)
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

		//TODO: remove
		usleep(100);
	}
	mutexUnlock(state->irq_lock);

	if (state->drv_exit & EV_BUS_ERROR)
		enet_printf(state, "HW signalled memory bus error -- device halted");

	endthread();
}


int enet_mdioSetup(void *arg, unsigned max_khz, unsigned min_hold_ns, unsigned opt_preamble)
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


void enet_mdioWait(enet_priv_t *state)
{
	// FIXME: timeout
	while (!(state->mmio->EIR & ENET_IRQ_MII))
		/* relax */;
	state->mmio->EIR = ENET_IRQ_MII;
}


uint16_t enet_mdioIO(enet_priv_t *state, unsigned addr, unsigned reg, unsigned val, int read)
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


uint16_t enet_mdioRead(void *arg, unsigned addr, uint16_t reg)
{
	enet_priv_t *state = arg;
	uint16_t v;

	v = enet_mdioIO(state, addr, reg, 0, 1);
#if MDIO_DEBUG
	//enet_printf(state, "MDIO %02x[%02x] ?= %04x", addr, reg, v);
#endif
	return v;
}


void enet_mdioWrite(void *arg, unsigned addr, uint16_t reg, uint16_t val)
{
	enet_priv_t *state = arg;

	enet_mdioIO(state, addr, reg, val, 0);
#if MDIO_DEBUG
	// enet_printf(state, "MDIO %02x[%02x] := %04x", addr, reg, val);
#endif
}
