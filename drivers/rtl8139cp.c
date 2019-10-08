/*
 * Phoenix-RTOS --- networking stack
 *
 * RTL8139C+ NIC driver
 *
 * Copyright 2017 Phoenix Systems
 * Author: Michał Mirosław
 *
 * %LICENSE%
 */
#include "arch/cc.h"
#include "lwip/etharp.h"
#include "netif-driver.h"
#include "physmmap.h"
#include "bdring.h"
#include "pci.h"
#include "res-create.h"
#include "rtl8139cp-regs.h"

#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/ethip6.h"
#include "lwip/etharp.h"
#include "netif/ppp/pppoe.h"



#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/threads.h>
#include <sys/interrupt.h>

#define USE_DMA64 (sizeof(addr_t) > 4)
#define RTL_RING_BUF_SIZE	0x1000	/* RX + TX */
#define RTL_RX_RING_SIZE	64
#define RTL_TX_RING_SIZE	64
#define DEBUG_RINGS	0

typedef struct
{
	volatile struct rtl_regs *mmio;
	struct netif *netif;

#define PRIV_RESOURCES(s) &(s)->irq_lock, 5, ~0x07
	handle_t irq_lock, rx_lock, tx_lock, rx_irq_cond, tx_irq_cond, rx_irq_handle, tx_irq_handle;
	unsigned drv_exit;

	net_bufdesc_ring_t rx, tx, txp;

	uint16_t devnum;

	uint32_t rx_stack[2048], tx_stack[2048], irq_stack[256];
} rtl_priv_t;


static void rtl_printf(rtl_priv_t *state, const char *format, ...)
{
	char buf[256];
	va_list arg;

	va_start(arg, format);
	vsnprintf(buf, sizeof(buf), format, arg);
	va_end(arg);

	printf("PCI " PCI_DEVNUM_FMT ": %s\n", PCI_DEVNUM_ARGS(state->devnum), buf);
}


static void rtl_chipReset(rtl_priv_t *state)
{
	/* trigger and wait for reset */
	state->mmio->CR = RTL_CMD_RESET;
	while (state->mmio->CR & RTL_CMD_RESET)
		usleep(100);

	/* enable C+ mode */
	state->mmio->CPCR = RTL_CMD_TX_MODE_CP|RTL_CMD_RX_MODE_CP|RTL_CMD_RX_CSUM|RTL_CMD_RX_VLAN|RTL_CMD_PCI_MULRW;

	/* clear RX multicast filter */
	state->mmio->MAR[0] = 0;
	state->mmio->MAR[1] = 0;
}


static void rtl_readCardMac(rtl_priv_t *state)
{
	uint32_t buf[2];

	// XX: cpu_to_le(), need dword access
	buf[0] = state->mmio->IDR[0];
	buf[1] = state->mmio->IDR[1];

	memcpy(&state->netif->hwaddr, buf, ETH_HWADDR_LEN);
}


static void rtl_showCardId(rtl_priv_t *state)
{
	uint32_t tc, rc;
	uint8_t *mac;

	tc = state->mmio->TCR;
	rc = state->mmio->RCR;
	rtl_printf(state, "HW ver-id %03x dma-burst: tx %u rx %u",
		(tc >> 20) & 0x7cc,
		16 << ((tc & RTL_TX_DMA_BURST) >> RTL_TX_DMA_BURST_SHIFT),
		16 << ((rc & RTL_RX_DMA_BURST) >> RTL_RX_DMA_BURST_SHIFT));

	mac = (void *)&state->netif->hwaddr;
	rtl_printf(state, "MAC: %02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}


static size_t rtl_nextRxBufferSize(const net_bufdesc_ring_t *ring, size_t i)
{
	volatile rtl_buf_desc_t *r = ring->ring;
	uint32_t cmd = r[i].cmd;

	if (cmd & RTL_DESC_OWN)
		return 0;

	cmd &= RXCMD_SZ_MASK;
	return cmd + ETH_PAD_SIZE;
}


static int rtl_pktRxFinished(const net_bufdesc_ring_t *ring, size_t i)
{
	volatile rtl_buf_desc_t *r = ring->ring;

	return r[i].cmd & RTL_DESC_LS;
}


static void rtl_fillDesc(const net_bufdesc_ring_t *ring, size_t i, addr_t pa, size_t sz, unsigned seg)
{
	volatile rtl_buf_desc_t *r = ring->ring;
	uint32_t cmd = sz;

	if (seg & BDRING_SEG_FIRST)
		cmd |= RTL_DESC_FS;
	if (seg & BDRING_SEG_LAST)
		cmd |= RTL_DESC_LS;

	if (i == ring->last)
		cmd |= RTL_DESC_EOR;
	cmd |= RTL_DESC_OWN;

	if (USE_DMA64)
		r[i].addr.h = USE_DMA64 ? pa >> 32 : 0;
	r[i].addr.l = pa;
	asm volatile ("" ::: "memory");
	r[i].cmd = cmd;
}


static void rtl_fillRxDesc(const net_bufdesc_ring_t *ring, size_t i, addr_t pa, size_t sz, unsigned seg)
{
	rtl_fillDesc(ring, i, pa + ETH_PAD_SIZE, sz - ETH_PAD_SIZE, 0);
}

static int rtl_nextTxDone(const net_bufdesc_ring_t *ring, size_t i)
{
	volatile rtl_buf_desc_t *r = ring->ring;

	return !(r[i].cmd & RTL_DESC_OWN);
}


static const net_bufdesc_ops_t rtl_ring_ops = {
	rtl_nextRxBufferSize,
	rtl_pktRxFinished,
	rtl_fillRxDesc,
	rtl_nextTxDone,
	rtl_fillDesc,

	/* desc_size */		sizeof(rtl_buf_desc_t),
	/* ring_alignment */	64,
	/* pkt_buf_sz */	1524,	/* <= RXCMD_SZ_MASK */
	/* max_tx_frag */	TXCMD_SZ_MASK,
};

static const size_t rtl_ring_sz[] = { RTL_RX_RING_SIZE, RTL_TX_RING_SIZE, RTL_TX_RING_SIZE };


static int rtl_initRings(rtl_priv_t *state)
{
	int err;

	err = net_initRings(&state->rx, rtl_ring_sz, 3, &rtl_ring_ops);
	if (err)
		return err;

	net_refillRx(&state->rx, 0);

	state->mmio->RDSAR.h = USE_DMA64 ? state->rx.phys >> 32 : 0;
	state->mmio->RDSAR.l = state->rx.phys;

	state->mmio->TNPDS.h = USE_DMA64 ? state->tx.phys >> 32 : 0;
	state->mmio->TNPDS.l = state->tx.phys;

	state->mmio->THPDS.h = USE_DMA64 ? state->txp.phys >> 32 : 0;
	state->mmio->THPDS.l = state->txp.phys;

	return 0;
}


/* IRQ: RX */


static int rtl_rx_irq_handler(unsigned irq, void *arg)
{
	rtl_priv_t *state = arg;

	if (!(state->mmio->ISR & RTL_INT_RX))
		return -1;

	__sync_fetch_and_and(&state->mmio->IMR, ~RTL_INT_RX);
	return 0;
}


static void rtl_rx_irq_thread(void *arg)
{
	rtl_priv_t *state = arg;
	size_t rx_done;

	mutexLock(state->irq_lock);
	while (!state->drv_exit) {
		state->mmio->ISR = RTL_INT_RX;
		mutexUnlock(state->irq_lock);

		rx_done = net_receivePackets(&state->rx, state->netif, 0);
		if (rx_done || !net_rxFullyFilled(&state->rx))
			net_refillRx(&state->rx, 0);

		mutexLock(state->irq_lock);
		if (!(state->mmio->ISR & RTL_INT_RX)) {
			__sync_fetch_and_or(&state->mmio->IMR, RTL_INT_RX);
			condWait(state->rx_irq_cond, state->irq_lock, 0);
		}
	}
	mutexUnlock(state->irq_lock);

	endthread();
}


/* IRQ: TX */


static int rtl_tx_irq_handler(unsigned irq, void *arg)
{
	rtl_priv_t *state = arg;

	if (!(state->mmio->ISR & RTL_INT_TX))
		return -1;

	__sync_fetch_and_and(&state->mmio->IMR, ~RTL_INT_TX);
	return 0;
}


static void rtl_tx_irq_thread(void *arg)
{
	rtl_priv_t *state = arg;
	size_t tx_done;

	mutexLock(state->irq_lock);
	while (!state->drv_exit) {
		state->mmio->ISR = RTL_INT_TX;
		mutexUnlock(state->irq_lock);

		tx_done = net_reapTxFinished(&state->tx);

		mutexLock(state->irq_lock);
		if (!tx_done) {
			__sync_fetch_and_or(&state->mmio->IMR, RTL_INT_TX);
			condWait(state->tx_irq_cond, state->irq_lock, 0);
		}
	}
	mutexUnlock(state->irq_lock);

	endthread();
}


static int rtl_initDevice(rtl_priv_t *state, uint16_t devnum, int irq)
{
	uint32_t crev;
	int err;

	state->devnum = devnum;

	state->mmio = pci_mapMemBAR(devnum, 1);
	if (!state->mmio)
		return -ENOMEM;

	crev = pci_configRead(devnum, 8) & 0xFF;
	if (crev < 20) {
		rtl_printf(state, "error: card does not support C+ mode");
		return -ENOTTY;
	}

	if ((err = create_mutexcond_bulk(PRIV_RESOURCES(state))))
		return err;

	rtl_chipReset(state);
	pci_setBusMaster(devnum, 1);
	rtl_readCardMac(state);
	rtl_showCardId(state);

	if ((err = rtl_initRings(state)) != EOK)
		goto err_exit;

	beginthread(rtl_rx_irq_thread, 0, (void *)state->rx_stack, sizeof(state->rx_stack), state);
	beginthread(rtl_tx_irq_thread, 0, (void *)state->tx_stack, sizeof(state->tx_stack), state);
	interrupt(irq, rtl_rx_irq_handler, state, state->rx_irq_cond, &state->rx_irq_handle);
	interrupt(irq, rtl_tx_irq_handler, state, state->tx_irq_cond, &state->tx_irq_handle);

	state->mmio->CR = RTL_CMD_RX_ENABLE | RTL_CMD_TX_ENABLE;
	state->mmio->RCR = (4 << RTL_RX_DMA_BURST_SHIFT) | RTL_RX_FTH | RTL_RX_BCAST | RTL_RX_MCAST | RTL_RX_UCAST;
	state->mmio->IMR = RTL_INT_RX | RTL_INT_TX;

	return EOK;

err_exit:
	rtl_chipReset(state);
	return err;
}


static err_t rtl_netifOutput(struct netif *netif, struct pbuf *p)
{
	rtl_priv_t *state = netif->state;
	size_t nf;
	int do_unref = 0;

	if (ETH_PAD_SIZE)
		pbuf_header(p, -ETH_PAD_SIZE); /* drop the padding word */

	if (p->tot_len < 60) {
		struct pbuf *q = pbuf_alloc(PBUF_RAW, 60 + ETH_PAD_SIZE, PBUF_RAM);
		pbuf_header(q, -ETH_PAD_SIZE);
		pbuf_copy(q, p);
		p = q;
		do_unref = 1;
	}

	mutexLock(state->tx_lock);
	nf = net_transmitPacket(&state->tx, p);
	if (nf)
		state->mmio->TPPOLL = RTL_POLL_NPQ;
	mutexUnlock(state->tx_lock);

	if (do_unref)
		pbuf_free(p);

	return nf ? ERR_OK : ERR_BUF;
}


static int rtl_netifInit(struct netif *netif, char *cfg)
{
	rtl_priv_t *priv;
	unsigned devnum;
	char *p;
	int irq;

	netif->linkoutput = rtl_netifOutput;

	priv = netif->state;
	priv->netif = netif;

	if (!cfg)
		return ERR_ARG;

	devnum = strtoul(cfg, &p, 0);
	if (!*cfg || *p++ != ':' || devnum > 0xFFFF)
		return ERR_ARG;

	irq = strtoul((cfg = p), &p, 0);
	if (!*cfg || *p || irq < 0)
		return ERR_ARG;

	return rtl_initDevice(priv, devnum, irq);
}


static netif_driver_t rtl_drv = {
	.init = rtl_netifInit,
	.state_sz = sizeof(rtl_priv_t),
	.state_align = _Alignof(rtl_priv_t),
	.name = "rtl",
};


__constructor__(1000)
void register_driver_rtl(void)
{
	register_netif_driver(&rtl_drv);
}
