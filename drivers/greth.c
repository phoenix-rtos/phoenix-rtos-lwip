/*
 * Phoenix-RTOS --- networking stack
 *
 * GR740 GRETH network module driver
 *
 * Copyright 2025 Phoenix Systems
 * Author: Andrzej Tlomak
 *
 * %LICENSE%
 */

#include "arch/cc.h"
#include "ephy.h"
#include "lwip/err.h"
#include "lwip/netif.h"
#include "lwip/opt.h"
#include "netif-driver.h"
#include "bdring.h"
#include "physmmap.h"
#include "greth-regs.h"
#include "board_config.h"

#include <stddef.h>
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
#include <sys/interrupt.h>

#define greth_printf(state, fmt, ...) printf("lwip: greth@%p: " fmt "\n", (void *)state->dev_phys_addr, ##__VA_ARGS__)

#define GRETH_MAC_IAB      UINT64_C(0x0050C275A000) /* Gaisler research AB */
#define GRETH_RX_RING_SIZE 8
#define GRETH_TX_RING_SIZE 8
#define GRETH_MAX_PKT_SZ   1514

#ifndef GRETH_EDCL
#define GRETH_EDCL 0
#endif

#define GRETH_DEBUG 0
#if GRETH_DEBUG
#define greth_debug_printf(state, fmt, ...) greth_printf(state, fmt, ##__VA_ARGS__)
#else
#define greth_debug_printf(state, fmt, ...)
#endif


typedef struct {
	volatile struct greth_regs *mmio;
	struct netif *netif;
	atomic_bool drv_exit;
	addr_t dev_phys_addr;

	handle_t irq_cond;
	handle_t irq_lock;
	handle_t irq_handle;
	uint32_t irq_stack[1024] __attribute__((aligned(16)));

	handle_t tx_lock;
	handle_t rx_lock;
	union {
		struct {
			net_bufdesc_ring_t rx, tx;
		};
		net_bufdesc_ring_t rings[2];
	};

	eth_phy_state_t phy;

} greth_state_t;


#if !GRETH_EDCL
static void greth_disableEdcl(greth_state_t *state)
{
	state->mmio->CTRL = GRETH_CTRL_ED;
}
#endif


__attribute__((section(".interrupt"), aligned(0x1000))) static int greth_irqHandler(unsigned int n, void *arg)
{
	(void)n;
	greth_state_t *state = arg;
	uint32_t events;

	events = state->mmio->STAT;
	state->mmio->CTRL &= ~(GRETH_CTRL_TI | GRETH_CTRL_RI | GRETH_CTRL_PI);

	if ((events & (GRETH_STAT_TA | GRETH_STAT_RA)) != 0) {
		state->drv_exit = true;
	}

	return 0;
}


static void greth_irqThread(void *arg)
{
	greth_state_t *state = arg;
	size_t rx_done = 0;

	mutexLock(state->irq_lock);
	while (!state->drv_exit) {

		if ((state->mmio->STAT & (GRETH_STAT_RI | GRETH_STAT_RE)) != 0) {
			state->mmio->STAT = GRETH_STAT_RI;
			rx_done = net_receivePackets(&state->rx, state->netif);
			if ((rx_done > 0) || (net_rxFullyFilled(&state->rx) == 0)) {
				net_refillRx(&state->rx);
				state->mmio->CTRL |= GRETH_CTRL_RE;
			}
		}

		if ((state->mmio->STAT & (GRETH_STAT_TI | GRETH_STAT_TE)) != 0) {
			state->mmio->STAT = GRETH_STAT_TI;
			net_reapTxFinished(&state->tx);
		}

		if ((state->mmio->STAT & GRETH_STAT_PS) != 0) {
			state->mmio->STAT = GRETH_STAT_PS;
			ephy_macInterrupt(&state->phy);
		}

		if ((state->mmio->STAT & (GRETH_STAT_TI | GRETH_STAT_RI | GRETH_STAT_PS)) == 0) {
			state->mmio->CTRL |= GRETH_CTRL_TI | GRETH_CTRL_RI | GRETH_CTRL_PI;
			condWait(state->irq_cond, state->irq_lock, 0);
		}
	}
	mutexUnlock(state->irq_lock);


	if ((state->mmio->STAT & GRETH_STAT_TA) != 0) {
		greth_printf(state, "HW signalled TX AHB error -- device halted");
	}
	if ((state->mmio->STAT & GRETH_STAT_RA) != 0) {
		greth_printf(state, "HW signalled RX AHB error -- device halted");
	}

	endthread();
}


/* MDIO */


#if GRETH_DEBUG
static inline const char *greth_mdioOpToString(unsigned op)
{
	switch (op) {
		case GRETH_MDIO_READ:
			return "READ";
		case GRETH_MDIO_WRITE:
			return "WRITE";
		default:
			return "UNDEFINED";
	}
}
#endif


static uint16_t greth_mdioIO(greth_state_t *state, unsigned addr, unsigned reg, unsigned val, unsigned op)
{
	uint32_t greth_reg =
			((val << GRETH_MDIO_DATA_SHIFT) & GRETH_MDIO_DATA_MASK) |
			((addr << GRETH_MDIO_PHYADDR_SHIFT) & GRETH_MDIO_PHYADDR_MASK) |
			((reg << GRETH_MDIO_REGADDR_SHIFT) & GRETH_MDIO_REGADDR_MASK) |
			op;
	greth_debug_printf(state, "mdio: op %s, addr=0x%08x, reg=0x%08x, val=0x%04x greth_reg: %08x", greth_mdioOpToString(op), addr, reg, val, greth_reg);

	state->mmio->MDIO = greth_reg;
	while ((state->mmio->MDIO & GRETH_MDIO_BUSY) != 0) { }
	return ((state->mmio->MDIO & GRETH_MDIO_DATA_MASK) >> GRETH_MDIO_DATA_SHIFT);
}


static int greth_mdioSetup(void *arg, unsigned max_khz, unsigned min_hold_ns, unsigned opt_preamble)
{
	/* GR740 turn on PHY interrupts */
	greth_state_t *state = arg;
	state->mmio->CTRL |= GRETH_CTRL_PI;
	return 0;
}


static uint16_t greth_mdioRead(void *arg, unsigned addr, uint16_t reg)
{
	greth_state_t *state = arg;
	return greth_mdioIO(state, addr, reg, 0, GRETH_MDIO_READ);
}


static void greth_mdioWrite(void *arg, unsigned addr, uint16_t reg, uint16_t val)
{
	greth_state_t *state = arg;
	(void)greth_mdioIO(state, addr, reg, val, GRETH_MDIO_WRITE);
}


static const mdio_bus_ops_t greth_mdio_ops = {
	greth_mdioSetup,
	greth_mdioRead,
	greth_mdioWrite,
};


static void greth_setLinkState(void *arg, int state)
{
	struct netif *netif = arg;
	greth_state_t *s = netif->state;
	int speed, full_duplex;
	uint32_t ctrl;

	if (state != 0) {
		speed = ephy_linkSpeed(&s->phy, &full_duplex);
		ctrl = s->mmio->CTRL & ~(GRETH_CTRL_FD | GRETH_CTRL_SP | GRETH_CTRL_GB);

		if (full_duplex != 0) {
			ctrl |= GRETH_CTRL_FD;
		}
		switch (speed) {
			case 10:
				break;
			case 100:
				ctrl |= GRETH_CTRL_SP;
				break;
			case 1000:
				ctrl |= GRETH_CTRL_GB | GRETH_CTRL_FD;
				break;
			default:
				break;
		}
		s->mmio->CTRL = ctrl;
		netif_set_link_up(netif);
	}
	else {
		netif_set_link_down(netif);
	}
}

/* TX / RX */
static size_t greth_nextRxBufferSize(const net_bufdesc_ring_t *ring, size_t i)
{
	volatile greth_buf_desc_t *desc = (volatile greth_buf_desc_t *)ring->ring + i;
	size_t sz;
	if ((desc->flags & GRETH_DESC_EN) != 0) {
		return 0;
	}
	sz = (desc->flags >> GRETH_DESC_LEN_SHIFT) & GRETH_DESC_LEN_MASK;
	if (sz == 0) {
		sz = 1;
		printf("lwip: greth: WARNING: This message indicates a potential HW bug:\n");
		printf("lwip: greth: HW provided invalid size: %zu. Setting size to 1\n", sz);
	}
	return sz;
}


static bool greth_pktRxFinished(const net_bufdesc_ring_t *ring, size_t i)
{
	volatile greth_buf_desc_t *desc = (volatile greth_buf_desc_t *)ring->ring + i;

	return ((desc->flags & GRETH_DESC_EN) == 0u);
}


static void greth_fillRxDesc(const net_bufdesc_ring_t *ring, size_t i, addr_t pa, size_t sz, unsigned seg)
{
	(void)sz;
	volatile greth_buf_desc_t *desc = (volatile greth_buf_desc_t *)ring->ring + i;
	unsigned wrap = desc == (volatile greth_buf_desc_t *)ring->ring + ring->last ? GRETH_DESC_WR : 0;

	desc->addr = pa;

	atomic_thread_fence(memory_order_seq_cst);
	desc->flags = GRETH_DESC_EN | GRETH_DESC_IE | wrap;
	atomic_thread_fence(memory_order_seq_cst);
}


static bool greth_nextTxDone(const net_bufdesc_ring_t *ring, size_t i)
{
	volatile greth_buf_desc_t *desc = (volatile greth_buf_desc_t *)ring->ring + i;
	return ((desc->flags & GRETH_DESC_EN) == 0u);
}


static void greth_fillTxDesc(const net_bufdesc_ring_t *ring, size_t i, addr_t pa, size_t sz, unsigned seg)
{
	volatile greth_buf_desc_t *desc = (volatile greth_buf_desc_t *)ring->ring + i;
	uint32_t flags;

	flags = GRETH_DESC_EN;
	flags |= (i == ring->last) ? GRETH_DESC_WR : 0;
	flags |= (sz << GRETH_DESC_LEN_SHIFT) & GRETH_DESC_LEN_MASK; /* shift (0) just for consistency  */
	flags |= ((seg & BDRING_SEG_LAST) != 0) ? 0 : GRETH_DESC_TX_MO;
	flags |= GRETH_DESC_IE;
	flags |= GRETH_DESC_TX_UC | GRETH_DESC_TX_TC | GRETH_DESC_TX_IC;

	desc->addr = pa;
	atomic_thread_fence(memory_order_seq_cst);
	desc->flags = flags;
	atomic_thread_fence(memory_order_seq_cst);
}


static const net_bufdesc_ops_t greth_ring_ops = {
	.nextRxBufferSize = greth_nextRxBufferSize,
	.pktRxFinished = greth_pktRxFinished,
	.fillRxDesc = greth_fillRxDesc,
	.nextTxDone = greth_nextTxDone,
	.fillTxDesc = greth_fillTxDesc,
	.desc_size = sizeof(greth_buf_desc_t),
	.pkt_buf_sz = GRETH_MAX_PKT_SZ,
	.ring_alignment = 1024,
	.max_tx_frag = 0xFFFF,
};

static const size_t greth_ring_sizes[] = { GRETH_RX_RING_SIZE, GRETH_TX_RING_SIZE };


static int greth_initRings(greth_state_t *state)
{
	int err;

	err = net_initRings(state->rings, greth_ring_sizes, sizeof(state->rings) / sizeof(*state->rings), &greth_ring_ops);
	if (err != 0) {
		return err;
	}

	state->mmio->TX_DESC_PTR = state->tx.phys;
	state->mmio->RX_DESC_PTR = state->rx.phys;

	return 0;
}


static err_t greth_netifOutput(struct netif *netif, struct pbuf *p)
{
	greth_state_t *state = netif->state;
	size_t nf;

#if (ETH_PAD_SIZE != 0)
	(void)pbuf_remove_header(p, ETH_PAD_SIZE); /* drop the padding word (not supported by HW) */
#endif

	mutexLock(state->tx_lock);
	nf = net_transmitPacket(&state->tx, p);
	if (nf != 0) {
		state->mmio->CTRL |= GRETH_CTRL_TE;
	}
	mutexUnlock(state->tx_lock);

	return (nf != 0) ? ERR_OK : ERR_BUF;
}


static inline uint8_t greth_getByte(uint32_t v, int i)
{
	return (v >> (i * 8)) & 0xFF;
}


static void greth_setCardMac(greth_state_t *state)
{
	uint64_t mac = GRETH_MAC_IAB;
#ifdef GRETH_EUI48
	mac |= (GRETH_EUI48 & 0xFFFu);
#endif
	state->mmio->MAC_MSB = mac >> 32;
	state->mmio->MAC_LSB = mac & 0xFFFFFFFFu;
}


static void greth_readCardMac(greth_state_t *state)
{
	uint8_t *mac = state->netif->hwaddr;

	/* MAC LSB reg*/
	mac[5] = greth_getByte(state->mmio->MAC_LSB, 0);
	mac[4] = greth_getByte(state->mmio->MAC_LSB, 1);
	mac[3] = greth_getByte(state->mmio->MAC_LSB, 2);
	mac[2] = greth_getByte(state->mmio->MAC_LSB, 3);

	/* MAC MSB reg*/
	mac[1] = greth_getByte(state->mmio->MAC_MSB, 0);
	mac[0] = greth_getByte(state->mmio->MAC_MSB, 1);
}


static void greth_showCardId(greth_state_t *state)
{
	uint8_t *mac;
	mac = (void *)&state->netif->hwaddr;
	greth_printf(state, "initizalized, MAC=%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}


static void greth_startGreth(greth_state_t *state)
{
	/* clear status */
	state->mmio->STAT =
			GRETH_STAT_IA | GRETH_STAT_TS |
			GRETH_STAT_TA | GRETH_STAT_RA |
			GRETH_STAT_TI | GRETH_STAT_RI |
			GRETH_STAT_TE | GRETH_STAT_RE;

	/* interrupt mask */
	state->mmio->CTRL |= GRETH_CTRL_TI | GRETH_CTRL_RI;

	state->mmio->CTRL |= GRETH_CTRL_RE;
}


static int greth_createResources(greth_state_t *state)
{
	state->irq_lock = (handle_t)-1;
	state->irq_cond = (handle_t)-1;

	if (mutexCreate(&state->irq_lock) < 0) {
		return -1;
	}
	if (condCreate(&state->irq_cond) < 0) {
		return -1;
	}
	return 0;
}


static void greth_cleanupResources(greth_state_t *state)
{
	if (state->irq_lock != (handle_t)-1) {
		resourceDestroy(state->irq_lock);
	}
	if (state->irq_cond != (handle_t)-1) {
		resourceDestroy(state->irq_cond);
	}
}


static void greth_reset(greth_state_t *state)
{
	state->mmio->CTRL = GRETH_CTRL_RS;
	while ((state->mmio->CTRL & GRETH_CTRL_RS) != 0) { }
}


static int greth_initDevice(greth_state_t *state, int irq, bool mdio)
{
	state->mmio = physmmap(state->dev_phys_addr, _PAGE_SIZE);
	if (state->mmio == MAP_FAILED) {
		return -ENOMEM;
	};

	greth_reset(state);

#if !GRETH_EDCL
	greth_disableEdcl(state);
#endif

	int err = greth_initRings(state);
	if (err != 0) {
		return err;
	}
	greth_debug_printf(state, "Initialized GRETH Rings");


	if (mdio) {
		err = register_mdio_bus(&greth_mdio_ops, state);
		if (err < 0) {
			greth_printf(state, "Can't register MDIO bus:  %s (%d)", strerror(-err), err);
			return err;
		}

		greth_debug_printf(state, "MDIO bus %d", err);
	}

	err = greth_createResources(state);
	if (err != 0) {
		greth_printf(state, "Couldn't create resources: %s (%d)", strerror(-err), err);
		greth_cleanupResources(state);
		return err;
	}

	err = interrupt(irq, greth_irqHandler, state, state->irq_cond, NULL);
	if (err != 0) {
		greth_printf(state, "Couldn't register interrupt handler: %s (%d)", strerror(-err), err);
		greth_cleanupResources(state);
		return err;
	}
	greth_debug_printf(state, "Interrupt handler initialized successfully");

	err = beginthread(greth_irqThread, 1, state->irq_stack, sizeof(state->irq_stack), state);
	if (err != 0) {
		greth_printf(state, "Couldn't begin interrupt thread: %s (%d)", strerror(-err), err);
		greth_cleanupResources(state);
		return err;
	}

	greth_setCardMac(state);
	greth_readCardMac(state);
	greth_showCardId(state);

	net_refillRx(&state->rx);
	greth_startGreth(state);

	return err;
};


static int greth_netifInit(struct netif *netif, char *cfg)
{
	greth_state_t *state;
	char *p;
	int err, irq;
	bool mdio = true;

	netif->linkoutput = greth_netifOutput;
	state = netif->state;
	state->netif = netif;

	if (cfg == NULL) {
		return -EINVAL;
	}

	/* base addr */
	state->dev_phys_addr = strtoul(cfg, &p, 0);
	if (*cfg == '\0' || *p != ':') {
		return -EINVAL;
	}
	p++;

	/* irq */
	cfg = p;
	irq = strtoul(cfg, &p, 0);
	if (*cfg == '\0' || (*p != '\0' && *p != ':') || irq < 0) {
		return -EINVAL;
	}
	p++;

	/* MDIO and PHY opts */
	cfg = NULL;
	while (p != NULL && *p != '\0') {
		cfg = strchr(p, ':');
		if (cfg != NULL) {
			*cfg = '\0';
			cfg++;
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

	err = greth_initDevice(state, irq, mdio);
	if (err != 0) {
		return err;
	}
	greth_debug_printf(state, "Initialized GRETH");

	if (cfg != NULL) {
		err = ephy_init(&state->phy, cfg, 0, greth_setLinkState, (void *)state->netif);
		if (err < 0) {
			greth_printf(state, "WARN: PHY init failed: %s (%d)", strerror(-err), err);
			greth_cleanupResources(state);
			return err;
		}
	}

	return 0;
}


const char *greth_media(struct netif *netif)
{
	int full_duplex, speed;
	greth_state_t *state;
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


static netif_driver_t greth_drv = {
	.init = greth_netifInit,
	.state_sz = sizeof(greth_state_t),
	.state_align = _Alignof(greth_state_t),
	.name = "greth",
	.media = greth_media,
};


__constructor__(1000) void register_driver_greth(void)
{
	register_netif_driver(&greth_drv);
}
