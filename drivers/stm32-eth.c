/*
 * Phoenix-RTOS --- networking stack
 *
 * STM32 ETH network module driver
 *
 * Copyright 2018, 2024, 2026 Phoenix Systems
 * Author: Michał Mirosław, Julian Uziembło, Jacek Maksymowicz
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
#include <stm32l4-multi.h>
#include <string.h>
#include <unistd.h>

#include "stm32-gpio.h"
#include "stm32-eth-regs.h"

#include <board_config.h>

#if defined(__CPU_STM32N6)
#include <phoenix/arch/armv8m/stm32/n6/stm32n6.h>

#define N_ETH   1
#define N_PCTLS 4
#else
#error "Unsupported platform"
#endif


#define WIP_UNFINISHED 0 /* TODO: this is so that MDIO communication can be tested */
/* Note: names starting with "ETH" have been fully adapted for STM32 ETH peripheral, while names starting with ENET
 * are more-or-less copy-pasted from imxrt implementation */
/* TODO: remove the #pragma region for final release */

#define ETH_DEBUG      1
#define MDIO_TIMEOUT   0
#define MDIO_DEBUG     0
#define ENET_SELFTEST  0 /* TODO: self-test functionality has not been ported to STM32N6! Decide later if it should be re-implemented or deleted. */
#define EPHY_BOARD_REV 0 /* TODO: I'm not sure what this is for, for now hardcoded to 0 */

#define ETH_MAX_PKT_SZ           1536 /* Receive buffer length (must be a multiple of 4) */
#define ETH_ENABLE_FLOW_CONTROL  true
#define ETH_PROMISC_MODE         false
#define ETH_ENABLE_RX_PAD_REMOVE true
#define ETH_RX_RING_SIZE         4
#define ETH_TX_RING_SIZE         4

#define MAIN_DMA_RX_CHANNEL 0UL
#define RESET_TIMEOUT_US    500000U

#define eth_printf(state, fmt, ...) printf("lwip: ETH%u: " fmt "\n", state->devnum, ##__VA_ARGS__)

#if ETH_DEBUG
#define eth_debug_printf(state, fmt, ...) eth_printf(state, fmt, ##__VA_ARGS__)
#else
#define eth_debug_printf(state, fmt, ...)
#endif

#define CHECK(x) \
	do { \
		int _ret = x; \
		if (_ret < 0) { \
			return _ret; \
		} \
	} while (0)

#define CHECK_MSG(x, state, ...) \
	do { \
		int _ret = x; \
		if (_ret < 0) { \
			eth_printf(state, ##__VA_ARGS__); \
			return _ret; \
		} \
	} while (0)


typedef struct {
	int16_t port; /* < 0 indicates pin not present */
	uint8_t pin;
	int8_t afMode; /* < 0 indicates pin works as GPIO, use STM32_PIN_SETUP_* */
} stm32_pin_setup_t;


#define eth_phymode_mii   0
#define eth_phymode_rmii  1
#define eth_phymode_rgmii 2

/*
 * Note: the numbering of eth_rmii_* and eth_rgmii_* enums has been chosen so that
 * corresponding RMII and RGMII pins have the same value. This may be useful in the future.
 */
enum {
	eth_rmii_ref_clk,
	eth_rmii_crs_dv,
	eth_rmii_tx_en,
	eth_rmii_txd0,
	eth_rmii_txd1,
	eth_rmii_rxd0,
	eth_rmii_rxd1,
	eth_rmii_pins,
};


enum {
	eth_rgmii_rx_clk,
	eth_rgmii_rx_ctl,
	eth_rgmii_tx_ctl,
	eth_rgmii_txd0,
	eth_rgmii_txd1,
	eth_rgmii_rxd0,
	eth_rgmii_rxd1,
	eth_rgmii_gtx_clk,
	eth_rgmii_clk125,
	eth_rgmii_txd2,
	eth_rgmii_txd3,
	eth_rgmii_rxd2,
	eth_rgmii_rxd3,
	eth_rgmii_pins,
};

typedef union {
	stm32_pin_setup_t rmii[eth_rmii_pins];
	stm32_pin_setup_t rgmii[eth_rgmii_pins];
} eth_pinout_t;

/* Pins common for all modes */
enum {
	eth_phy_mdc = 0U,
	eth_phy_mdio,
	eth_phy_intn,
	eth_phy_pins,
};

#ifndef ETH1_RX_REFCLK_INTERNAL
#define ETH1_RX_REFCLK_INTERNAL 1
#endif

#ifndef ETH1_TX_REFCLK_INTERNAL
#define ETH1_TX_REFCLK_INTERNAL 1
#endif

#ifndef ETH1_CLK_OUTPUT
#define ETH1_CLK_OUTPUT 0
#endif

#if defined(ETH1_MODE_RMII) && !defined(ETH1_MODE_RGMII) && !defined(ETH1_MODE_MII)
#define ETH1_PHYMODE eth_phymode_rmii
#elif defined(ETH1_MODE_RGMII) && !defined(ETH1_MODE_RMII) && !defined(ETH1_MODE_MII)
#define ETH1_PHYMODE eth_phymode_rgmii
#elif defined(ETH1_MODE_MII) && !defined(ETH1_MODE_RMII) && !defined(ETH1_MODE_RGMII)
#error "MII mode not supported yet"
#else
#error "Must define exactly one of ETH1_MODE_RMII, ETH1_MODE_RGMII or ETH1_MODE_MII"
#endif


static const struct {
	addr_t base;
	int irq;
	int pctls[N_PCTLS];
	stm32_pin_setup_t pinoutPhy[eth_phy_pins]; /* Pinout for PHY management and interrupts */
	stm32_pin_setup_t pinClk;
	eth_pinout_t pinout;
	unsigned int phyMode;
	unsigned int macOtpFuses[2]; /* Low and high OTP fuse containing MAC address */
	int ipclkMode;               /* PCTL for selecting MII/RMII/RGMII mode */
	int ipclkClksel;             /* PCTL for selecting ck_ker_ethX clock */
	int ipclkRxRefclk;           /* PCTL for selecting internal/external RX reference clock */
	int ipclkTxRefclk;           /* PCTL for selecting internal/external TX reference clock */
	uint32_t hclkFreqHz;         /* eth_hclk, also called "CSR clock" in docs. */
	uint8_t clksel;              /* Selection of source for ck_ker_ethX, */
	bool rxRefclkInternal;       /* RX reference clock source: external pin or internally generated */
	bool txRefclkInternal;       /* TX reference clock source: external pin or internally generated */
} eth_setup[N_ETH] = {
#if defined(__CPU_STM32N6)
	{
		.base = 0x58036000UL,
		.irq = eth1_irq,
		.pctls = { pctl_eth1, pctl_eth1mac, pctl_eth1tx, pctl_eth1rx },
		.pinoutPhy = {
			[eth_phy_mdc] = { ETH1_MDC_PORT, ETH1_MDC_PIN, 11 },
			[eth_phy_mdio] = { ETH1_MDIO_PORT, ETH1_MDIO_PIN, 11 },
#ifdef ETH1_PHY_INTN_PORT
			[eth_phy_intn] = { ETH1_PHY_INTN_PORT, ETH1_PHY_INTN_PIN, 11 },
#else
			[eth_phy_intn] = { -1, 0, 0 },
#endif
		},
#if ETH1_CLK_OUTPUT
		.pinClk = { gpiof, 5, 11 },
#else
		.pinClk = { -1, 0, 0 },
#endif
		.pinout = {
#if ETH1_PHYMODE == eth_phymode_rmii
			.rmii = {
#if ETH1_RX_REFCLK_INTERNAL == 0
				[eth_rmii_ref_clk] = { ETH1_REF_CLK_PORT, ETH1_REF_CLK_PIN, 11 },
#else
				[eth_rmii_ref_clk] = { -1, 0, 0 },
#endif
				[eth_rmii_crs_dv] = { gpiof, 10, 11 },
				[eth_rmii_tx_en] = { gpiof, 11, 11 },
				[eth_rmii_txd0] = { gpiof, 12, 11 },
				[eth_rmii_txd1] = { gpiof, 13, 11 },
				[eth_rmii_rxd0] = { gpiof, 14, 11 },
				[eth_rmii_rxd1] = { gpiof, 15, 11 },
			},
#elif ETH1_PHYMODE == eth_phymode_rgmii
			.rgmii = {
#if ETH1_RX_REFCLK_INTERNAL == 0
				[eth_rgmii_rx_clk] = { gpiof, 7, 11 },
#else
				[eth_rgmii_rx_clk] = { -1, 0, 0 },
#endif
				[eth_rgmii_rx_ctl] = { gpiof, 10, 11 },
				[eth_rgmii_tx_ctl] = { gpiof, 11, 11 },
				[eth_rgmii_txd0] = { gpiof, 12, 11 },
				[eth_rgmii_txd1] = { gpiof, 13, 11 },
				[eth_rgmii_rxd0] = { gpiof, 14, 11 },
				[eth_rgmii_rxd1] = { gpiof, 15, 11 },
				[eth_rgmii_gtx_clk] = { gpiof, 0, 12 },
#if ETH1_TX_REFCLK_INTERNAL == 0
				[eth_rgmii_clk125] = { gpiof, 2, 11 },
#else
				[eth_rgmii_clk125] = { -1, 0, 0 },
#endif
				[eth_rgmii_txd2] = { gpiog, 3, 11 },
				[eth_rgmii_txd3] = { gpiog, 4, 11 },
				[eth_rgmii_rxd2] = { gpiof, 8, 11 },
				[eth_rgmii_rxd3] = { gpiof, 9, 11 },

			}
#else
#error "ETH1_PHYMODE has invalid value"
#endif
		},
		.phyMode = ETH1_PHYMODE,
		.macOtpFuses = { 169, 170 },
		.ipclkMode = pctl_ipclk_eth1sel,
		.ipclkClksel = pctl_ipclk_eth1clksel,
		.ipclkRxRefclk = pctl_ipclk_eth1refclksel,
		.ipclkTxRefclk = pctl_ipclk_eth1gtxclksel,
		.hclkFreqHz = 200U * 1000U * 1000U, /* TODO: acquire from multidriver */
		.clksel = 0u,                       /* HCLK selected as reference clock */
		.rxRefclkInternal = (ETH1_RX_REFCLK_INTERNAL != 0),
		.txRefclkInternal = (ETH1_TX_REFCLK_INTERNAL != 0),
	},
#endif
};

typedef struct {
	volatile uint32_t descr[4];
	uint32_t addr0;
	uint32_t addr1;
} eth_desc_t;


typedef struct {
	volatile uint32_t *base;

	struct netif *netif;

#define PRIV_RESOURCES(s) &(s)->irq_lock, 3, ~0x03
	handle_t irq_lock, tx_lock;

	handle_t irq_cond, irq_handle;

	union {
		struct {
			net_bufdesc_ring_t rx, tx;
		};
		net_bufdesc_ring_t rings[2];
	};

	size_t devnum;
	oid_t multidrvOid;
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


static int stm32_pinConfigMulti(const oid_t *dev, const stm32_pin_setup_t *pins, size_t nPins)
{
	for (size_t i = 0; i < nPins; i++) {
		if (pins[i].port < 0) {
			continue;
		}

		CHECK(stm32_pinConfig(dev, pins[i].port, pins[i].pin, pins[i].afMode));
	}

	return 0;
}


static int stm32_getOTP(unsigned int word, unsigned int *out)
{
	platformctl_t pctl;
	pctl.action = pctl_get;
	pctl.type = pctl_otp;
	pctl.otp.addr = word;
	pctl.otp.val = 0; /* Will be overwritten on success */

	CHECK(platformctl(&pctl));
	*out = pctl.otp.val;
	return 0;
}


static int eth_reset(enet_state_t *state, size_t idx, time_t timeout)
{
	time_t now, when;

	eth_debug_printf(state, "Resetting device...");

	gettime(&now, NULL);
	when = now + timeout;
	/* trigger and wait for reset */

	state->base[eth_dmamr] |= ETH_DMAMR_SWR;
	asm volatile("dsb" ::: "memory"); /* TODO: HAL? */
	while (1) {
		if ((state->base[eth_dmamr] & ETH_DMAMR_SWR) == 0) {
			break;
		}

		usleep(1000);
		if (timeout != 0) {
			gettime(&now, NULL);
			if (now >= when) {
				eth_printf(state, "Couldn't reset device: timeout");
				return -ETIMEDOUT;
			}
		}
	}

	eth_debug_printf(state, "Reset done.");

	state->base[eth_mac1ustcr] = (eth_setup[idx].hclkFreqHz / (1000U * 1000U)) - 1;
	/* TODO: do any other initialization? */

	return 0;
}


static void enet_start(enet_state_t *state, size_t idx)
{
	uint32_t v;
	v = state->base[eth_maccr];
	v &= ~(
			ETH_MACCR_PRELEN_MASK |
			ETH_MACCR_DC | /* Disable deferral check */
			ETH_MACCR_BL_MASK |
			ETH_MACCR_DR |
			ETH_MACCR_DCRS |
			ETH_MACCR_DO |
			ETH_MACCR_ECRSFD |
			ETH_MACCR_LM | /* Disable loopback */
			ETH_MACCR_JE | /* Disable jumbo packet */
			ETH_MACCR_JD | /* Enable jabber */
			ETH_MACCR_BE |
			ETH_MACCR_WD | /* Enable watchdog (cut off RX at 2048 bytes) */
			ETH_MACCR_ACS |
			ETH_MACCR_CST |
			ETH_MACCR_S2KP |
			ETH_MACCR_GPSLCE);

	/* Select default link speed and duplex */
	v |= ETH_MACCR_DM;
	switch (eth_setup[idx].phyMode) {
		case eth_phymode_rgmii:
			v &= ~(ETH_MACCR_FES | ETH_MACCR_PS); /* 1 Gbps mode */
			break;

		case eth_phymode_rmii: /* Fall-through */
		case eth_phymode_mii:
			v |= ETH_MACCR_FES | ETH_MACCR_PS; /* 100 Mbps mode */
			break;

		default:
			/* Should never happen */
			break;
	}

	v |= 0 << ETH_MACCR_PRELEN_SHIFT; /* 7 bytes of preamble */
	v |= 0 << ETH_MACCR_BL_SHIFT;     /* Back-off limited to 2^10 slot delays */
	v |= ETH_ENABLE_RX_PAD_REMOVE ? ETH_MACCR_ACS : 0;
	v |= ETH_MACCR_IPC; /* Enable checksum offload TODO: is this okay? */
	state->base[eth_maccr] = v;

	v = state->base[eth_macecr];
	v &= ~(ETH_MACECR_EIPG_MASK | ETH_MACECR_EIPGEN | ETH_MACECR_USP | ETH_MACECR_SPEN | ETH_MACECR_DCRCC | ETH_MACECR_GPSL_MASK);
	v |= (1560 << ETH_MACECR_GPSL_SHIFT) & ETH_MACECR_GPSL_MASK; /* Set giant packet size limit (not used unless ETH_MACCR_GPSLCE is set) */
	state->base[eth_macecr] = v;

	v = state->base[eth_macwtr];
	v &= ~(ETH_MACWTR_WTO_MASK | ETH_MACWTR_PWE); /* Disable programmable watchdog */
	state->base[eth_macwtr] = v;

	v = state->base[eth_macpfr];
	v &= ~ETH_MACPFR_PR;
	v |= ETH_PROMISC_MODE ? ETH_MACPFR_PR : 0;
	state->base[eth_macpfr] = v;

	v = state->base[eth_macrxfcr];
	v &= ~(ETH_MACRXFCR_UP | ETH_MACRXFCR_RFE);
	v |= ETH_ENABLE_FLOW_CONTROL ? ETH_MACRXFCR_RFE : 0;
	state->base[eth_macrxfcr] = v;

	v = state->base[eth_macq0txfcr];
	v &= ~(ETH_MACQ0TXFCR_PT_MASK | ETH_MACQ0TXFCR_DZPQ | ETH_MACQ0TXFCR_PLT_MASK | ETH_MACQ0TXFCR_TFE);
	v |= ETH_ENABLE_FLOW_CONTROL ? (ETH_MACQ0TXFCR_DZPQ | ETH_MACQ0TXFCR_TFE) : 0;
	state->base[eth_macq0txfcr] = v;

#if WIP_UNFINISHED
	state->mmio->MRBR = ENET_MAX_PKT_SZ;
	state->mmio->FTRL = BIT(14) - 1;  // FIXME: truncation to just above link MTU

	uint32_t rcr = ENET_RCR_MAX_FL_NO_VLAN_VAL << ENET_RCR_MAX_FL_SHIFT |
			ENET_RCR_CRCFWD | ENET_RCR_PAUFWD;

	state->mmio->RACC =
#if ETH_PAD_SIZE == 2
			ENET_RACC_SHIFT16 |
#elif ETH_PAD_SIZE != 0
#error "Unsupported ETH_PAD_SIZE"
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
	state->base[eth_maccr] |= ETH_MACCR_TE | ETH_MACCR_RE;
#endif
}


static void eth_showCardId(enet_state_t *state)
{
	uint8_t *mac = (void *)&state->netif->hwaddr;
	eth_printf(state, "initialized, MAC=%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}


static size_t enet_nextRxBufferSize(const net_bufdesc_ring_t *ring, size_t i)
{
#if WIP_UNFINISHED
	volatile enet_buf_desc_t *desc = (volatile enet_buf_desc_t *)ring->ring + i;
	size_t sz;

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
#else
	return 0;
#endif
}


static bool enet_pktRxFinished(const net_bufdesc_ring_t *ring, size_t i)
{
#if WIP_UNFINISHED
	volatile enet_buf_desc_t *desc = (volatile enet_buf_desc_t *)ring->ring + i;

	return ((desc->flags & ENET_DESC_LAST) != 0u);
#else
	return false;
#endif
}


static void enet_fillRxDesc(const net_bufdesc_ring_t *ring, size_t i, addr_t pa, size_t sz, unsigned seg)
{
#if WIP_UNFINISHED
	volatile enet_buf_desc_t *desc = (volatile enet_buf_desc_t *)ring->ring + i;
	unsigned wrap = desc == (volatile enet_buf_desc_t *)ring->ring + ring->last ? ENET_DESC_WRAP : 0;

	desc->len = sz - ETH_PAD_SIZE;
	desc->addr = pa;

	atomic_thread_fence(memory_order_seq_cst);
	desc->flags = ENET_DESC_RDY | wrap;
	atomic_thread_fence(memory_order_seq_cst);
#endif
}


static bool enet_nextTxDone(const net_bufdesc_ring_t *ring, size_t i)
{
#if WIP_UNFINISHED
	volatile enet_buf_desc_t *desc = (volatile enet_buf_desc_t *)ring->ring + i;

	return ((desc->flags & ENET_DESC_RDY) == 0u);
#else
	return true;
#endif
}


static void enet_fillTxDesc(const net_bufdesc_ring_t *ring, size_t i, addr_t pa, size_t sz, unsigned seg)
{
#if WIP_UNFINISHED
	volatile enet_buf_desc_t *desc = (volatile enet_buf_desc_t *)ring->ring + i;
	unsigned flags;

	flags = ENET_DESC_RDY | ENET_TXD_TXCRC;
	flags |= (i == ring->last) ? ENET_DESC_WRAP : 0;
	flags |= ((seg & BDRING_SEG_LAST) != 0) ? ENET_DESC_LAST : 0;

	desc->len = sz;
	desc->addr = pa;


	atomic_thread_fence(memory_order_seq_cst);
	desc->flags = flags;
	atomic_thread_fence(memory_order_seq_cst);
#endif
}


static const net_bufdesc_ops_t enet_ring_ops = {
	.nextRxBufferSize = enet_nextRxBufferSize,
	.pktRxFinished = enet_pktRxFinished,
	.fillRxDesc = enet_fillRxDesc,
	.nextTxDone = enet_nextTxDone,
	.fillTxDesc = enet_fillTxDesc,
	.desc_size = sizeof(eth_desc_t),
	.pkt_buf_sz = ETH_MAX_PKT_SZ,
	.ring_alignment = 64,
	.max_tx_frag = 0xFFFF,
};

static const size_t enet_ring_sizes[] = { ETH_RX_RING_SIZE, ETH_TX_RING_SIZE };


static int enet_initRings(enet_state_t *state)
{
	int err;

	err = net_initRings(state->rings, enet_ring_sizes, sizeof(state->rings) / sizeof(*state->rings), &enet_ring_ops);
	if (err != 0) {
		return err;
	}
#if WIP_UNFINISHED
	state->mmio->RDSR = state->rx.phys;
	state->mmio->TDSR = state->tx.phys;
#endif
	return 0;
}


static int enet_irqHandler(unsigned irq, void *arg)
{
#if WIP_UNFINISHED
	uint32_t events;
	enet_state_t *state = arg;

	events = state->mmio->EIR & (ENET_IRQ_RXF | ENET_IRQ_TXF | ENET_IRQ_EBERR);
	state->mmio->EIMR &= ~(ENET_IRQ_RXF | ENET_IRQ_TXF);

	if ((events & ENET_IRQ_EBERR) != 0) {
		atomic_fetch_or(&state->drv_exit, EV_BUS_ERROR);
	}
#endif

	return 0;
}


static void enet_irqThread(void *arg)
{
	enet_state_t *state = arg;
#if WIP_UNFINISHED
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
		eth_printf(state, "HW signalled memory bus error -- device halted");
	}
#else
	for (;;) {
		sleep(1);
		/* TODO: according to docs "This bit is set when rising edge is detected on the ETH_PHY_INTN input."
		 * In other words it appears they intend interrupts to be active high instead of active low...
		 * There's very little documentation about it, we may end up just polling the pin with GPIO
		 * or maybe use EXTI interrupt. */
		if ((state->base[eth_macisr] & ETH_MACISR_PHYIS) != 0) {
			ephy_macInterrupt(&state->phy);
		}
		else {
			printf("no irq\n");
		}
	}
#endif

	endthread();
}

static err_t eth_netifOutput(struct netif *netif, struct pbuf *p)
{
	enet_state_t *state = netif->state;
	size_t nf;

	if (ETH_PAD_SIZE != 2) {
		(void)pbuf_header(p, -ETH_PAD_SIZE); /* drop the padding word */
	}

	mutexLock(state->tx_lock);
	nf = net_transmitPacket(&state->tx, p);
	if (nf != 0) {
#if WIP_UNFINISHED
		state->mmio->TDAR = ENET_TDAR_TDAR;
#endif
	}
	mutexUnlock(state->tx_lock);

	return nf ? ERR_OK : ERR_BUF;
}


#pragma region mdio


static int eth_mdioSetup(void *arg, unsigned max_khz, unsigned min_hold_ns, unsigned opt_preamble)
{
	enet_state_t *state = arg;
	size_t idx = state->devnum - 1U;
	uint32_t v = state->base[eth_macmdioar];
	v &= ~(0xf << 8);

	/*
	 * Only consider the lower 8 options for dividers. Other options result in higher clock rates
	 * which may not be supported by PHY. And yes, on the hardware level the options are not sorted...
	 */
	static const struct {
		uint16_t divider;
		uint8_t val;
	} options[8] = {
		{ 16U, 2 },
		{ 26U, 3 },
		{ 42U, 0 },
		{ 62U, 1 },
		{ 102U, 4 },
		{ 124U, 5 },
		{ 204U, 6 },
		{ 324U, 7 },
	};

	uint32_t maxHz = max_khz * 1000U;
	uint32_t i;
	for (i = 0; i < 8; i++) {
		if ((eth_setup[idx].hclkFreqHz / options[i].divider) <= maxHz) {
			v |= (uint32_t)options[i].val << 8;
			break;
		}
	}

	if (i == 8) {
		eth_printf(state, "Cannot find an appropriate divider for MDC clock (base freq %u)", eth_setup[idx].hclkFreqHz);
		return -EIO;
	}

	/* Configuring hold time doesn't seem to be supported in hardware */
	(void)min_hold_ns;

	v &= ~ETH_MACMDIOAR_PSE;
	if (opt_preamble != 0) {
		v |= ETH_MACMDIOAR_PSE; /* Suppress preamble (only 1 bit of preamble will be transmitted) */
	}

	state->base[eth_macmdioar] = v;
	return 0;
}


static int eth_mdioWait(enet_state_t *state, time_t timeout)
{
	if (timeout != 0) {
		time_t now, when;
		gettime(&now, NULL);
		when = now + timeout;

		while ((state->base[eth_macmdioar] & ETH_MACMDIOAR_GB) != 0) {
			gettime(&now, NULL);
			if (now >= when) {
				eth_debug_printf(state, "eth_mdioWait: timeout");
				return -ETIMEDOUT;
			}

			usleep(10);
		}
	}
	else {
		while ((state->base[eth_macmdioar] & ETH_MACMDIOAR_GB) != 0) {
			/* Wait for transaction to finish */
		}
	}

	return 0;
}


static uint16_t eth_mdioIO(enet_state_t *state, unsigned addr, unsigned reg, unsigned val, bool write)
{
	const char *opString = write ? "WRITE" : "READ";
#if MDIO_DEBUG
	eth_printf(state, "mdio: op %s, addr=0x%08x, reg=0x%08x, val=0x%04x", opString, addr, reg, val);
#endif

	uint32_t ar = state->base[eth_macmdioar];
	uint32_t dr = (val & 0xffffU);

	ar &= ~(ETH_MACMDIOAR_GOC | ETH_MACMDIOAR_RDA_MASK | ETH_MACMDIOAR_PA_MASK);
	ar |= write ? ETH_MACMDIOAR_GOC_WRITE : ETH_MACMDIOAR_GOC_READ;
	if ((addr & NETDEV_MDIO_CLAUSE45) != 0) {
		/* clause 45 */
		ar |= ETH_MACMDIOAR_C45E;
		uint32_t device = addr & NETDEV_MDIO_A_MASK;
		uint32_t phy = (addr & NETDEV_MDIO_B_MASK) >> 8;
		ar |= (phy << ETH_MACMDIOAR_PA_SHIFT) & ETH_MACMDIOAR_PA_MASK;
		ar |= (device << ETH_MACMDIOAR_RDA_SHIFT) & ETH_MACMDIOAR_RDA_MASK;
		dr |= (reg & 0xffffU);
	}
	else {
		/* clause 22 */
		ar &= ~ETH_MACMDIOAR_C45E;
		ar |= (addr << ETH_MACMDIOAR_PA_SHIFT) & ETH_MACMDIOAR_PA_MASK;
		ar |= (reg << ETH_MACMDIOAR_RDA_SHIFT) & ETH_MACMDIOAR_RDA_MASK;
	}

	state->base[eth_macmdioar] = ar;
	state->base[eth_macmdiodr] = dr;
	state->base[eth_macmdioar] = ar | ETH_MACMDIOAR_GB;
	if (eth_mdioWait(state, MDIO_TIMEOUT) < 0) {
		eth_printf(state, "WARN: MDIO %s operation timeout", opString);
	}

	val = write ? 0U : (state->base[eth_macmdiodr] & 0xffffU);
	return val;
}


static uint16_t eth_mdioRead(void *arg, unsigned addr, uint16_t reg)
{
	enet_state_t *state = arg;
	return eth_mdioIO(state, addr, reg, 0, false);
}


static void eth_mdioWrite(void *arg, unsigned addr, uint16_t reg, uint16_t val)
{
	enet_state_t *state = arg;
	(void)eth_mdioIO(state, addr, reg, val, true);
}


static const mdio_bus_ops_t eth_mdio_ops = {
	eth_mdioSetup,
	eth_mdioRead,
	eth_mdioWrite,
};


#pragma endregion mdio


static void eth_setLinkState(void *arg, int state)
{
	struct netif *netif = arg;
	enet_state_t *priv = netif->state;
	uint32_t v;
	int speed, duplex;

	if (state != 0) {
		speed = ephy_linkSpeed(&priv->phy, &duplex);
		v = priv->base[eth_maccr];
		v &= ~(ETH_MACCR_DM | ETH_MACCR_FES);
		v |= duplex != 0 ? ETH_MACCR_DM : 0;
		if (speed == 1000) {
			v &= ~ETH_MACCR_PS;
		}
		else {
			v |= ETH_MACCR_PS;
			v |= (speed == 100) ? ETH_MACCR_FES : 0;
		}

		priv->base[eth_maccr] = v;
		netif_set_link_up(netif);
	}
	else {
		netif_set_link_down(netif);
	}
}


const char *eth_media(struct netif *netif)
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


#pragma region selftest
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
		eth_debug_printf(state, "self-test RX: invalid packet length");
		eth_debug_printf(state, "expected: %uB", (TEST_PACKET_LEN + ETH_PAD_SIZE));
		eth_debug_printf(state, "actual:   %uB", p->len);
		is_valid_pkt = false;
	}
	uint8_t *data = pbuf_get_contiguous(p, buf, sizeof(buf), TEST_PACKET_LEN, ETH_PAD_SIZE);
	if (data == NULL || memcmp(TEST_PACKET, data, TEST_PACKET_LEN) != 0) {
#if ETH_DEBUG
		if (data == NULL) {
			data = p->payload;
		}
		eth_printf(state, "self-test RX: invalid packet contents");

		eth_printf(state, "expected:");
		for (int i = 0; i < TEST_PACKET_LEN; i++) {
			if (i != 0 && i % 16 == 0) {
				printf("\n");
			}
			printf("%02x ", TEST_PACKET[i]);
		}
		printf("\n");

		eth_printf(state, "actual:");
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

	eth_printf(state, "Start enet phy tx/rx selftest");

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
		if (eth_netifOutput(netif, p) != ERR_OK) { /* frees pbuf internally */
			eth_printf(state, "failed to send test packet");
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

		eth_debug_printf(state, "stats: TX: PACKETS=%u CRC_ALIGN=%u OK=%u",
				state->mmio->stats.RMON_T_PACKETS,
				state->mmio->stats.RMON_T_CRC_ALIGN,
				state->mmio->stats.IEEE_T_FRAME_OK);

		eth_debug_printf(state, "stats: RX: PACKETS=%u CRC_ALIGN=%u OK=%u",
				state->mmio->stats.RMON_R_PACKETS,
				state->mmio->stats.RMON_R_CRC_ALIGN,
				state->mmio->stats.IEEE_R_FRAME_OK);

		if ((err < 0) || (state->selfTest.rx_valid != 1)) {
			eth_debug_printf(state, "Test failed: state->selfTest.rx_valid=%d, %s (%d)",
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
#pragma endregion selftest


#pragma region initialization


static int eth_initMDIO(enet_state_t *state, size_t idx)
{
	CHECK_MSG(
			stm32_pinConfigMulti(&state->multidrvOid, eth_setup[idx].pinoutPhy, eth_phy_pins),
			state, "Couldn't configure MDIO pins");


	return 0;
}


/*
 * Enable clocks and set up clock muxes for ETH module
 */
static int eth_clockEnable(enet_state_t *state, size_t idx)
{
	platformctl_t pctl;
	pctl.action = pctl_set;
	pctl.type = pctl_ipclk;
	pctl.ipclk.ipclk = eth_setup[idx].ipclkMode;
	switch (eth_setup[idx].phyMode) {
		case eth_phymode_mii: pctl.ipclk.setting = 0U; break;
		case eth_phymode_rmii: pctl.ipclk.setting = 4U; break;
		case eth_phymode_rgmii: pctl.ipclk.setting = 1U; break;
		default: return -EINVAL;
	}

	CHECK(platformctl(&pctl));

	pctl.ipclk.ipclk = eth_setup[idx].ipclkClksel;
	pctl.ipclk.setting = eth_setup[idx].clksel;
	CHECK(platformctl(&pctl));

	if (eth_setup[idx].phyMode == eth_phymode_rgmii) {
		pctl.ipclk.ipclk = eth_setup[idx].ipclkTxRefclk;
		pctl.ipclk.setting = eth_setup[idx].txRefclkInternal ? 1u : 0u;
		CHECK(platformctl(&pctl));
	}

	pctl.ipclk.ipclk = eth_setup[idx].ipclkRxRefclk;
	pctl.ipclk.setting = eth_setup[idx].rxRefclkInternal ? 1u : 0u;
	CHECK(platformctl(&pctl));

	pctl.action = pctl_set;
	pctl.type = pctl_devclk;
	pctl.devclk.state = 1u;
	pctl.devclk.lpState = 1u;
	for (size_t i = 0; i < N_PCTLS; i++) {
		if (eth_setup[idx].pctls[i] < 0) {
			continue;
		}

		pctl.devclk.dev = eth_setup[idx].pctls[i];
		CHECK_MSG(platformctl(&pctl), state, "Couldn't enable ENET clocks");
	}

	return 0;
}


/*
 * Set pin config for the required ENET module
 */
static int eth_pinConfig(enet_state_t *state, size_t idx)
{
	CHECK(stm32_pinConfigMulti(&state->multidrvOid, &eth_setup[idx].pinClk, 1));
	switch (eth_setup[idx].phyMode) {
		case eth_phymode_rmii:
			return stm32_pinConfigMulti(&state->multidrvOid, eth_setup[idx].pinout.rmii, eth_rmii_pins);

		case eth_phymode_rgmii:
			return stm32_pinConfigMulti(&state->multidrvOid, eth_setup[idx].pinout.rgmii, eth_rgmii_pins);

		case eth_phymode_mii:
			return -ENOTSUP;

		default: /* Should never happen */
			return -EINVAL;
	}

	return 0;
}


static int eth_setupMacAddr(enet_state_t *state, size_t idx)
{
	uint8_t *mac = (void *)&state->netif->hwaddr;
	unsigned int low, high;
	CHECK(stm32_getOTP(eth_setup[idx].macOtpFuses[0], &low));
	CHECK(stm32_getOTP(eth_setup[idx].macOtpFuses[1], &high));
	if ((low == 0) && (high == 0)) {
		eth_printf(state, "WARN: MAC address stored in eFuses is invalid, using default address");
		low = 0x04050607U;
		high = 0x0203U; /* Bit 2 of first octet marks it as a locally administered address */
	}

	mac[0] = (high >> 8) & 0xff;
	mac[1] = (high >> 0) & 0xff;
	mac[2] = (low >> 24) & 0xff;
	mac[3] = (low >> 16) & 0xff;
	mac[4] = (low >> 8) & 0xff;
	mac[5] = (low >> 0) & 0xff;
	state->base[eth_maca0hr] = (1UL << 31) | (MAIN_DMA_RX_CHANNEL << 16) | (high & 0xFFFF);
	state->base[eth_maca0lr] = low;
	return 0;
}


static int eth_initDevice(enet_state_t *state, unsigned long devnum, bool mdio)
{
	// FIXME: cleanup on error
	if ((devnum < 1) || (devnum > N_ETH)) {
		return -ENODEV;
	}

	state->devnum = devnum;
	size_t idx = devnum - 1U;
	int err;

	/* TODO: configurable timeout */
	for (size_t i = 0; i < 100; i++) {
		err = lookup(STM32_MULTI_PATH, NULL, &state->multidrvOid);
		if (err < 0) {
			usleep(100 * 1000);
		}
		else {
			break;
		}
	}

	CHECK_MSG(err, state, "Failed to find multidriver");

	state->base = physmmap(eth_setup[idx].base, 0x1400);
	if (state->base == MAP_FAILED) {
		eth_printf(state, "eth_initDevice: no memory");
		return -ENOMEM;
	}

	CHECK(create_mutexcond_bulk(PRIV_RESOURCES(state)));
	CHECK(eth_clockEnable(state, idx));
	eth_debug_printf(state, "Enabled clock");
	/* ETH reset will fail unless all (incl. external) clocks are provided - so configure pins first */
	CHECK_MSG(
			eth_pinConfig(state, idx),
			state, "Couldn't configure pins: %s (%d)", strerror(-_ret), _ret);
	eth_debug_printf(state, "Pins configured");
	CHECK(eth_reset(state, idx, RESET_TIMEOUT_US));
	CHECK(eth_setupMacAddr(state, idx));

	if (mdio) {
		CHECK(eth_initMDIO(state, idx));
		eth_debug_printf(state, "Initialized MDIO");
	}

	CHECK(enet_initRings(state));
	eth_debug_printf(state, "Initialized ENET Rings");
	eth_debug_printf(state, "mmio 0x%p irq %d", state->base, eth_setup[idx].irq);

	CHECK_MSG(
			interrupt(eth_setup[idx].irq, enet_irqHandler, state, state->irq_cond, &state->irq_handle),
			state, "Couldn't register interrupt handler: %s (%d)", strerror(-_ret), _ret);
	eth_debug_printf(state, "Interrupt handler initialized successfully");

	CHECK_MSG(beginthread(enet_irqThread, 4, state->irq_stack, sizeof(state->irq_stack), state),
			state, "Couldn't begin interrupt thread: %s (%d)", strerror(-_ret), _ret);

	if (mdio) {
		CHECK_MSG(
				register_mdio_bus(&eth_mdio_ops, state),
				state, "Can't register MDIO bus:  %s (%d)", strerror(-_ret), _ret);
		eth_debug_printf(state, "MDIO bus registered");
	}

	net_refillRx(&state->rx);
	enet_start(state, idx);

	eth_showCardId(state);

	return 0;
}


/* ARGS: eth:n[:no-mdio][:PHY:[model:][bus.]addr[:config]] */
static int eth_netifInit(struct netif *netif, char *cfg)
{
	enet_state_t *state;
	char *p;
	int err;
	bool mdio = true;

	netif->linkoutput = eth_netifOutput;
	state = netif->state;
	state->netif = netif;

	if (cfg == NULL) {
		return -EINVAL;
	}

	/* Ethernet peripheral number */
	unsigned long devnum = strtoul(cfg, &p, 0);
	if (*cfg == '\0' || *p++ != ':') {
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

	err = eth_initDevice(state, devnum, mdio);
	if (err != 0) {
		eth_printf(state, "Failed to initialize ETH");
		return err;
	}
	eth_debug_printf(state, "Initialized ETH");

	if (cfg != NULL) {
		err = ephy_init(&state->phy, cfg, EPHY_BOARD_REV, eth_setLinkState, (void *)state->netif);
		if (err < 0) {
			eth_printf(state, "WARN: PHY init failed: %s (%d)", strerror(-err), err);
			return err;
		}

#if ENET_SELFTEST
		err = enet_phySelfTest(netif);
		if (err < 0) {
			eth_printf(state, "WARN: PHY autotest failed");
		}
		else {
			eth_printf(state, "PHY selftest passed successfully");
		}
#endif
	}

	return 0;
}


#pragma endregion initialization


static netif_driver_t eth_drv = {
	.init = eth_netifInit,
	.state_sz = sizeof(enet_state_t),
	.state_align = _Alignof(enet_state_t),
	.name = "eth",
	.media = eth_media,
};


__constructor__(1000) void register_driver_eth(void)
{
	register_netif_driver(&eth_drv);
}
