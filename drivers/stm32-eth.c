/*
 * Phoenix-RTOS --- networking stack
 *
 * STM32 ETH network module driver
 *
 * RIF, clocks, pins, MAC reset, MAC address, MDIO bus, PHY link state polling,
 * DMA descriptor rings (cacheable memory, one descriptor per cache line), TX path (linkoutput -> TX ring -> DMA),
 * RX path (RX ring -> lwIP) and the ETH interrupt with one IRQ thread (RX, TX reaping, DMA errors, PHY polling).
 *
 * Copyright 2018, 2024, 2026 Phoenix Systems
 * Author: Michał Mirosław, Julian Uziembło, Jacek Maksymowicz
 *
 * %LICENSE%
 */


#include "arch/cc.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "netif-driver.h"
#include "bdring.h"
#include "ephy.h"
#include "physmmap.h"
#include "res-create.h"

#include <sys/mman.h>
#include <sys/platform.h>
#include <sys/threads.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stm32l4-multi.h>

#include "stm32-gpio.h"
#include "stm32-eth-regs.h"

#if defined(__CPU_STM32N6)
#include <phoenix/arch/armv8m/stm32/n6/stm32n6.h>

#define N_ETH   1
#define N_PCTLS 4
#else
#error "Unsupported platform"
#endif

/* NOTE: board_config.h uses gpio port enums from stm32l4-multi.h */
#include <board_config.h>


/* Debug output (init progress, link changes, DMA setup) - override with -DSTM32ETH_DEBUG=1 */
#ifndef STM32ETH_DEBUG
#define STM32ETH_DEBUG 0
#endif

#define ETH_DEBUG  STM32ETH_DEBUG
#define MDIO_DEBUG 0

/* Maximum TX buffer (fragment) length = TDES2.B1L limit; a smaller value forces multi-descriptor frames (test only) */
#ifndef STM32ETH_TX_MAX_FRAG
#define STM32ETH_TX_MAX_FRAG 0x3fffU
#endif

#define ETH_ENABLE_FLOW_CONTROL  true
#define ETH_PROMISC_MODE         false
#define ETH_ENABLE_RX_PAD_REMOVE true

#define MAIN_DMA_RX_CHANNEL 0UL

#define RESET_TIMEOUT_US      (500U * 1000U)
#define MDIO_TIMEOUT_US       (10U * 1000U)
#define LINK_POLL_INTERVAL_US (1000U * 1000U)
#define IRQ_THREAD_PRIO       4 /* as imx-enet; tcpip thread: 3 */

#define MULTIDRV_LOOKUP_RETRIES 100

#define ETH_REGS_SIZE 0x1400U

/*
 * DMA descriptors are in cacheable memory (dmammap(), AXISRAM): the ETH1 bus master can't reach AHBSRAM and
 * MAP_UNCACHED has no effect on NOMMU. Each 16-byte descriptor occupies its own 32-byte D-cache line:
 * DMACxCR.DSL = 2 skips 2 x 8 bytes (64-bit DMA bus, measured on NUCLEO-N657X0-Q) after each descriptor.
 * Descriptors are cleaned from D-cache before they are passed to DMA and invalidated before they are read.
 */
#define ETH_RING_RX      0
#define ETH_RING_TX      1
#define ETH_RX_RING_SIZE 16U            /* power of 2 */
#define ETH_TX_RING_SIZE 16U            /* power of 2 */
#define ETH_CACHE_LINE   32U            /* Cortex-M55 D-cache line */
#define ETH_DESC_SIZE    ETH_CACHE_LINE /* descriptor stride */
#define ETH_DESC_DSL     2U             /* (ETH_DESC_SIZE - 16) / 8 B DMA bus width */
#define ETH_RING_ALIGN   ETH_CACHE_LINE
#define ETH_RX_BUF_SIZE  1536U
#define ETH_DMA_PBL      32U /* TX/RX programmable burst length (HAL default ETH_TXDMABURSTLENGTH_32BEAT) */
#define ETH_TX_MAX_FRAGS 8U  /* bdring.c MAX_TX_FRAGMENTS: a packet needs fewer fragments than this */
#define ETH_TX_QUEUE_TQS 7U  /* MTL TX queue 0 size: 256 B * (TQS + 1) = 2048 B (HAL ETH_TRANSMIT_QUEUE_SIZE_2048) */

#define ETH_RX_QUEUE_RQS 15U /* MTL RX queue 0 size: 256 B * (RQS + 1) = 4096 B = whole RX FIFO (HAL ETH_RECEIVE_QUEUE_SIZE_4096) */

#define ETH_TX_STOP_TIMEOUT_US (10U * 1000U)
#define ETH_RX_STOP_TIMEOUT_US (10U * 1000U)
#define ETH_STATS_POLLS        10U /* debug: log TX/RX statistics every N link polls (if changed) */

/* DMA channel 0 interrupts: normal (RX/TX completion) and abnormal (RX buffer unavailable, fatal bus error) */
#define ETH_DMA_IRQS (ETH_DMACIER_NIE | ETH_DMACIER_RIE | ETH_DMACIER_TIE | ETH_DMACIER_AIE | ETH_DMACIER_RBUE | ETH_DMACIER_FBEE)

/* a full-size frame (DMA buffer of ETH_RX_BUF_SIZE) must fit in ETH_TX_MAX_FRAGS - 1 fragments */
_Static_assert((STM32ETH_TX_MAX_FRAG <= 0x3fffU) && (STM32ETH_TX_MAX_FRAG >= ((ETH_RX_BUF_SIZE + ETH_TX_MAX_FRAGS - 2U) / (ETH_TX_MAX_FRAGS - 1U))),
		"STM32ETH_TX_MAX_FRAG must be 220..0x3fff (TDES2.B1L)");
_Static_assert(ETH_TX_RING_SIZE > ETH_TX_MAX_FRAGS, "TX ring must hold a packet of ETH_TX_MAX_FRAGS - 1 fragments");

#define eth_printf(state, fmt, ...) printf("lwip: ETH%u: " fmt "\n", (unsigned int)(state)->devnum, ##__VA_ARGS__)

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


/* DMA descriptor (normal descriptor, read and write-back format share the layout) padded to a D-cache line */
typedef struct {
	uint32_t des[4];
	uint32_t skip[4]; /* not accessed by DMA (DSL) */
} eth_dma_desc_t;


typedef struct {
	int16_t port; /* < 0 indicates pin not present */
	uint8_t pin;
	int8_t afMode; /* < 0 indicates pin works as GPIO, use STM32_PIN_CONFIG_* */
} stm32_pin_setup_t;


#define eth_phymode_rmii 1

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

/* PHY management pins */
enum {
	eth_phy_mdc = 0U,
	eth_phy_mdio,
	eth_phy_pins,
};

#ifndef ETH1_RX_REFCLK_INTERNAL
#define ETH1_RX_REFCLK_INTERNAL 1
#endif

/* TODO: only RMII mode is supported for now */
#if defined(ETH1_MODE_RMII) && !defined(ETH1_MODE_RGMII) && !defined(ETH1_MODE_MII)
#define ETH1_PHYMODE eth_phymode_rmii
#else
#error "Only ETH1_MODE_RMII is supported"
#endif


static const struct {
	addr_t base;
	int pctls[N_PCTLS];
	unsigned int irq;                          /* ETH global interrupt */
	int risup;                                 /* RIF slave index (register access) */
	int rimc;                                  /* RIF master index (DMA access) */
	stm32_pin_setup_t pinoutPhy[eth_phy_pins]; /* Pinout for PHY management */
	stm32_pin_setup_t rmii[eth_rmii_pins];
	unsigned int phyMode;
	unsigned int macOtpFuses[2]; /* Low and high OTP fuse containing MAC address */
	int ipclkMode;               /* PCTL for selecting MII/RMII/RGMII mode */
	int ipclkClksel;             /* PCTL for selecting ck_ker_ethX clock */
	int ipclkRxRefclk;           /* PCTL for selecting internal/external RX reference clock */
	uint32_t hclkFreqHz;         /* eth_hclk, also called "CSR clock" in docs. */
	uint8_t clksel;              /* Selection of source for ck_ker_ethX */
	bool rxRefclkInternal;       /* RX reference clock source: external pin or internally generated */
} eth_setup[N_ETH] = {
#if defined(__CPU_STM32N6)
	{
		.base = 0x58036000UL, /* ETH1_BASE_S */
		.pctls = { pctl_eth1, pctl_eth1mac, pctl_eth1tx, pctl_eth1rx },
		.irq = eth1_irq, /* ETH1_IRQn (179) + 16 */
		.risup = pctl_risup_eth1,
		.rimc = pctl_rimc_eth1,
		.pinoutPhy = {
			[eth_phy_mdc] = { ETH1_MDC_PORT, ETH1_MDC_PIN, 11 },
			[eth_phy_mdio] = { ETH1_MDIO_PORT, ETH1_MDIO_PIN, 11 },
		},
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
		.phyMode = ETH1_PHYMODE,
		.macOtpFuses = { 169, 170 },
		.ipclkMode = pctl_ipclk_eth1sel,
		.ipclkClksel = pctl_ipclk_eth1clksel,
		.ipclkRxRefclk = pctl_ipclk_eth1refclksel,
		/*
		 * HCLK = IC2 (400 MHz) / HPRE (2) = 200 MHz, as configured by PLO
		 * (plo: hal/armv8m/stm32/n6/stm32n6.c:402,442).
		 * TODO: acquire from platform instead of hardcoding.
		 */
		.hclkFreqHz = 200U * 1000U * 1000U,
		.clksel = 0u, /* HCLK selected as ck_ker_eth1 */
		.rxRefclkInternal = (ETH1_RX_REFCLK_INTERNAL != 0),
	},
#endif
};


typedef struct {
	volatile uint32_t *base;

	struct netif *netif;

#define PRIV_RESOURCES(s) &(s)->lock, 3, ~0x03
	handle_t lock, txLock, cond; /* txLock: TX ring filling + tail pointer, TX reaping */

	size_t devnum;
	oid_t multidrvOid;
	int mdioBus; /* MDIO bus index registered by this device, < 0 if none */
	bool phyValid;
	atomic_bool linkUp; /* last link state reported by ephy (written only by ephy_init() and the IRQ thread) */
	atomic_uint linkChanges;
	eth_phy_state_t phy;

	/* DMA descriptor rings (cacheable memory from net_initRings()), valid if ringsValid */
	net_bufdesc_ring_t rings[2];
	bool ringsValid;
	bool txStarted;        /* TX path (MTL queue, DMA, MAC TX) started by eth_startTx() */
	bool rxStarted;        /* RX path (MTL queue, DMA, MAC RX) started by eth_startRx() */
	atomic_bool txStopped; /* DMA fatal bus error - nothing is transmitted or received until reset */

	/* ETH interrupt (eth_initDevice()) and IRQ thread (eth_netifInit()) */
	handle_t irqHandle;
	bool irqValid;
	atomic_uint irqCount;
	atomic_uint irqStatus; /* OR of DMAC0SR seen by the interrupt handler (debug) */

	/* RX packet in progress (IRQ thread only): length of its previous descriptors, error */
	size_t rxPktLen;
	bool rxPktBad;
	uint32_t rxLastRdes3;
	err_t (*input)(struct pbuf *p, struct netif *netif); /* lwIP input (tcpip_input), called by eth_netifInput() */

	/* RX statistics (IRQ thread only) */
	uint32_t rxPackets, rxBytes;
	uint32_t rxErrors;                                /* packets with RDES3.ES */
	uint32_t rxErrFlags;                              /* OR of RDES3 write-back error flags */
	uint32_t rxBadDesc;                               /* packets in more than one descriptor or context descriptors (not expected) */
	uint32_t rxInputDrop;                             /* packets lwIP couldn't queue (tcpip_input() failed) */
	uint32_t rxRbu;                                   /* DMACSR.RBU events (DMA ran out of descriptors) */
	uint32_t rxRefillLow;                             /* refills that left the ring not fully filled (no packet buffer memory) */
	uint32_t rxMtlOverflow, rxMtlMissed, rxDmaMissed; /* clear-on-read hardware counters, accumulated every poll */
	uint32_t rxDropCntWraps;                          /* reads with a counter overflow flag: the totals are lower bounds */

	/* Current packet (written under txLock): total length for TDES3.FL and the sum of its fragment lengths */
	size_t txPktLen;
	size_t txFragSum;

	/* TX statistics */
	atomic_uint txDropped;  /* not queued and not retryable: link down, TX stopped, no memory (ERR_IF, ERR_MEM) */
	atomic_uint txRingFull; /* not queued because the ring was full (ERR_BUF - the caller may retry) */
	uint32_t txPackets;     /* completed packets (last descriptor written back), under TX ring lock */
	uint32_t txErrors;      /* completed packets with TDES3.ES set, under TX ring lock */
	uint32_t txErrFlags;    /* OR of TDES3 write-back error flags [15:0], under TX ring lock */

	uint32_t irqStack[2048] __attribute__((aligned(16))); /* RX -> tcpip_input, lwIP output path (netif_set_link_up()) */
} eth_state_t;


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
	platformctl_t pctl = {
		.action = pctl_get,
		.type = pctl_otp,
		.otp = {
			.addr = word,
			.val = 0, /* Will be overwritten on success */
		},
	};

	CHECK(platformctl(&pctl));
	*out = pctl.otp.val;
	return 0;
}


/*
 * Configure RIF so that ETH1 registers are accessible from the (secure, unprivileged) lwip process
 * and the ETH1 bus master issues secure transactions (RISAF allows only secure accesses to SRAM).
 * NOTE: RISUP must not be set to privileged - user processes run unprivileged.
 */
static int eth_rifConfig(eth_state_t *state, size_t idx)
{
	platformctl_t pctl = {
		.action = pctl_set,
		.type = pctl_risup,
		.risup = {
			.index = eth_setup[idx].risup,
			.secure = 1,
			.privileged = 0, /* no change */
			.lock = 0,
		},
	};

	CHECK_MSG(platformctl(&pctl), state, "Couldn't configure RIF slave (RISUP): %s (%d)", strerror(-_ret), _ret);

	pctl = (platformctl_t) {
		.action = pctl_set,
		.type = pctl_rimc,
		.rimc = {
			.index = eth_setup[idx].rimc,
			.secure = 1,
			.privileged = 0, /* no change */
			.cid = 1,
		},
	};

	CHECK_MSG(platformctl(&pctl), state, "Couldn't configure RIF master (RIMC): %s (%d)", strerror(-_ret), _ret);

	eth_debug_printf(state, "RIF configured");
	return 0;
}


static int eth_reset(eth_state_t *state, size_t idx, time_t timeout)
{
	time_t now, when;

	eth_debug_printf(state, "Resetting device...");

	gettime(&now, NULL);
	when = now + timeout;

	/* trigger and wait for reset */
	state->base[eth_dmamr] |= ETH_DMAMR_SWR;
	__asm__ volatile("dsb" ::: "memory");
	for (;;) {
		if ((state->base[eth_dmamr] & ETH_DMAMR_SWR) == 0) {
			break;
		}

		usleep(1000);
		gettime(&now, NULL);
		if (now >= when) {
			eth_printf(state, "Couldn't reset device: timeout (DMAMR=0x%08x)", (unsigned int)state->base[eth_dmamr]);
			return -ETIMEDOUT;
		}
	}

	eth_debug_printf(state, "Reset done");

	/* 1 us tick counter: HCLK [MHz] - 1 */
	state->base[eth_mac1ustcr] = (eth_setup[idx].hclkFreqHz / (1000U * 1000U)) - 1U;

	return 0;
}


/* Static MAC configuration. Transmitter and receiver (MACCR.TE/RE) are left disabled. */
static void eth_macConfig(eth_state_t *state)
{
	uint32_t v;

	v = state->base[eth_maccr];
	v &= ~(
			ETH_MACCR_RE |
			ETH_MACCR_TE |
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

	/* Default link speed and duplex (RMII): 100 Mbps, full duplex - updated on link change */
	v |= ETH_MACCR_DM | ETH_MACCR_FES | ETH_MACCR_PS;

	v |= 0 << ETH_MACCR_PRELEN_SHIFT; /* 7 bytes of preamble */
	v |= 0 << ETH_MACCR_BL_SHIFT;     /* Back-off limited to 2^10 slot delays */
	/* Strip padding/CRC of length packets (ACS) and CRC of type packets (CST) */
	v |= ETH_ENABLE_RX_PAD_REMOVE ? (ETH_MACCR_ACS | ETH_MACCR_CST) : 0;
	/*
	 * RX checksum offload (as HAL): results go to RDES1 (IPHE/IPCE), not to RDES3.ES, and aren't used - lwIP checks the
	 * checksums itself. Packets with checksum errors are not dropped in hardware (MTLRXQ0OMR.DISTCPEF = 1, eth_startRx()).
	 */
	v |= ETH_MACCR_IPC;
	state->base[eth_maccr] = v;

	v = state->base[eth_macecr];
	v &= ~(ETH_MACECR_EIPG_MASK | ETH_MACECR_EIPGEN | ETH_MACECR_USP | ETH_MACECR_SPEN | ETH_MACECR_DCRCC | ETH_MACECR_GPSL_MASK);
	v |= (1560UL << ETH_MACECR_GPSL_SHIFT) & ETH_MACECR_GPSL_MASK; /* Giant packet size limit (not used unless ETH_MACCR_GPSLCE is set) */
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
	/*
	 * Pause time: maximum (0xffff pause quanta), zero-quanta pause enabled (DZPQ = 0) to resume the link partner early
	 * - as HAL (ZeroQuantaPause = ENABLE) and Linux stmmac. Previously PT = 0 (pause frames with zero pause time).
	 */
	v |= ETH_ENABLE_FLOW_CONTROL ? (ETH_MACQ0TXFCR_TFE | ETH_MACQ0TXFCR_PT_MASK) : 0;
	state->base[eth_macq0txfcr] = v;

	eth_debug_printf(state, "MAC configured, MACCR=0x%08x", (unsigned int)state->base[eth_maccr]);
}


static void eth_showCardId(eth_state_t *state)
{
	uint8_t *mac = (void *)&state->netif->hwaddr;
	eth_printf(state, "initialized, MAC=%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}


static int eth_mdioSetup(void *arg, unsigned max_khz, unsigned min_hold_ns, unsigned opt_preamble)
{
	eth_state_t *state = arg;
	size_t idx = state->devnum - 1U;
	uint32_t v = state->base[eth_macmdioar];
	v &= ~(0xfUL << 8); /* CR */

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
	for (i = 0; i < 8U; i++) {
		if ((eth_setup[idx].hclkFreqHz / options[i].divider) <= maxHz) {
			v |= (uint32_t)options[i].val << 8;
			break;
		}
	}

	if (i == 8U) {
		eth_printf(state, "Cannot find an appropriate divider for MDC clock (base freq %u)", (unsigned int)eth_setup[idx].hclkFreqHz);
		return -EIO;
	}

	/* Configuring hold time doesn't seem to be supported in hardware */
	(void)min_hold_ns;

	v &= ~ETH_MACMDIOAR_PSE;
	if (opt_preamble != 0U) {
		v |= ETH_MACMDIOAR_PSE; /* Suppress preamble (only 1 bit of preamble will be transmitted) */
	}

	state->base[eth_macmdioar] = v;
	eth_debug_printf(state, "MDC = %u Hz (CR=%u)", (unsigned int)(eth_setup[idx].hclkFreqHz / options[i].divider), (unsigned int)options[i].val);
	return 0;
}


static int eth_mdioWait(eth_state_t *state, time_t timeout)
{
	time_t now, when;

	gettime(&now, NULL);
	when = now + timeout;

	while ((state->base[eth_macmdioar] & ETH_MACMDIOAR_GB) != 0) {
		gettime(&now, NULL);
		if (now >= when) {
			return -ETIMEDOUT;
		}

		usleep(10);
	}

	return 0;
}


static uint16_t eth_mdioIO(eth_state_t *state, unsigned addr, unsigned reg, unsigned val, bool write)
{
	const char *opString = write ? "WRITE" : "READ";

#if MDIO_DEBUG
	eth_printf(state, "mdio: op %s, addr=0x%08x, reg=0x%08x, val=0x%04x", opString, addr, reg, val);
#endif

	/* Previous transaction might have timed out */
	if (eth_mdioWait(state, MDIO_TIMEOUT_US) < 0) {
		eth_printf(state, "WARN: MDIO %s: bus busy", opString);
		return 0xffffU;
	}

	uint32_t ar = state->base[eth_macmdioar];
	uint32_t dr = (val & 0xffffU);
	ar &= ~(ETH_MACMDIOAR_GOC | ETH_MACMDIOAR_RDA_MASK | ETH_MACMDIOAR_PA_MASK);
	ar |= write ? ETH_MACMDIOAR_GOC_WRITE : ETH_MACMDIOAR_GOC_READ;

	if ((addr & NETDEV_MDIO_CLAUSE45) != 0U) {
		/* clause 45 */
		ar |= ETH_MACMDIOAR_C45E;
		uint32_t device = addr & NETDEV_MDIO_A_MASK;
		uint32_t phy = (addr & NETDEV_MDIO_B_MASK) >> 8;
		ar |= (phy << ETH_MACMDIOAR_PA_SHIFT) & ETH_MACMDIOAR_PA_MASK;
		ar |= (device << ETH_MACMDIOAR_RDA_SHIFT) & ETH_MACMDIOAR_RDA_MASK;
		dr |= (reg & 0xffffU) << 16; /* MACMDIODR.RA */
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

	if (eth_mdioWait(state, MDIO_TIMEOUT_US) < 0) {
		eth_printf(state, "WARN: MDIO %s operation timeout (addr=0x%x, reg=0x%x)", opString, addr, reg);
		return 0xffffU;
	}

	return write ? 0U : (uint16_t)(state->base[eth_macmdiodr] & 0xffffU);
}


static uint16_t eth_mdioRead(void *arg, unsigned addr, uint16_t reg)
{
	eth_state_t *state = arg;
	return eth_mdioIO(state, addr, reg, 0, false);
}


static void eth_mdioWrite(void *arg, unsigned addr, uint16_t reg, uint16_t val)
{
	eth_state_t *state = arg;
	(void)eth_mdioIO(state, addr, reg, val, true);
}


static const mdio_bus_ops_t eth_mdio_ops = {
	eth_mdioSetup,
	eth_mdioRead,
	eth_mdioWrite,
};


static void eth_setLinkState(void *arg, int state)
{
	struct netif *netif = arg;
	eth_state_t *priv = netif->state;
	int speed, duplex = 0;

	(void)atomic_fetch_add(&priv->linkChanges, 1U);

	if (state == 0) {
		/* stop queueing TX frames first (linkoutput drops them while the link is down) */
		atomic_store(&priv->linkUp, false);
		eth_debug_printf(priv, "link down");
		netif_set_link_down(netif);
		return;
	}

	speed = ephy_linkSpeed(&priv->phy, &duplex);
	if (speed == 0) {
		eth_printf(priv, "WARN: link up, but speed unknown - MAC configuration unchanged");
	}
	else {
		uint32_t old = priv->base[eth_maccr];
		uint32_t v = old & ~(ETH_MACCR_DM | ETH_MACCR_FES | ETH_MACCR_PS);
		v |= (duplex != 0) ? ETH_MACCR_DM : 0U;
		if (speed != 1000) {
			v |= ETH_MACCR_PS;
			v |= (speed == 100) ? ETH_MACCR_FES : 0U;
		}

		if (v != old) {
			/* Change speed/duplex with transmitter and receiver disabled, restore them only if they were enabled */
			uint32_t trx = old & (ETH_MACCR_TE | ETH_MACCR_RE);
			if (trx != 0U) {
				priv->base[eth_maccr] = old & ~trx;
			}
			priv->base[eth_maccr] = v & ~trx;
			if (trx != 0U) {
				priv->base[eth_maccr] = v;
			}
		}
	}

	/* accept TX frames only after the MAC speed/duplex matches the link */
	atomic_store(&priv->linkUp, true);
	eth_debug_printf(priv, "link up %dMbps/%s, MACCR=0x%08x", speed, (duplex != 0) ? "full" : "half", (unsigned int)priv->base[eth_maccr]);
	netif_set_link_up(netif);
}


static const char *eth_media(struct netif *netif)
{
	int full_duplex = 0, speed;
	eth_state_t *state = netif->state;

	if (!state->phyValid) {
		return "unspecified";
	}

	speed = ephy_linkSpeed(&state->phy, &full_duplex);

	switch (speed) {
		case 0:
			return "unspecified";
		case 10:
			return (full_duplex != 0) ? "10Mbps/full-duplex" : "10Mbps/half-duplex";
		case 100:
			return (full_duplex != 0) ? "100Mbps/full-duplex" : "100Mbps/half-duplex";
		case 1000:
			return (full_duplex != 0) ? "1000Mbps/full-duplex" : "1000Mbps/half-duplex";
		default:
			return "unrecognized";
	}
}


static const size_t eth_ringSizes[] = {
	[ETH_RING_RX] = ETH_RX_RING_SIZE,
	[ETH_RING_TX] = ETH_TX_RING_SIZE,
};


static void eth_cleanDCache(volatile void *addr, size_t sz)
{
	platformctl_t pctl = {
		.action = pctl_set,
		.type = pctl_cleanDCache,
		.opDCache = {
			.addr = (void *)addr,
			.sz = sz,
		},
	};

	(void)platformctl(&pctl);
}


static void eth_invalDCache(volatile void *addr, size_t sz)
{
	platformctl_t pctl = {
		.action = pctl_set,
		.type = pctl_invalDCache,
		.opDCache = {
			.addr = (void *)addr,
			.sz = sz,
		},
	};

	(void)platformctl(&pctl);
}


static inline volatile eth_dma_desc_t *eth_desc(const net_bufdesc_ring_t *ring, size_t i)
{
	return (volatile eth_dma_desc_t *)ring->ring + i;
}


static inline addr_t eth_descPhys(const net_bufdesc_ring_t *ring, size_t i)
{
	return ring->phys + (i * sizeof(eth_dma_desc_t));
}


/*
 * Prepare a TX normal descriptor and pass it to DMA (OWN is set last, then the cache line is cleaned).
 * The caller writes the tail pointer (after a dsb) to start DMA on it.
 * FL = pktLen (total length of the packet) in every descriptor of the packet - as HAL (stm32n6xx_hal_eth.c:3460, 3569)
 * and Linux stmmac. IOC is set on the last descriptor of a packet, so that DMACxSR.TI reports its completion.
 * CPC = 0 (insert CRC and pad), CIC = 0 (no checksum insertion).
 * NOTE: invalidating the line of a descriptor while it is being filled would discard the CPU writes - descriptor lines
 * are invalidated only under the TX ring lock or txLock (net_transmitPacket() fills them under both).
 */
static inline void eth_txDescFill(volatile eth_dma_desc_t *desc, addr_t pa, size_t len, size_t pktLen, bool first, bool last)
{
	uint32_t tdes3 = (pktLen & ETH_TDES3_FL_MASK) | (0UL << ETH_TDES3_CPC_SHIFT);

	tdes3 |= first ? ETH_TDES3_FD : 0U;
	tdes3 |= last ? ETH_TDES3_LD : 0U;

	desc->des[0] = (uint32_t)pa;
	desc->des[1] = 0U;
	desc->des[2] = (len & ETH_TDES2_B1L_MASK) | (last ? ETH_TDES2_IOC : 0U);
	desc->des[3] = tdes3;

	/* descriptor contents must be visible to DMA before it gets the ownership */
	__asm__ volatile("dmb" ::: "memory");
	desc->des[3] = tdes3 | ETH_TDES3_OWN;
	eth_cleanDCache(desc, sizeof(*desc));
}


/* Returns true if DMA has released the TX descriptor */
static inline bool eth_txDescDone(volatile eth_dma_desc_t *desc)
{
	/* the descriptor may have been written back by DMA */
	eth_invalDCache(desc, sizeof(*desc));
	if ((desc->des[3] & ETH_TDES3_OWN) != 0U) {
		return false;
	}

	/* don't read the rest of the descriptor (write-back) before OWN */
	__asm__ volatile("dmb" ::: "memory");
	return true;
}


static inline eth_state_t *eth_txRingState(const net_bufdesc_ring_t *ring)
{
	return (eth_state_t *)((uintptr_t)ring - offsetof(eth_state_t, rings[ETH_RING_TX]));
}


/*
 * bdring fillTxDesc callback - called by net_transmitPacket() (from eth_netifOutput(), under txLock and the ring lock)
 * for each fragment of a packet, from the last one to the first one.
 * The total packet length for TDES3.FL is taken from the pbuf in eth_netifOutput() (state->txPktLen),
 * so it doesn't depend on the fill order.
 */
static void eth_fillTxDesc(const net_bufdesc_ring_t *ring, size_t i, addr_t pa, size_t sz, unsigned seg)
{
	eth_state_t *state = eth_txRingState(ring);

	/* frame data written by the CPU (pbuf copy) must reach memory before DMA reads it; NOMMU: pa == va */
	eth_cleanDCache((void *)pa, sz);

	eth_txDescFill(eth_desc(ring, i), pa, sz, state->txPktLen, (seg & BDRING_SEG_FIRST) != 0U, (seg & BDRING_SEG_LAST) != 0U);
	state->txFragSum += sz;
}


/* bdring nextTxDone callback - called by net_reapTxFinished() under the ring lock */
static bool eth_nextTxDone(const net_bufdesc_ring_t *ring, size_t i)
{
	eth_state_t *state = eth_txRingState(ring);
	volatile eth_dma_desc_t *desc = eth_desc(ring, i);
	uint32_t tdes3;

	if (!eth_txDescDone(desc)) {
		return false;
	}

	/* write-back format: status is valid in the last descriptor of a packet */
	tdes3 = desc->des[3];
	if ((tdes3 & ETH_TDES3_LD) != 0U) {
		state->txPackets++;
		if ((tdes3 & ETH_TDES3_WB_ES) != 0U) {
			state->txErrors++;
			state->txErrFlags |= tdes3 & ETH_TDES3_WB_ERR_MASK;
		}
	}

	return true;
}


static inline eth_state_t *eth_rxRingState(const net_bufdesc_ring_t *ring)
{
	return (eth_state_t *)((uintptr_t)ring - offsetof(eth_state_t, rings[ETH_RING_RX]));
}


/*
 * bdring fillRxDesc callback - called by net_refillRx() (IRQ thread or init, under the ring lock).
 * The buffer is invalidated, not cleaned: a reused packet buffer may hold dirty lines written by lwIP, and they must
 * not be written back over data the DMA stores. Packet buffers are page-aligned, so no cache line is shared.
 */
static void eth_fillRxDesc(const net_bufdesc_ring_t *ring, size_t i, addr_t pa, size_t sz, unsigned seg)
{
	volatile eth_dma_desc_t *desc = eth_desc(ring, i);
	uint32_t rdes3 = ETH_RDES3_BUF1V | ETH_RDES3_IOC;

	(void)seg;

	/* NOMMU: pa == va */
	eth_invalDCache((void *)pa, sz);

	desc->des[0] = (uint32_t)pa;
	desc->des[1] = 0U;
	desc->des[2] = 0U;
	desc->des[3] = rdes3;

	/* descriptor contents must be visible to DMA before it gets the ownership */
	__asm__ volatile("dmb" ::: "memory");
	desc->des[3] = rdes3 | ETH_RDES3_OWN;
	eth_cleanDCache(desc, sizeof(*desc));
}


/*
 * bdring nextRxBufferSize callback - called by net_receivePackets() (IRQ thread, under the ring lock).
 * Returns the number of bytes in the buffer of descriptor i, 0 if the DMA still owns it.
 * A completed descriptor never returns 0 (that would stop net_receivePackets()): packets with errors, in more than one
 * descriptor (giant packets, > RBSZ = 1536 B) or context descriptors are marked bad and dropped by eth_netifInput().
 */
static size_t eth_nextRxBufferSize(const net_bufdesc_ring_t *ring, size_t i)
{
	eth_state_t *state = eth_rxRingState(ring);
	volatile eth_dma_desc_t *desc = eth_desc(ring, i);
	struct pbuf *p = ring->bufp[i];
	uint32_t rdes3;
	size_t len, pl;

	/* the descriptor may have been written back by DMA */
	eth_invalDCache(desc, sizeof(*desc));
	rdes3 = desc->des[3];
	if ((rdes3 & ETH_RDES3_WB_OWN) != 0U) {
		return 0;
	}

	/* don't read the rest of the descriptor (write-back) before OWN */
	__asm__ volatile("dmb" ::: "memory");
	state->rxLastRdes3 = rdes3;

	if ((rdes3 & ETH_RDES3_WB_CTXT) != 0U) {
		/* context descriptor (timestamps are not enabled): no packet data, drop it as a packet on its own */
		state->rxPktLen = 0;
		state->rxPktBad = true;
		return 1;
	}

	if ((rdes3 & ETH_RDES3_WB_FD) != 0U) {
		state->rxPktLen = 0;
		state->rxPktBad = false;
	}

	if ((rdes3 & ETH_RDES3_WB_LD) == 0U) {
		/* not the last descriptor of the packet: the buffer is full */
		len = ETH_RX_BUF_SIZE;
		state->rxPktBad = true;
	}
	else {
		/* PL = length of the whole packet (CRC stripped: MACCR.ACS/CST) */
		pl = rdes3 & ETH_RDES3_WB_PL_MASK;
		len = (pl > state->rxPktLen) ? (pl - state->rxPktLen) : 0U;
		if ((rdes3 & (ETH_RDES3_WB_FD | ETH_RDES3_WB_ES)) != ETH_RDES3_WB_FD) {
			state->rxPktBad = true;
		}
		if ((len == 0U) || (len > ETH_RX_BUF_SIZE)) {
			/* inconsistent length - keep the buffer bounds */
			state->rxPktBad = true;
			len = (len == 0U) ? 1U : ETH_RX_BUF_SIZE;
		}
	}
	state->rxPktLen += len;

	/* data written by the DMA: drop stale cache lines (speculative reads) before the CPU reads the buffer */
	eth_invalDCache(p->payload, len);

	return len;
}


/*
 * bdring pktRxFinished callback: every descriptor is passed up as a packet of its own (a single pbuf).
 * A packet in more than one descriptor (> RBSZ, e.g. a giant packet) is marked bad by eth_nextRxBufferSize() in every
 * descriptor and dropped piece by piece. Chaining the pieces in net_receivePackets() would leak buffers:
 * LWIP_HOOK_ETH_INPUT gets and frees only the last pbuf of the chain, and a chain left unfinished when the DMA still
 * owns the next descriptor is dropped without being freed.
 */
static bool eth_pktRxFinished(const net_bufdesc_ring_t *ring, size_t i)
{
	(void)ring;
	(void)i;

	return true;
}


/* Descriptor rings: RX and TX callbacks */
static const net_bufdesc_ops_t eth_ringOps = {
	.nextRxBufferSize = eth_nextRxBufferSize,
	.pktRxFinished = eth_pktRxFinished,
	.fillRxDesc = eth_fillRxDesc,
	.nextTxDone = eth_nextTxDone,
	.fillTxDesc = eth_fillTxDesc,
	.desc_size = ETH_DESC_SIZE,
	.ring_alignment = ETH_RING_ALIGN,
	.pkt_buf_sz = ETH_RX_BUF_SIZE,
	.max_tx_frag = STM32ETH_TX_MAX_FRAG,
};

_Static_assert(sizeof(eth_dma_desc_t) == ETH_DESC_SIZE, "descriptor stride must match DMACxCR.DSL");
_Static_assert((ETH_DESC_SIZE - 16U) == (ETH_DESC_DSL * 8U), "DSL in 8-byte units (64-bit DMA bus)");


/* Wait until (reg & mask) == val. Returns false on timeout. */
static bool eth_waitReg(eth_state_t *state, unsigned int reg, uint32_t mask, uint32_t val, time_t timeout)
{
	time_t start, now;

	gettime(&start, NULL);
	for (;;) {
		if ((state->base[reg] & mask) == val) {
			return true;
		}

		gettime(&now, NULL);
		if ((now - start) >= timeout) {
			return false;
		}
		usleep(100);
	}
}


/* Log TX DMA/MTL/MAC status registers and the descriptors at the ring tail (next to reap) and head (next to fill) */
static void eth_logTxRegs(eth_state_t *state, const char *when)
{
	const net_bufdesc_ring_t *tx = &state->rings[ETH_RING_TX];
	volatile eth_dma_desc_t *desc;
	uint32_t tdes[2][4];
	unsigned int head, tail;

	eth_printf(state, "TX %s: DMAC0SR=0x%08x DMADSR=0x%08x DMAISR=0x%08x DMAC0TXCR=0x%08x DMAC0CATXDR=0x%08x DMAC0CATXBR=0x%08x",
			when, (unsigned int)state->base[eth_dmac0sr], (unsigned int)state->base[eth_dmadsr], (unsigned int)state->base[eth_dmaisr],
			(unsigned int)state->base[eth_dmac0txcr], (unsigned int)state->base[eth_dmac0catxdr], (unsigned int)state->base[eth_dmac0catxbr]);
	eth_printf(state, "TX %s: DMAC0TXDLAR=0x%08x DMAC0TXDTPR=0x%08x DMAC0TXRLR=%u MTLTXQ0OMR=0x%08x MTLTXQ0DR=0x%08x MTLTXQ0UR=0x%08x MACCR=0x%08x",
			when, (unsigned int)state->base[eth_dmac0txdlar], (unsigned int)state->base[eth_dmac0txdtpr], (unsigned int)state->base[eth_dmac0txrlr],
			(unsigned int)state->base[eth_mtltxq0omr], (unsigned int)state->base[eth_mtltxq0dr], (unsigned int)state->base[eth_mtltxq0ur],
			(unsigned int)state->base[eth_maccr]);

	if (!state->ringsValid) {
		return;
	}

	/* descriptor lines are invalidated - not while one is being filled */
	mutexLock(state->txLock);
	head = atomic_load(&tx->head);
	tail = atomic_load(&tx->tail);
	for (size_t k = 0; k < 2U; k++) {
		desc = eth_desc(tx, (k == 0U) ? tail : head);
		eth_invalDCache(desc, sizeof(*desc));
		for (size_t j = 0; j < 4U; j++) {
			tdes[k][j] = desc->des[j];
		}
	}
	mutexUnlock(state->txLock);

	eth_printf(state, "TX %s: ring tail=%u (0x%08x) TDES=%08x %08x %08x %08x, head=%u (0x%08x) TDES=%08x %08x %08x %08x",
			when, tail, (unsigned int)eth_descPhys(tx, tail),
			(unsigned int)tdes[0][0], (unsigned int)tdes[0][1], (unsigned int)tdes[0][2], (unsigned int)tdes[0][3],
			head, (unsigned int)eth_descPhys(tx, head),
			(unsigned int)tdes[1][0], (unsigned int)tdes[1][1], (unsigned int)tdes[1][2], (unsigned int)tdes[1][3]);
}


/*
 * Start the TX path (HAL: ETHEx_SetMTLConfig() + HAL_ETH_Start() TX part): MTL TX queue 0 (2048 B, store and forward,
 * enabled), flush it, TX DMA (suspended: tail pointer = ring base) and MAC TX (MACCR.TE).
 * The TX path is started once at init and runs regardless of the link state: linkoutput drops frames while the link
 * is down and eth_setLinkState() disables TE only for the time of a speed/duplex change.
 */
static void eth_startTx(eth_state_t *state)
{
	uint32_t v = state->base[eth_mtltxq0omr];

	v &= ~(ETH_MTLTXQOMR_TQS_MASK | ETH_MTLTXQOMR_TXQEN_MASK | ETH_MTLTXQOMR_TTC_MASK | ETH_MTLTXQOMR_TSF | ETH_MTLTXQOMR_FTQ);
	v |= (ETH_TX_QUEUE_TQS << ETH_MTLTXQOMR_TQS_SHIFT) | ETH_MTLTXQOMR_TXQEN_EN | ETH_MTLTXQOMR_TSF;
	state->base[eth_mtltxq0omr] = v;

	state->base[eth_mtltxq0omr] = v | ETH_MTLTXQOMR_FTQ;
	if (!eth_waitReg(state, eth_mtltxq0omr, ETH_MTLTXQOMR_FTQ, 0U, ETH_TX_STOP_TIMEOUT_US)) {
		eth_printf(state, "WARN: MTL TX queue not flushed (MTLTXQ0OMR=0x%08x)", (unsigned int)state->base[eth_mtltxq0omr]);
	}

	state->base[eth_dmac0txcr] |= ETH_DMACTXCR_ST;
	state->base[eth_dmac0sr] = ETH_DMACSR_TPS;
	state->base[eth_maccr] |= ETH_MACCR_TE;
	__asm__ volatile("dsb" ::: "memory");
	state->txStarted = true;

	eth_debug_printf(state, "TX started: MTLTXQ0OMR=0x%08x DMAC0TXCR=0x%08x DMAC0TXDTPR=0x%08x MACCR=0x%08x",
			(unsigned int)state->base[eth_mtltxq0omr], (unsigned int)state->base[eth_dmac0txcr],
			(unsigned int)state->base[eth_dmac0txdtpr], (unsigned int)state->base[eth_maccr]);
}


/*
 * Stop the TX path (HAL_ETH_Stop() order): TX DMA, wait for the TX process to stop, flush MTL TX queue 0, MAC TX,
 * disable the queue. Returns false if DMA may still access the descriptors/buffers (they must not be freed then).
 */
static bool eth_stopTx(eth_state_t *state)
{
	bool stopped, flushed;

	if (!state->txStarted) {
		return true;
	}

	state->base[eth_dmac0txcr] &= ~ETH_DMACTXCR_ST;
	stopped = eth_waitReg(state, eth_dmadsr, ETH_DMADSR_TPS0_MASK, ETH_DMADSR_TPS_STOPPED << ETH_DMADSR_TPS0_SHIFT, ETH_TX_STOP_TIMEOUT_US);

	state->base[eth_mtltxq0omr] |= ETH_MTLTXQOMR_FTQ;
	flushed = eth_waitReg(state, eth_mtltxq0omr, ETH_MTLTXQOMR_FTQ, 0U, ETH_TX_STOP_TIMEOUT_US);

	state->base[eth_maccr] &= ~ETH_MACCR_TE;
	state->base[eth_mtltxq0omr] &= ~(ETH_MTLTXQOMR_TXQEN_MASK | ETH_MTLTXQOMR_FTQ);
	state->txStarted = false;

	if (!stopped || !flushed) {
		eth_printf(state, "WARN: TX stop:%s%s", !stopped ? " DMA not stopped" : "", !flushed ? " MTL queue not flushed" : "");
		eth_logTxRegs(state, "stop");
	}

	return stopped;
}


/* Free pbufs of completed TX descriptors */
static void eth_txReap(eth_state_t *state)
{
	mutexLock(state->txLock);
	(void)net_reapTxFinished(&state->rings[ETH_RING_TX]);
	mutexUnlock(state->txLock);
}


/*
 * Number of TX descriptors net_transmitPacket() needs for p: a regular pbuf is copied into one DMA buffer
 * (net_makeDMAPbuf()), a custom (DMA) pbuf chain is referenced and split into fragments of at most max_tx_frag.
 */
static size_t eth_txFragsNeeded(const struct pbuf *p)
{
	size_t n = 0, left = p->tot_len;

	if ((p->flags & PBUF_FLAG_IS_CUSTOM) == 0U) {
		return (left + STM32ETH_TX_MAX_FRAG - 1U) / STM32ETH_TX_MAX_FRAG;
	}

	for (; (p != NULL) && (left != 0U); p = p->next) {
		n += (p->len == 0U) ? 1U : ((p->len + STM32ETH_TX_MAX_FRAG - 1U) / STM32ETH_TX_MAX_FRAG);
		left -= (p->len < left) ? p->len : left;
	}

	return n;
}


/*
 * netif linkoutput. The pbuf stays owned by the caller (net_makeDMAPbuf() copies or references it).
 * Returns: ERR_OK - queued, ERR_IF - link down or TX stopped (fatal bus error), ERR_BUF - TX ring full,
 * ERR_MEM - no DMA buffer memory or too many fragments. imx-enet/greth return ERR_BUF for every failure and don't
 * check the link state (their MAC drops frames without a link).
 */
static err_t eth_netifOutput(struct netif *netif, struct pbuf *p)
{
	eth_state_t *state = netif->state;
	net_bufdesc_ring_t *tx = &state->rings[ETH_RING_TX];
	size_t nfree, nfrags, nf;
	err_t err;

	if (!atomic_load(&state->linkUp) || atomic_load(&state->txStopped) || !state->txStarted) {
		(void)atomic_fetch_add(&state->txDropped, 1U);
		return ERR_IF;
	}

	mutexLock(state->txLock);

	(void)net_reapTxFinished(tx);

	/* bdring: a packet of n fragments needs n < min(free entries, MAX_TX_FRAGMENTS) */
	nfree = (atomic_load(&tx->tail) - atomic_load(&tx->head) - 1U) & tx->last;
	nfrags = eth_txFragsNeeded(p);
	if ((nfrags >= ETH_TX_MAX_FRAGS) || (p->tot_len > ETH_TDES3_FL_MASK)) {
		err = ERR_MEM;
	}
	else if (nfrags >= nfree) {
		(void)atomic_fetch_add(&state->txRingFull, 1U);
		err = ERR_BUF;
	}
	else {
		state->txPktLen = p->tot_len;
		state->txFragSum = 0;
		nf = net_transmitPacket(tx, p);
		if (nf != 0U) {
			/* descriptors (and buffers) are cleaned - make sure it completed before DMA is started on them */
			__asm__ volatile("dsb" ::: "memory");
			state->base[eth_dmac0txdtpr] = (uint32_t)eth_descPhys(tx, atomic_load(&tx->head));
			err = ERR_OK;

			if (state->txFragSum != state->txPktLen) {
				eth_printf(state, "WARN: TX fragments %u B != packet %u B", (unsigned int)state->txFragSum, (unsigned int)state->txPktLen);
			}
		}
		else {
			err = ERR_MEM;
		}
	}

	mutexUnlock(state->txLock);

	/* ERR_BUF is counted as ring-full only: the caller may retry */
	if ((err != ERR_OK) && (err != ERR_BUF)) {
		(void)atomic_fetch_add(&state->txDropped, 1U);
	}

	return err;
}


/* Log RX DMA/MTL/MAC registers and the descriptors at the ring head (next to read) and tail (next to fill) */
static void eth_logRxRegs(eth_state_t *state, const char *when)
{
	const net_bufdesc_ring_t *rx = &state->rings[ETH_RING_RX];
	volatile eth_dma_desc_t *desc;
	uint32_t rdes[2][4];
	unsigned int head, tail;

	eth_printf(state, "RX %s: DMAC0SR=0x%08x DMADSR=0x%08x DMAC0RXCR=0x%08x DMAC0CARXDR=0x%08x DMAC0CARXBR=0x%08x DMAC0IER=0x%08x",
			when, (unsigned int)state->base[eth_dmac0sr], (unsigned int)state->base[eth_dmadsr], (unsigned int)state->base[eth_dmac0rxcr],
			(unsigned int)state->base[eth_dmac0carxdr], (unsigned int)state->base[eth_dmac0carxbr], (unsigned int)state->base[eth_dmac0ier]);
	eth_printf(state, "RX %s: DMAC0RXDLAR=0x%08x DMAC0RXDTPR=0x%08x DMAC0RXRLR=%u MTLRXQ0OMR=0x%08x MTLRXQ0DR=0x%08x MACRXQC0R=0x%08x MACCR=0x%08x",
			when, (unsigned int)state->base[eth_dmac0rxdlar], (unsigned int)state->base[eth_dmac0rxdtpr], (unsigned int)state->base[eth_dmac0rxrlr],
			(unsigned int)state->base[eth_mtlrxq0omr], (unsigned int)state->base[eth_mtlrxq0dr], (unsigned int)state->base[eth_macrxqc0r],
			(unsigned int)state->base[eth_maccr]);

	if (!state->ringsValid) {
		return;
	}

	/* called from the IRQ thread or after RX was stopped - nobody fills RX descriptors concurrently */
	head = atomic_load(&rx->head);
	tail = atomic_load(&rx->tail);
	for (size_t k = 0; k < 2U; k++) {
		desc = eth_desc(rx, (k == 0U) ? head : tail);
		eth_invalDCache(desc, sizeof(*desc));
		for (size_t j = 0; j < 4U; j++) {
			rdes[k][j] = desc->des[j];
		}
	}

	eth_printf(state, "RX %s: ring head=%u (0x%08x) RDES=%08x %08x %08x %08x, tail=%u (0x%08x) RDES=%08x %08x %08x %08x",
			when, head, (unsigned int)eth_descPhys(rx, head),
			(unsigned int)rdes[0][0], (unsigned int)rdes[0][1], (unsigned int)rdes[0][2], (unsigned int)rdes[0][3],
			tail, (unsigned int)eth_descPhys(rx, tail),
			(unsigned int)rdes[1][0], (unsigned int)rdes[1][1], (unsigned int)rdes[1][2], (unsigned int)rdes[1][3]);
}


/*
 * RX tail pointer = descriptor after the last one passed to DMA (bdring ring->tail, the next one to fill; Linux stmmac).
 * The DMA uses descriptors up to the tail pointer and suspends there (RBU) - bdring always keeps that one unfilled.
 * HAL writes the address of the last filled descriptor instead, which leaves that descriptor unused until the next refill.
 */
static void eth_rxKick(eth_state_t *state)
{
	const net_bufdesc_ring_t *rx = &state->rings[ETH_RING_RX];

	/* descriptors are cleaned (syscall with dsb) - order the tail pointer write after them anyway */
	__asm__ volatile("dsb" ::: "memory");
	state->base[eth_dmac0rxdtpr] = (uint32_t)eth_descPhys(rx, atomic_load(&rx->tail));
}


/*
 * Start the RX path (HAL: ETHEx_SetMTLConfig() RX part + HAL_ETH_Start() RX part), after the TX path:
 * fill the RX ring, MTL RX queue 0 (4096 B, store and forward), MAC RX queue 0, RX DMA, MAC RX (MACCR.RE).
 * Not fallible: if packet buffers are short, the IRQ thread refills the ring later.
 */
static void eth_startRx(eth_state_t *state)
{
	net_bufdesc_ring_t *rx = &state->rings[ETH_RING_RX];
	uint32_t v;

	/* MMC counter interrupts don't depend on MACIER: mask them (HAL_ETH_Init()), clear pending ones (cleared on read) */
	state->base[eth_mmc_rx_interrupt_mask] |= ETH_MMCRIMR_ALL;
	state->base[eth_mmc_tx_interrupt_mask] |= ETH_MMCTIMR_ALL;
	(void)state->base[eth_mmc_rx_interrupt];
	(void)state->base[eth_mmc_tx_interrupt];

	/* each descriptor is cleaned from D-cache by eth_fillRxDesc() */
	(void)net_refillRx(rx);

	/*
	 * MTL RX queue 0: whole RX FIFO, store and forward, error and undersized packets dropped (FEP = FUP = 0).
	 * DISTCPEF = 1: unlike HAL, packets with TCP/IP checksum errors (MACCR.IPC) are not dropped in the MTL - lwIP checks
	 * the checksums itself and counts the errors. No hardware flow control (EHFC = 0).
	 */
	v = state->base[eth_mtlrxq0omr];
	v &= ~(ETH_MTLRXQOMR_RQS_MASK | ETH_MTLRXQOMR_RFD_MASK | ETH_MTLRXQOMR_RFA_MASK | ETH_MTLRXQOMR_EHFC | ETH_MTLRXQOMR_DISTCPEF |
			ETH_MTLRXQOMR_RSF | ETH_MTLRXQOMR_FEP | ETH_MTLRXQOMR_FUP | ETH_MTLRXQOMR_RTC_MASK);
	v |= (ETH_RX_QUEUE_RQS << ETH_MTLRXQOMR_RQS_SHIFT) | ETH_MTLRXQOMR_RSF | ETH_MTLRXQOMR_DISTCPEF;
	state->base[eth_mtlrxq0omr] = v;

	v = state->base[eth_macrxqc0r];
	v &= ~ETH_MACRXQC0R_RXQ0EN_MASK;
	v |= ETH_MACRXQC0R_RXQ0EN_GT;
	state->base[eth_macrxqc0r] = v;

	state->base[eth_dmac0sr] = ETH_DMACSR_RPS | ETH_DMACSR_RBU;
	eth_rxKick(state);
	state->base[eth_dmac0rxcr] |= ETH_DMACRXCR_SR;
	state->base[eth_maccr] |= ETH_MACCR_RE;
	__asm__ volatile("dsb" ::: "memory");
	state->rxStarted = true;

	eth_debug_printf(state, "RX started: %u buffers, MTLRXQ0OMR=0x%08x MACRXQC0R=0x%08x DMAC0RXCR=0x%08x DMAC0RXDTPR=0x%08x MACCR=0x%08x MACPFR=0x%08x",
			(unsigned int)((atomic_load(&rx->tail) - atomic_load(&rx->head)) & rx->last),
			(unsigned int)state->base[eth_mtlrxq0omr], (unsigned int)state->base[eth_macrxqc0r], (unsigned int)state->base[eth_dmac0rxcr],
			(unsigned int)state->base[eth_dmac0rxdtpr], (unsigned int)state->base[eth_maccr], (unsigned int)state->base[eth_macpfr]);
}


/*
 * Stop the RX path: MAC RX first (no new packet enters the MTL), RX DMA, wait for the RX process to stop, MAC RX queue.
 * Returns false if DMA may still write to the RX buffers (they must not be freed then).
 */
static bool eth_stopRx(eth_state_t *state)
{
	bool stopped;

	if (!state->rxStarted) {
		return true;
	}

	state->base[eth_maccr] &= ~ETH_MACCR_RE;
	state->base[eth_dmac0rxcr] &= ~ETH_DMACRXCR_SR;
	stopped = eth_waitReg(state, eth_dmadsr, ETH_DMADSR_RPS0_MASK, ETH_DMADSR_RPS_STOPPED << ETH_DMADSR_RPS0_SHIFT, ETH_RX_STOP_TIMEOUT_US);
	state->base[eth_macrxqc0r] &= ~ETH_MACRXQC0R_RXQ0EN_MASK;
	state->rxStarted = false;

	if (!stopped) {
		eth_printf(state, "WARN: RX stop: DMA not stopped");
		eth_logRxRegs(state, "stop");
	}

	return stopped;
}


/*
 * netif->input of this interface (lwIP's input function, tcpip_input, is called from here):
 * called by net_receivePackets() in the IRQ thread right after the descriptor of the packet was read, so
 * state->rxPktBad / rxLastRdes3 describe this packet. Bad packets are dropped and counted.
 * The pbuf is always consumed: bdring ignores the return value, so a packet lwIP couldn't queue is freed here.
 */
static err_t eth_netifInput(struct pbuf *p, struct netif *netif)
{
	eth_state_t *state = netif->state;
	uint32_t rdes3 = state->rxLastRdes3;

	if (state->rxPktBad) {
		state->rxPktBad = false;
		if ((rdes3 & ETH_RDES3_WB_ES) != 0U) {
			state->rxErrors++;
			state->rxErrFlags |= rdes3 & ETH_RDES3_WB_ERR_MASK;
		}
		else {
			state->rxBadDesc++;
		}
		if ((state->rxErrors + state->rxBadDesc) == 1U) {
			eth_debug_printf(state, "RX: dropped bad packet, RDES3=0x%08x", (unsigned int)rdes3);
		}
		pbuf_free(p);
		return ERR_OK;
	}

	state->rxPackets++;
	state->rxBytes += p->tot_len;

	if (state->input(p, netif) != ERR_OK) {
		state->rxInputDrop++;
		pbuf_free(p);
	}

	return ERR_OK;
}


/* IRQ thread: pass received packets to lwIP, refill the ring, move the tail pointer (resumes a suspended RX DMA) */
static void eth_rxProcess(eth_state_t *state)
{
	net_bufdesc_ring_t *rx = &state->rings[ETH_RING_RX];

	if (!state->rxStarted) {
		return;
	}

	(void)net_receivePackets(rx, state->netif);
	/*
	 * Move the tail pointer only when descriptors were added: without new descriptors a suspended RX DMA would find
	 * none again and raise RBU again (interrupt storm while packet buffers are exhausted); the refill is retried at
	 * least once per LINK_POLL_INTERVAL_US.
	 */
	if (net_refillRx(rx) != 0U) {
		eth_rxKick(state);
	}
	if (net_rxFullyFilled(rx) == 0) {
		state->rxRefillLow++;
	}
}


/*
 * ETH interrupt handler (kernel context - no syscalls): mask the DMA channel 0 interrupts and wake the IRQ thread,
 * which clears the status and unmasks them. DMAC0SR is only read (FBE is handled by the thread, the status stays set).
 */
static int eth_irqHandler(unsigned int n, void *arg)
{
	eth_state_t *state = arg;

	(void)n;

	state->base[eth_dmac0ier] = 0U;
	(void)atomic_fetch_or(&state->irqStatus, state->base[eth_dmac0sr]);
	atomic_fetch_add(&state->irqCount, 1U);

	return 0;
}


/* IRQ thread: DMA fatal bus error - stop transmitting and receiving, no recovery (step 5) */
static void eth_dmaFatal(eth_state_t *state, uint32_t sr)
{
	atomic_store(&state->txStopped, true);
	state->base[eth_maccr] &= ~(ETH_MACCR_TE | ETH_MACCR_RE);

	eth_printf(state, "ERROR: DMA fatal bus error (DMAC0SR=0x%08x TEB=%u REB=%u) - TX and RX stopped, reset required",
			(unsigned int)sr, (unsigned int)((sr & ETH_DMACSR_TEB_MASK) >> ETH_DMACSR_TEB_SHIFT),
			(unsigned int)((sr & ETH_DMACSR_REB_MASK) >> ETH_DMACSR_REB_SHIFT));
	eth_logTxRegs(state, "FBE");
	eth_logRxRegs(state, "FBE");
}


#if ETH_DEBUG
static void eth_logStats(eth_state_t *state, const char *why)
{
	const net_bufdesc_ring_t *tx = &state->rings[ETH_RING_TX];
	const net_bufdesc_ring_t *rx = &state->rings[ETH_RING_RX];

	eth_printf(state, "TX stats (%s): packets=%u errors=%u (flags 0x%04x) dropped=%u ring-full=%u MMC tx_packet_count_good=%u ring head=%u tail=%u",
			why, (unsigned int)state->txPackets, (unsigned int)state->txErrors, (unsigned int)state->txErrFlags,
			atomic_load(&state->txDropped), atomic_load(&state->txRingFull), (unsigned int)state->base[eth_tx_packet_count_good],
			(unsigned int)atomic_load(&tx->head), (unsigned int)atomic_load(&tx->tail));
	eth_printf(state, "RX stats (%s): packets=%u bytes=%u errors=%u (flags 0x%08x) bad-desc=%u input-drop=%u rbu=%u refill-low=%u irqs=%u "
					  "MMC rx_unicast_packets_good=%u crc=%u align=%u MTL overflow=%u missed=%u DMA missed=%u counter-wraps=%u ring head=%u tail=%u",
			why, (unsigned int)state->rxPackets, (unsigned int)state->rxBytes, (unsigned int)state->rxErrors, (unsigned int)state->rxErrFlags,
			(unsigned int)state->rxBadDesc, (unsigned int)state->rxInputDrop, (unsigned int)state->rxRbu, (unsigned int)state->rxRefillLow,
			atomic_load(&state->irqCount), (unsigned int)state->base[eth_rx_unicast_packets_good],
			(unsigned int)state->base[eth_rx_crc_error_packets], (unsigned int)state->base[eth_rx_alignment_error_packets],
			(unsigned int)state->rxMtlOverflow, (unsigned int)state->rxMtlMissed, (unsigned int)state->rxDmaMissed,
			(unsigned int)state->rxDropCntWraps, (unsigned int)atomic_load(&rx->head), (unsigned int)atomic_load(&rx->tail));
}
#endif


/*
 * IRQ thread, every poll: accumulate the clear-on-read RX drop counters. Their fields have 11 bits; when one crosses its
 * maximum between two reads, the overflow flag is set and the read value is not the full count (step 4 R5: 4166 drops
 * read as 0) - such reads are counted, the totals are then lower bounds.
 */
static void eth_rxDropCounters(eth_state_t *state)
{
	uint32_t mpocr = state->base[eth_mtlrxq0mpocr];
	uint32_t mfcr = state->base[eth_dmac0mfcr];

	state->rxMtlOverflow += mpocr & ETH_MTLRXQMPOCR_OVFPKTCNT_MASK;
	state->rxMtlMissed += (mpocr & ETH_MTLRXQMPOCR_MISPKTCNT_MASK) >> ETH_MTLRXQMPOCR_MISPKTCNT_SHIFT;
	state->rxDmaMissed += mfcr & ETH_DMACMFCR_MFC_MASK;
	if (((mpocr & (ETH_MTLRXQMPOCR_OVFCNTOVF | ETH_MTLRXQMPOCR_MISCNTOVF)) != 0U) || ((mfcr & ETH_DMACMFCR_MFCO) != 0U)) {
		state->rxDropCntWraps++;
	}
}


/* IRQ thread, once per LINK_POLL_INTERVAL_US (state->lock not held): PHY poll, statistics, tests */
typedef struct {
	unsigned int polls;
	unsigned int linkChanges;
	uint32_t txPackets, rxPackets;
} eth_pollState_t;


static void eth_poll(eth_state_t *state, eth_pollState_t *ps)
{
	/*
	 * NUCLEO-N657X0-Q has no PHY interrupt line (nINT/REFCLKO pin outputs REF_CLK) - poll the PHY.
	 * NOTE: LAN8742A ISFR reports an event on every read when polled, so link changes are detected from BMSR.
	 * netif_set_link_up/down() (from eth_setLinkState()) runs lwIP code (DHCP, ARP, ...) and may call linkoutput:
	 * lwIP core lock must be held, txLock must not be held here.
	 */
	if (state->phyValid) {
		LOCK_TCPIP_CORE();
		ephy_pollLink(&state->phy, atomic_load(&state->linkUp));
		UNLOCK_TCPIP_CORE();
	}

	eth_rxDropCounters(state);

	ps->polls++;
#if ETH_DEBUG
	if (atomic_load(&state->linkChanges) != ps->linkChanges) {
		ps->linkChanges = atomic_load(&state->linkChanges);
		eth_logStats(state, atomic_load(&state->linkUp) ? "link up" : "link down");
	}
	else if (((ps->polls % ETH_STATS_POLLS) == 0U) && ((state->txPackets != ps->txPackets) || (state->rxPackets != ps->rxPackets))) {
		ps->txPackets = state->txPackets;
		ps->rxPackets = state->rxPackets;
		eth_logStats(state, "periodic");
	}
#endif
}


/*
 * IRQ thread (imx-enet pattern): clear the DMA channel status, receive and refill, reap TX descriptors, unmask the
 * interrupts and wait for the next interrupt; poll the PHY once per LINK_POLL_INTERVAL_US (also under traffic).
 * The interrupt handler masks DMAC0IER, so events arriving while the thread works keep the status bits set and
 * raise the interrupt again when the thread unmasks them; a wakeup before condWait() is not lost (sticky condition).
 */
static void eth_irqThread(void *arg)
{
	eth_state_t *state = arg;
	eth_pollState_t ps = { .linkChanges = atomic_load(&state->linkChanges) };
	time_t now, lastPoll = 0;
	bool fatal = false;
	uint32_t sr;

	mutexLock(state->lock);
	for (;;) {
		sr = state->base[eth_dmac0sr];
		if ((sr & ETH_DMACSR_W1C_MASK) != 0U) {
			state->base[eth_dmac0sr] = sr & ETH_DMACSR_W1C_MASK;
		}

		if (((sr & ETH_DMACSR_FBE) != 0U) && !fatal) {
			fatal = true;
			eth_dmaFatal(state, sr);
		}

		if (!fatal) {
			if ((sr & ETH_DMACSR_RBU) != 0U) {
				state->rxRbu++;
			}
			eth_rxProcess(state);
			eth_txReap(state);
		}

		gettime(&now, NULL);
		if ((now - lastPoll) >= (time_t)LINK_POLL_INTERVAL_US) {
			lastPoll = now;
			mutexUnlock(state->lock);
			eth_poll(state, &ps);
			mutexLock(state->lock);
		}

		if (!fatal) {
			state->base[eth_dmac0ier] = ETH_DMA_IRQS;
			/*
			 * Events that came while DMAC0IER was 0 (after the W1C above) may not raise the interrupt when it is
			 * enabled again (NIS/AIS only summarize enabled sources) - handle them now instead of waiting.
			 */
			if ((state->base[eth_dmac0sr] & (ETH_DMACSR_RI | ETH_DMACSR_TI | ETH_DMACSR_RBU | ETH_DMACSR_FBE)) != 0U) {
				continue;
			}
		}
		(void)condWait(state->cond, state->lock, LINK_POLL_INTERVAL_US);
	}

	mutexUnlock(state->lock);
	endthread();
}


static int eth_initMDIO(eth_state_t *state, size_t idx)
{
	CHECK_MSG(
			stm32_pinConfigMulti(&state->multidrvOid, eth_setup[idx].pinoutPhy, eth_phy_pins),
			state, "Couldn't configure MDIO pins: %s (%d)", strerror(-_ret), _ret);

	return 0;
}


/*
 * Enable clocks and set up clock muxes for ETH module
 */
static int eth_clockEnable(eth_state_t *state, size_t idx)
{
	platformctl_t pctl = { 0 };
	pctl.action = pctl_set;
	pctl.type = pctl_ipclk;
	pctl.ipclk.ipclk = eth_setup[idx].ipclkMode;

	switch (eth_setup[idx].phyMode) {
		case eth_phymode_rmii:
			pctl.ipclk.setting = 4U; /* ETH1SEL: RMII */
			break;
		default:
			return -EINVAL;
	}
	CHECK_MSG(platformctl(&pctl), state, "Couldn't set PHY interface mode");

	pctl.ipclk.ipclk = eth_setup[idx].ipclkClksel;
	pctl.ipclk.setting = eth_setup[idx].clksel;
	CHECK_MSG(platformctl(&pctl), state, "Couldn't set kernel clock source");

	pctl.ipclk.ipclk = eth_setup[idx].ipclkRxRefclk;
	pctl.ipclk.setting = eth_setup[idx].rxRefclkInternal ? 1u : 0u;
	CHECK_MSG(platformctl(&pctl), state, "Couldn't set reference clock source");

	pctl.action = pctl_set;
	pctl.type = pctl_devclk;
	pctl.devclk.state = 1u;
	pctl.devclk.lpState = 1u;
	for (size_t i = 0; i < N_PCTLS; i++) {
		pctl.devclk.dev = eth_setup[idx].pctls[i];
		CHECK_MSG(platformctl(&pctl), state, "Couldn't enable ETH clocks");
	}

	return 0;
}


/*
 * Set pin config for the required ETH module
 */
static int eth_pinConfig(eth_state_t *state, size_t idx)
{
	switch (eth_setup[idx].phyMode) {
		case eth_phymode_rmii:
			return stm32_pinConfigMulti(&state->multidrvOid, eth_setup[idx].rmii, eth_rmii_pins);
		default:
			return -ENOTSUP;
	}
}


static void eth_setupMacAddr(eth_state_t *state, size_t idx)
{
	uint8_t *mac = (void *)&state->netif->hwaddr;
	unsigned int low = 0, high = 0;
	int err;

	err = stm32_getOTP(eth_setup[idx].macOtpFuses[0], &low);
	if (err == 0) {
		err = stm32_getOTP(eth_setup[idx].macOtpFuses[1], &high);
	}

	if (err < 0) {
		eth_printf(state, "WARN: couldn't read MAC address from OTP: %s (%d)", strerror(-err), err);
		low = 0;
		high = 0;
	}
	else {
		eth_printf(state, "OTP[%u]=0x%08x OTP[%u]=0x%08x",
				eth_setup[idx].macOtpFuses[0], low, eth_setup[idx].macOtpFuses[1], high);
	}

	if ((low == 0U) && (high == 0U)) {
		eth_printf(state, "WARN: MAC address stored in OTP is invalid, using default address");
		low = 0x04050607U;
		high = 0x0203U; /* First octet 0x02: bit 1 = locally administered, bit 0 = unicast */
	}

	/*
	 * TODO: byte order of the MAC address in OTP words 169/170 is unconfirmed (risk R5):
	 * this follows WIP (word 170 holds the most significant bytes), while Zephyr
	 * (stm32n6.dtsi: mac-address@2a4) reads 6 bytes in memory order starting from word 169.
	 */
	mac[0] = (high >> 8) & 0xffU;
	mac[1] = (high >> 0) & 0xffU;
	mac[2] = (low >> 24) & 0xffU;
	mac[3] = (low >> 16) & 0xffU;
	mac[4] = (low >> 8) & 0xffU;
	mac[5] = (low >> 0) & 0xffU;

	/* MACA0HR: AE (always 1 for address 0), DCS = RX DMA channel, ADDRHI = bytes 4-5 of the address in register order */
	state->base[eth_maca0hr] = (1UL << 31) | (MAIN_DMA_RX_CHANNEL << 16) | (((uint32_t)mac[5] << 8) | mac[4]);
	state->base[eth_maca0lr] = ((uint32_t)mac[3] << 24) | ((uint32_t)mac[2] << 16) | ((uint32_t)mac[1] << 8) | mac[0];
}


/* Log HW features relevant for DMA configuration (address width, FIFO sizes, queues, channels) */
static void eth_logHwFeatures(eth_state_t *state)
{
	static const unsigned int addrWidth[4] = { 32, 40, 48, 0 };
	uint32_t hwf0 = state->base[eth_machwf0r];
	uint32_t hwf1 = state->base[eth_machwf1r];
	uint32_t hwf2 = state->base[eth_machwf2r];

	/* values are used only in debug output */
	(void)addrWidth;
	(void)hwf0;
	(void)hwf1;
	(void)hwf2;

	eth_debug_printf(state, "MACHWF0R=0x%08x MACHWF1R=0x%08x MACHWF2R=0x%08x",
			(unsigned int)hwf0, (unsigned int)hwf1, (unsigned int)hwf2);
	eth_debug_printf(state, "HW: ACTPHYSEL=%u ADDR64=%u (%u-bit) TXFIFOSIZE=%u (%u B) RXFIFOSIZE=%u (%u B)",
			(unsigned int)((hwf0 & ETH_MACHWF0R_ACTPHYSEL_MASK) >> ETH_MACHWF0R_ACTPHYSEL_SHIFT),
			(unsigned int)((hwf1 & ETH_MACHWF1R_ADDR64_MASK) >> ETH_MACHWF1R_ADDR64_SHIFT),
			addrWidth[(hwf1 & ETH_MACHWF1R_ADDR64_MASK) >> ETH_MACHWF1R_ADDR64_SHIFT],
			(unsigned int)((hwf1 & ETH_MACHWF1R_TXFIFOSIZE_MASK) >> ETH_MACHWF1R_TXFIFOSIZE_SHIFT),
			128U << ((hwf1 & ETH_MACHWF1R_TXFIFOSIZE_MASK) >> ETH_MACHWF1R_TXFIFOSIZE_SHIFT),
			(unsigned int)((hwf1 & ETH_MACHWF1R_RXFIFOSIZE_MASK) >> ETH_MACHWF1R_RXFIFOSIZE_SHIFT),
			128U << ((hwf1 & ETH_MACHWF1R_RXFIFOSIZE_MASK) >> ETH_MACHWF1R_RXFIFOSIZE_SHIFT));
	eth_debug_printf(state, "HW: TXQCNT=%u RXQCNT=%u TXCHCNT=%u RXCHCNT=%u",
			(unsigned int)((hwf2 & ETH_MACHWF2R_TXQCNT_MASK) >> ETH_MACHWF2R_TXQCNT_SHIFT) + 1U,
			(unsigned int)((hwf2 & ETH_MACHWF2R_RXQCNT_MASK) >> ETH_MACHWF2R_RXQCNT_SHIFT) + 1U,
			(unsigned int)((hwf2 & ETH_MACHWF2R_TXCHCNT_MASK) >> ETH_MACHWF2R_TXCHCNT_SHIFT) + 1U,
			(unsigned int)((hwf2 & ETH_MACHWF2R_RXCHCNT_MASK) >> ETH_MACHWF2R_RXCHCNT_SHIFT) + 1U);
}


/*
 * DMA configuration (channel 0), following HAL defaults (stm32n6xx_hal_eth.c @ d88071e:
 * ETH_MACDMAConfig() l. 3201-3222, ETH_SetDMAConfig() l. 3056-3100, RBSZ l. 415,
 * descriptor lists: ETH_DMATxDescListInit() l. 3260-3266, ETH_DMARxDescListInit() l. 3309-3312),
 * except DSL = 2 (16-byte descriptors in 32-byte cache lines, no HAL backup fields).
 * DMA and MTL queues are left stopped here - the TX path is started by eth_startTx(), RX stays disabled.
 */
static void eth_dmaConfig(eth_state_t *state)
{
	const net_bufdesc_ring_t *rx = &state->rings[ETH_RING_RX];
	const net_bufdesc_ring_t *tx = &state->rings[ETH_RING_TX];
	uint32_t v;

	/* DMAMR: TAA = fixed priority, TXPR = 0 */
	v = state->base[eth_dmamr];
	v &= ~(ETH_DMAMR_TAA_MASK | ETH_DMAMR_TXPR);
	state->base[eth_dmamr] = v;

	/* DMASBMR: AAL, fixed burst, BLEN4, RD/WR OSR limit = 3 */
	v = state->base[eth_dmasbmr];
	v &= ~ETH_DMASBMR_CFG_MASK;
	v |= ETH_DMASBMR_AAL | ETH_DMASBMR_FB | ETH_DMASBMR_BLEN4;
	v |= (3UL << ETH_DMASBMR_RD_OSR_LMT_SHIFT) | (3UL << ETH_DMASBMR_WR_OSR_LMT_SHIFT);
	state->base[eth_dmasbmr] = v;

	/* DMAC0CR: DSL = 2 (32-byte descriptor stride), PBLx8 = 0, MSS = 536 (HAL ETH_SEGMENT_SIZE_DEFAULT, unused without TSO) */
	v = state->base[eth_dmac0cr];
	v &= ~ETH_DMACCR_CFG_MASK;
	v |= (ETH_DESC_DSL << ETH_DMACCR_DSL_SHIFT) | (0x218UL & ETH_DMACCR_MSS_MASK);
	state->base[eth_dmac0cr] = v;

	/* DMAC0TXCR: TXPBL = 32, OSF = 0, TSE = 0, stopped */
	v = state->base[eth_dmac0txcr];
	v &= ~(ETH_DMACTXCR_TXPBL_MASK | ETH_DMACTXCR_OSF | ETH_DMACTXCR_TSE | ETH_DMACTXCR_ST);
	v |= ETH_DMA_PBL << ETH_DMACTXCR_TXPBL_SHIFT;
	state->base[eth_dmac0txcr] = v;

	/* DMAC0RXCR: RXPBL = 32, RPF = 0, RBSZ, stopped */
	v = state->base[eth_dmac0rxcr];
	v &= ~(ETH_DMACRXCR_RXPBL_MASK | ETH_DMACRXCR_RPF | ETH_DMACRXCR_RBSZ_MASK | ETH_DMACRXCR_SR);
	v |= ETH_DMA_PBL << ETH_DMACRXCR_RXPBL_SHIFT;
	v |= (ETH_RX_BUF_SIZE << ETH_DMACRXCR_RBSZ_SHIFT) & ETH_DMACRXCR_RBSZ_MASK;
	state->base[eth_dmac0rxcr] = v;

	/*
	 * Descriptor lists. TX tail pointer = ring base (no descriptors for DMA yet), as in HAL.
	 * RX tail pointer is written when RX descriptors are passed to DMA.
	 */
	state->base[eth_dmac0txrlr] = ETH_TX_RING_SIZE - 1U;
	state->base[eth_dmac0txdlar] = (uint32_t)tx->phys;
	state->base[eth_dmac0txdtpr] = (uint32_t)tx->phys;
	state->base[eth_dmac0rxrlr] = ETH_RX_RING_SIZE - 1U;
	state->base[eth_dmac0rxdlar] = (uint32_t)rx->phys;

	eth_debug_printf(state, "rings: RX 0x%08x (%u x %u B), TX 0x%08x (%u x %u B), DSL=%u",
			(unsigned int)rx->phys, ETH_RX_RING_SIZE, ETH_DESC_SIZE, (unsigned int)tx->phys, ETH_TX_RING_SIZE, ETH_DESC_SIZE, ETH_DESC_DSL);
	eth_debug_printf(state, "DMAC0TXDLAR=0x%08x DMAC0TXRLR=%u DMAC0RXDLAR=0x%08x DMAC0RXRLR=%u",
			(unsigned int)state->base[eth_dmac0txdlar], (unsigned int)state->base[eth_dmac0txrlr],
			(unsigned int)state->base[eth_dmac0rxdlar], (unsigned int)state->base[eth_dmac0rxrlr]);
	eth_debug_printf(state, "DMAMR=0x%08x DMASBMR=0x%08x DMAC0CR=0x%08x DMAC0TXCR=0x%08x DMAC0RXCR=0x%08x (RBSZ=%u)",
			(unsigned int)state->base[eth_dmamr], (unsigned int)state->base[eth_dmasbmr],
			(unsigned int)state->base[eth_dmac0cr], (unsigned int)state->base[eth_dmac0txcr],
			(unsigned int)state->base[eth_dmac0rxcr],
			(unsigned int)((state->base[eth_dmac0rxcr] & ETH_DMACRXCR_RBSZ_MASK) >> ETH_DMACRXCR_RBSZ_SHIFT));
}


/* Size of the descriptor memory allocated by net_initRings() */
static size_t eth_ringsMemSize(void)
{
	size_t sz = 0;

	for (size_t i = 0; i < sizeof(eth_ringSizes) / sizeof(eth_ringSizes[0]); i++) {
		sz += (eth_ringSizes[i] * ETH_DESC_SIZE + ETH_RING_ALIGN - 1U) & ~(ETH_RING_ALIGN - 1U);
	}

	return sz;
}


/* Descriptor rings + DMA configuration. Leaves nothing allocated on failure. */
static int eth_initDma(eth_state_t *state)
{
	int err;

	eth_logHwFeatures(state);

	err = net_initRings(state->rings, eth_ringSizes, sizeof(eth_ringSizes) / sizeof(eth_ringSizes[0]), &eth_ringOps);
	if (err < 0) {
		eth_printf(state, "Couldn't initialize descriptor rings: %s (%d)", strerror(-err), err);
		return err;
	}
	state->ringsValid = true;

	/* net_initRings() cleared the rings through D-cache - write them back before DMA can see them */
	eth_cleanDCache(state->rings[0].ring, eth_ringsMemSize());

	eth_dmaConfig(state);

	return 0;
}


/* dmaIdle: DMA can't access the rings and buffers any more (eth_stopTx() succeeded) */
static void eth_releaseRings(eth_state_t *state, bool dmaIdle)
{
	const net_bufdesc_ring_t *tx = &state->rings[ETH_RING_TX];
	const net_bufdesc_ring_t *rx = &state->rings[ETH_RING_RX];

	if (!state->ringsValid) {
		return;
	}

	if (!dmaIdle) {
		eth_printf(state, "WARN: DMA not stopped - descriptor rings and packet buffers are not freed");
		return;
	}

	/* pbufs of RX descriptors filled and not received yet (other bufp entries were passed to lwIP) */
	for (size_t i = atomic_load(&rx->head); i != atomic_load(&rx->tail); i = (i + 1U) & rx->last) {
		if (rx->bufp[i] != NULL) {
			pbuf_free(rx->bufp[i]);
			rx->bufp[i] = NULL;
		}
	}

	/* pbufs of queued/completed TX packets (net_transmitPacket() keeps one past the last fragment) */
	for (size_t i = 0; i <= tx->last; i++) {
		if (tx->bufp[i] != NULL) {
			pbuf_free(tx->bufp[i]);
			tx->bufp[i] = NULL;
		}
	}

	for (size_t i = 0; i < sizeof(state->rings) / sizeof(state->rings[0]); i++) {
		resourceDestroy(state->rings[i].lock);
	}
	/* net_initRings() allocates bufp and descriptor memory for all rings in one block each */
	free(state->rings[0].bufp);
	munmap((void *)state->rings[0].ring, eth_ringsMemSize());
	state->ringsValid = false;
}


/* Hardware bring-up. Resources (register mapping, mutex/cond) must be acquired by the caller. */
static int eth_initHw(eth_state_t *state, size_t idx, bool mdio)
{
	CHECK(eth_clockEnable(state, idx));
	eth_debug_printf(state, "Clocks enabled");

	/* ETH reset will fail unless all (incl. external) clocks are provided - so configure pins first */
	CHECK_MSG(
			eth_pinConfig(state, idx),
			state, "Couldn't configure pins: %s (%d)", strerror(-_ret), _ret);

	if (mdio) {
		CHECK(eth_initMDIO(state, idx));
	}
	eth_debug_printf(state, "Pins configured");

	CHECK(eth_reset(state, idx, RESET_TIMEOUT_US));

	eth_macConfig(state);
	eth_setupMacAddr(state, idx);

	/* Last fallible step: on failure the rings are not allocated */
	CHECK(eth_initDma(state));

	/* DMA channel interrupts stay masked (DMAC0IER = 0) until the IRQ thread runs */
	eth_startTx(state);
	eth_startRx(state);

	return 0;
}


/* Stop the interrupt handler, then RX and TX DMA. Returns false if DMA may still access the rings and buffers. */
static bool eth_stopDevice(eth_state_t *state)
{
	bool rxIdle, txIdle;

	if (state->irqValid) {
		state->base[eth_dmac0ier] = 0U;
		resourceDestroy(state->irqHandle);
		state->irqValid = false;
	}

	rxIdle = eth_stopRx(state);
	txIdle = eth_stopTx(state);

	return rxIdle && txIdle;
}


static void eth_releaseResources(eth_state_t *state)
{
	bool dmaIdle = eth_stopDevice(state);

	eth_releaseRings(state, dmaIdle);
	resourceDestroy(state->cond);
	resourceDestroy(state->txLock);
	resourceDestroy(state->lock);
	physunmap(state->base, ETH_REGS_SIZE);
	state->base = NULL;
}


static int eth_initDevice(eth_state_t *state, unsigned long devnum, bool mdio)
{
	int err = -ENOENT;

	if ((devnum < 1U) || (devnum > N_ETH)) {
		return -ENODEV;
	}

	state->devnum = devnum;
	size_t idx = devnum - 1U;

	/* TODO: configurable timeout */
	for (size_t i = 0; i < MULTIDRV_LOOKUP_RETRIES; i++) {
		err = lookup(STM32_MULTI_PATH, NULL, &state->multidrvOid);
		if (err >= 0) {
			break;
		}
		usleep(100 * 1000);
	}
	CHECK_MSG(err, state, "Failed to find multidriver");

	/* RIF must be configured before the first access to ETH registers */
	CHECK(eth_rifConfig(state, idx));

	state->base = (volatile uint32_t *)physmmap(eth_setup[idx].base, ETH_REGS_SIZE);
	if (state->base == MAP_FAILED) {
		eth_printf(state, "Couldn't map registers");
		return -ENOMEM;
	}

	err = create_mutexcond_bulk(PRIV_RESOURCES(state));
	if (err < 0) {
		eth_printf(state, "Couldn't create resources");
		physunmap(state->base, ETH_REGS_SIZE);
		state->base = NULL;
		return err;
	}

	err = eth_initHw(state, idx, mdio);
	if (err < 0) {
		eth_releaseResources(state);
		return err;
	}

	/* the handler only masks DMAC0IER and wakes the IRQ thread (state->cond), started by eth_netifInit() */
	err = interrupt(eth_setup[idx].irq, eth_irqHandler, state, state->cond, &state->irqHandle);
	if (err < 0) {
		eth_printf(state, "Couldn't register interrupt %u: %s (%d)", eth_setup[idx].irq, strerror(-err), err);
		eth_releaseResources(state);
		return err;
	}
	state->irqValid = true;
	eth_debug_printf(state, "IRQ %u registered", eth_setup[idx].irq);

	if (mdio) {
		/* FIXME: MDIO bus can't be unregistered - state must not be freed after this point */
		state->mdioBus = register_mdio_bus(&eth_mdio_ops, state);
		if (state->mdioBus < 0) {
			eth_printf(state, "Can't register MDIO bus: %s (%d)", strerror(-state->mdioBus), state->mdioBus);
			eth_releaseResources(state);
			return state->mdioBus;
		}
		eth_debug_printf(state, "MDIO bus %d registered", state->mdioBus);
	}

	eth_showCardId(state);
	return 0;
}


static void eth_logPhyId(eth_state_t *state)
{
	uint16_t id1, id2;

	/* Log only if the PHY is on the MDIO bus of this device */
	if ((state->mdioBus < 0) || (state->phy.bus != (unsigned int)state->mdioBus)) {
		return;
	}

	/* ephy_readPhyId() doesn't print the ID - read it here, with the bus locked */
	if (mdio_lock_bus(state->phy.bus) < 0) {
		return;
	}
	id1 = eth_mdioRead(state, state->phy.addr, 2);
	id2 = eth_mdioRead(state, state->phy.addr, 3);
	mdio_unlock_bus(state->phy.bus);

	eth_printf(state, "PHY%u.%u ID 0x%04x%04x", state->phy.bus, state->phy.addr, id1, id2);
}


/* ARGS: stm32eth:n[:no-mdio][:PHY:[model:][bus.]addr[:config]] */
static int eth_netifInit(struct netif *netif, char *cfg)
{
	eth_state_t *state;
	char *p;
	int err;
	bool mdio = true;

	netif->linkoutput = eth_netifOutput;

	state = netif->state;
	state->netif = netif;

	/* netif_add() sets netif->input before calling init: received packets go through eth_netifInput() */
	state->input = netif->input;
	netif->input = eth_netifInput;

	atomic_init(&state->txDropped, 0U);
	state->mdioBus = -1;
	state->phyValid = false;
	atomic_init(&state->linkUp, false);
	atomic_init(&state->linkChanges, 0U);
	state->ringsValid = false;
	state->txStarted = false;
	state->rxStarted = false;
	atomic_init(&state->txStopped, false);
	atomic_init(&state->txRingFull, 0U);
	state->txPackets = 0;
	state->txErrors = 0;
	state->txErrFlags = 0;
	state->irqValid = false;
	atomic_init(&state->irqCount, 0U);
	atomic_init(&state->irqStatus, 0U);
	state->rxPktLen = 0;
	state->rxPktBad = false;
	state->rxLastRdes3 = 0;
	state->rxPackets = 0;
	state->rxBytes = 0;
	state->rxErrors = 0;
	state->rxErrFlags = 0;
	state->rxBadDesc = 0;
	state->rxInputDrop = 0;
	state->rxRbu = 0;
	state->rxRefillLow = 0;
	state->rxMtlOverflow = 0;
	state->rxMtlMissed = 0;
	state->rxDmaMissed = 0;
	state->rxDropCntWraps = 0;

	if (cfg == NULL) {
		return -EINVAL;
	}

	/* Ethernet peripheral number */
	unsigned long devnum = strtoul(cfg, &p, 0);
	if ((*cfg == '\0') || ((*p != ':') && (*p != '\0'))) {
		return -EINVAL;
	}
	if (*p == ':') {
		p++;
	}

	/* MDIO and PHY opts */
	cfg = NULL;
	while ((p != NULL) && (*p != '\0')) {
		cfg = strchr(p, ':');
		if (cfg != NULL) {
			*cfg++ = '\0';
		}

		if (strcmp(p, "no-mdio") == 0) {
			mdio = false;
			p = cfg;
			cfg = NULL;
			continue;
		}

		if (strcmp(p, "PHY") == 0) {
			if ((cfg == NULL) || (*cfg == '\0')) {
				return -EINVAL;
			}
			break;
		}

		return -EINVAL;
	}

	err = eth_initDevice(state, devnum, mdio);
	if (err != 0) {
		printf("lwip: ETH%lu: Failed to initialize device: %s (%d)\n", devnum, strerror(-err), err);
		return err;
	}

	if (cfg != NULL) {
		/* ephy_init() reports the initial link state through eth_setLinkState() */
		err = ephy_init(&state->phy, cfg, 0, eth_setLinkState, (void *)state->netif);
		if (err < 0) {
			eth_printf(state, "WARN: PHY init failed: %s (%d)", strerror(-err), err);
		}
		else {
			state->phyValid = true;
			eth_logPhyId(state);
		}
	}

	if (err >= 0) {
		/* RX, TX reaping, DMA errors and PHY polling */
		err = beginthread(eth_irqThread, IRQ_THREAD_PRIO, state->irqStack, sizeof(state->irqStack), state);
		if (err < 0) {
			eth_printf(state, "Couldn't begin IRQ thread: %s (%d)", strerror(-err), err);
		}
	}

	if (err < 0) {
		/*
		 * FIXME: state can't be released after register_mdio_bus() - at least remove the interrupt handler
		 * and keep DMA away from the rings
		 */
		(void)eth_stopDevice(state);
		return err;
	}

	eth_debug_printf(state, "Initialized");
	return 0;
}


static netif_driver_t eth_drv = {
	.init = eth_netifInit,
	.state_sz = sizeof(eth_state_t),
	.state_align = _Alignof(eth_state_t),
	.name = "stm32eth",
	.media = eth_media,
};


__constructor__(1000) void register_driver_stm32eth(void)
{
	register_netif_driver(&eth_drv);
}
