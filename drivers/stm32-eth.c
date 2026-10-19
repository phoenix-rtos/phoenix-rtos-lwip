/*
 * Phoenix-RTOS --- networking stack
 *
 * STM32 ETH network module driver
 *
 * Driver skeleton: RIF, clocks, pins, MAC reset, MAC address, MDIO bus,
 * PHY link state polling and DMA descriptor rings (cacheable memory, one descriptor per cache line).
 * Data path (RX/TX, interrupts) is not implemented yet - DMA is never started in normal operation.
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

#include <sys/mman.h>
#include <sys/platform.h>
#include <sys/threads.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <errno.h>
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

/*
 * DMA smoke test (debug only), runs once after the first link up:
 * transmit one broadcast test frame (EtherType 0x88B5) from a buffer in AXISRAM2 and one from AXISRAM3-6,
 * then stop DMA.
 */
#ifndef STM32ETH_DMA_SMOKE_TEST
#define STM32ETH_DMA_SMOKE_TEST 0
#endif

#define ETH_ENABLE_FLOW_CONTROL  true
#define ETH_PROMISC_MODE         false
#define ETH_ENABLE_RX_PAD_REMOVE true

#define MAIN_DMA_RX_CHANNEL 0UL

#define RESET_TIMEOUT_US      (500U * 1000U)
#define MDIO_TIMEOUT_US       (10U * 1000U)
#define LINK_POLL_INTERVAL_US (1000U * 1000U)
#define LINK_THREAD_PRIO      4

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

#define PRIV_RESOURCES(s) &(s)->lock, 2, ~0x01
	handle_t lock, cond;

	size_t devnum;
	oid_t multidrvOid;
	int mdioBus; /* MDIO bus index registered by this device, < 0 if none */
	bool phyValid;
	bool linkUp; /* last link state reported by ephy (written only by ephy_init() and the link thread) */
	eth_phy_state_t phy;

	atomic_uint txDropped;

	/* DMA descriptor rings (cacheable memory from net_initRings()), valid if ringsValid */
	net_bufdesc_ring_t rings[2];
	bool ringsValid;

#if STM32ETH_DMA_SMOKE_TEST
	bool smokeTestDone;
#endif

	uint32_t linkStack[1024] __attribute__((aligned(16)));
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
	v |= ETH_MACCR_IPC; /* Enable RX checksum offload TODO: verify together with RX path */
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


/* Data path is not implemented yet - drop all packets. The pbuf is owned by the caller. */
static err_t eth_netifOutput(struct netif *netif, struct pbuf *p)
{
	eth_state_t *state = netif->state;

	(void)p;
	(void)atomic_fetch_add(&state->txDropped, 1U);

	return ERR_IF;
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

	priv->linkUp = (state != 0);

	if (state == 0) {
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


/* Descriptor rings: placement and sizes only, RX/TX callbacks are added together with the data path */
static const net_bufdesc_ops_t eth_ringOps = {
	.desc_size = ETH_DESC_SIZE,
	.ring_alignment = ETH_RING_ALIGN,
	.pkt_buf_sz = ETH_RX_BUF_SIZE,
	.max_tx_frag = ETH_TDES2_B1L_MASK,
};

_Static_assert(sizeof(eth_dma_desc_t) == ETH_DESC_SIZE, "descriptor stride must match DMACxCR.DSL");
_Static_assert((ETH_DESC_SIZE - 16U) == (ETH_DESC_DSL * 8U), "DSL in 8-byte units (64-bit DMA bus)");

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
 * NOTE: FL is set to the buffer length - valid for packets in a single buffer only.
 * IOC is set on the last descriptor of a packet, so that DMACxSR.TI reports its completion.
 */
static inline void eth_txDescFill(volatile eth_dma_desc_t *desc, addr_t pa, size_t len, bool first, bool last)
{
	uint32_t tdes3 = (len & ETH_TDES3_FL_MASK) | (0UL << ETH_TDES3_CPC_SHIFT); /* CPC = 0: insert CRC and pad */

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


#if STM32ETH_DMA_SMOKE_TEST

#define SMOKE_ETHERTYPE       0x88b5U /* IEEE 802 local experimental EtherType 1 */
#define SMOKE_PAYLOAD_LEN     64U
#define SMOKE_FRAME_LEN       (14U + SMOKE_PAYLOAD_LEN)
#define SMOKE_TIMEOUT_US      (100U * 1000U)
#define SMOKE_STOP_TIMEOUT_US (10U * 1000U)
#define SMOKE_PROBE_TRIES     64U
#define SMOKE_PROBE_SIZE      (16U * 1024U)
#define SMOKE_AXISRAM3_START  0x34200000U /* AXISRAM3-6: 0x34200000-0x343bffff */
#define SMOKE_AXISRAM6_END    0x343c0000U
#define SMOKE_BUFS            2U
#define SMOKE_BUF_SIZE        _PAGE_SIZE /* dmammap() granularity */


typedef struct {
	const char *name;
	bool run;
	addr_t buf;
	addr_t desc;
	uint32_t tdes3;
	uint32_t sr;
	uint32_t dsr;
	unsigned int us;
} eth_smokeResult_t;


static void eth_smokeLogRegs(eth_state_t *state, const char *when)
{
	eth_printf(state, "DMA smoke: %s: DMAC0SR=0x%08x DMADSR=0x%08x DMAISR=0x%08x DMAC0TXCR=0x%08x DMAC0CATXDR=0x%08x DMAC0CATXBR=0x%08x",
			when, (unsigned int)state->base[eth_dmac0sr], (unsigned int)state->base[eth_dmadsr], (unsigned int)state->base[eth_dmaisr],
			(unsigned int)state->base[eth_dmac0txcr], (unsigned int)state->base[eth_dmac0catxdr], (unsigned int)state->base[eth_dmac0catxbr]);
	eth_printf(state, "DMA smoke: %s: DMAC0TXDLAR=0x%08x DMAC0TXDTPR=0x%08x DMAC0TXRLR=%u MTLTXQ0OMR=0x%08x MTLTXQ0DR=0x%08x MTLTXQ0UR=0x%08x MACCR=0x%08x",
			when, (unsigned int)state->base[eth_dmac0txdlar], (unsigned int)state->base[eth_dmac0txdtpr], (unsigned int)state->base[eth_dmac0txrlr],
			(unsigned int)state->base[eth_mtltxq0omr], (unsigned int)state->base[eth_mtltxq0dr], (unsigned int)state->base[eth_mtltxq0ur],
			(unsigned int)state->base[eth_maccr]);
}


/* Test frame: broadcast, EtherType 0x88B5, payload 00 01 .. 3f */
static void eth_smokeFillFrame(eth_state_t *state, uint8_t *frame)
{
	memset(frame, 0xff, 6);                     /* destination: broadcast */
	memcpy(frame + 6, state->netif->hwaddr, 6); /* source: our MAC */
	frame[12] = (uint8_t)(SMOKE_ETHERTYPE >> 8);
	frame[13] = (uint8_t)(SMOKE_ETHERTYPE & 0xffU);
	for (size_t i = 0; i < SMOKE_PAYLOAD_LEN; i++) {
		frame[14U + i] = (uint8_t)i; /* counter pattern 00 01 02 ... */
	}
}


/* Transmit one frame from buf using TX descriptor i. TX DMA must be running (suspended at descriptor i). */
static void eth_smokeTransmit(eth_state_t *state, size_t i, uint8_t *buf, eth_smokeResult_t *res)
{
	const net_bufdesc_ring_t *tx = &state->rings[ETH_RING_TX];
	volatile eth_dma_desc_t *desc = eth_desc(tx, i);
	time_t start, now;

	eth_smokeFillFrame(state, buf);
	res->run = true;
	res->buf = va2pa(buf);
	res->desc = eth_descPhys(tx, i);
	eth_debug_printf(state, "DMA smoke: %s: buffer 0x%08x, descriptor %u at 0x%08x",
			res->name, (unsigned int)res->buf, (unsigned int)i, (unsigned int)res->desc);

	eth_cleanDCache(buf, SMOKE_FRAME_LEN);

	eth_txDescFill(desc, res->buf, SMOKE_FRAME_LEN, true, true);

	/* clear DMA channel status, so that it reports this transfer only */
	state->base[eth_dmac0sr] = ETH_DMACSR_W1C_MASK;

	__asm__ volatile("dsb" ::: "memory");
	state->base[eth_dmac0txdtpr] = (uint32_t)eth_descPhys(tx, i + 1U);

	gettime(&start, NULL);
	for (;;) {
		if (eth_txDescDone(desc) || ((state->base[eth_dmac0sr] & ETH_DMACSR_FBE) != 0U)) {
			break;
		}

		gettime(&now, NULL);
		if ((now - start) >= (time_t)SMOKE_TIMEOUT_US) {
			break;
		}
		usleep(100);
	}
	gettime(&now, NULL);

	res->us = (unsigned int)(now - start);
	eth_invalDCache(desc, sizeof(*desc));
	res->tdes3 = desc->des[3];
	res->sr = state->base[eth_dmac0sr];
	res->dsr = state->base[eth_dmadsr];
}


/* Allocate dmammap() chunks until one reaches into AXISRAM3-6. Returns a buffer inside it (owned by *chunk) or NULL. */
static uint8_t *eth_smokeAllocAxisram36(eth_state_t *state, void **chunk)
{
	void *chunks[SMOKE_PROBE_TRIES];
	uint8_t *found = NULL;
	size_t n;

	*chunk = NULL;
	for (n = 0; n < SMOKE_PROBE_TRIES; n++) {
		chunks[n] = dmammap(SMOKE_PROBE_SIZE);
		if (chunks[n] == NULL) {
			break;
		}

		addr_t pa = va2pa(chunks[n]);
		addr_t pend = pa + SMOKE_PROBE_SIZE;
		addr_t b = (pa < SMOKE_AXISRAM3_START) ? SMOKE_AXISRAM3_START : pa;
		if ((b + SMOKE_FRAME_LEN <= pend) && (b + SMOKE_FRAME_LEN <= SMOKE_AXISRAM6_END)) {
			found = (uint8_t *)chunks[n] + (b - pa);
			*chunk = chunks[n];
			n++;
			break;
		}
	}

	eth_debug_printf(state, "DMA smoke: AXISRAM3-6 probe: %u allocation(s) of %u B, %s",
			(unsigned int)n, SMOKE_PROBE_SIZE, (found != NULL) ? "found" : "not found");

	/* free all other chunks */
	for (size_t i = 0; i < n; i++) {
		if ((chunks[i] != NULL) && (chunks[i] != *chunk)) {
			munmap(chunks[i], SMOKE_PROBE_SIZE);
		}
	}

	return found;
}


/* Start TX: MTL TX queue 0, TX DMA (suspended - tail pointer = first descriptor) and MAC TX. Returns previous MTLTXQ0OMR. */
static uint32_t eth_smokeStart(eth_state_t *state)
{
	uint32_t omr = state->base[eth_mtltxq0omr];
	uint32_t v = omr;

	/* MTL TX queue 0: enabled, store and forward, 2048 B (HAL ETH_TRANSMIT_QUEUE_SIZE_2048) */
	v &= ~(ETH_MTLTXQOMR_TQS_MASK | ETH_MTLTXQOMR_TXQEN_MASK | ETH_MTLTXQOMR_TTC_MASK | ETH_MTLTXQOMR_TSF);
	v |= (7UL << ETH_MTLTXQOMR_TQS_SHIFT) | ETH_MTLTXQOMR_TXQEN_EN | ETH_MTLTXQOMR_TSF;
	state->base[eth_mtltxq0omr] = v;

	state->base[eth_dmac0txcr] |= ETH_DMACTXCR_ST;
	state->base[eth_maccr] |= ETH_MACCR_TE;
	__asm__ volatile("dsb" ::: "memory");

	return omr;
}


/* Wait until (reg & mask) == val. Returns false on timeout. */
static bool eth_smokeWait(eth_state_t *state, unsigned int reg, uint32_t mask, uint32_t val)
{
	time_t start, now;

	gettime(&start, NULL);
	for (;;) {
		if ((state->base[reg] & mask) == val) {
			return true;
		}

		gettime(&now, NULL);
		if ((now - start) >= (time_t)SMOKE_STOP_TIMEOUT_US) {
			return false;
		}
		usleep(100);
	}
}


/*
 * Stop TX (HAL_ETH_Stop() order): TX DMA, wait for the TX process to stop, flush MTL TX queue 0,
 * MAC TX, restore MTLTXQ0OMR (queue disabled). On success the TX ring is restored to the state after init.
 * Returns false if DMA may still access memory or needs a reset (SWR) before it can be used again.
 */
static bool eth_smokeStop(eth_state_t *state, uint32_t omr, bool fbe)
{
	const net_bufdesc_ring_t *tx = &state->rings[ETH_RING_TX];
	bool stopped, flushed;

	state->base[eth_dmac0txcr] &= ~ETH_DMACTXCR_ST;
	stopped = eth_smokeWait(state, eth_dmadsr, ETH_DMADSR_TPS0_MASK, ETH_DMADSR_TPS_STOPPED << ETH_DMADSR_TPS0_SHIFT);
	if (!stopped) {
		eth_printf(state, "WARN: DMA smoke: TX process not stopped (DMADSR=0x%08x)", (unsigned int)state->base[eth_dmadsr]);
	}

	state->base[eth_mtltxq0omr] |= ETH_MTLTXQOMR_FTQ;
	flushed = eth_smokeWait(state, eth_mtltxq0omr, ETH_MTLTXQOMR_FTQ, 0U);
	if (!flushed) {
		eth_printf(state, "WARN: DMA smoke: MTL TX queue not flushed (MTLTXQ0DR=0x%08x)", (unsigned int)state->base[eth_mtltxq0dr]);
	}

	state->base[eth_maccr] &= ~ETH_MACCR_TE;
	state->base[eth_mtltxq0omr] = omr & ~(ETH_MTLTXQOMR_TXQEN_MASK | ETH_MTLTXQOMR_FTQ);

	if (!stopped || fbe) {
		eth_printf(state, "ERROR: DMA smoke: TX DMA %s - reset (DMAMR.SWR) required before using DMA", fbe ? "fatal bus error" : "not stopped");
		return false;
	}

	/* restore the TX ring to the state after init (DMA restarts from DLAR) */
	for (size_t i = 0; i < ETH_TX_RING_SIZE; i++) {
		volatile eth_dma_desc_t *desc = eth_desc(tx, i);
		desc->des[0] = 0U;
		desc->des[1] = 0U;
		desc->des[2] = 0U;
		desc->des[3] = 0U;
	}
	eth_cleanDCache(tx->ring, ETH_TX_RING_SIZE * sizeof(eth_dma_desc_t));
	state->base[eth_dmac0txdlar] = (uint32_t)tx->phys;
	state->base[eth_dmac0txdtpr] = (uint32_t)tx->phys;
	state->base[eth_dmac0sr] = ETH_DMACSR_W1C_MASK;

	return true;
}


static void eth_smokeLogResult(eth_state_t *state, const eth_smokeResult_t *res)
{
	if (!res->run) {
		eth_printf(state, "DMA smoke: %s: NOT COVERED", res->name);
		return;
	}

	eth_printf(state, "DMA smoke: %s 0x%08x desc 0x%08x OWN=%u FBE=%u TI=%u TBU=%u TPS=%u AIS=%u NIS=%u TEB=%u "
					  "TDES3=0x%08x DMAC0SR=0x%08x DMADSR=0x%08x (TPS0=%u) t=%u us",
			res->name, (unsigned int)res->buf, (unsigned int)res->desc,
			((res->tdes3 & ETH_TDES3_OWN) != 0U) ? 1U : 0U,
			((res->sr & ETH_DMACSR_FBE) != 0U) ? 1U : 0U,
			((res->sr & ETH_DMACSR_TI) != 0U) ? 1U : 0U,
			((res->sr & ETH_DMACSR_TBU) != 0U) ? 1U : 0U,
			((res->sr & ETH_DMACSR_TPS) != 0U) ? 1U : 0U,
			((res->sr & ETH_DMACSR_AIS) != 0U) ? 1U : 0U,
			((res->sr & ETH_DMACSR_NIS) != 0U) ? 1U : 0U,
			(unsigned int)((res->sr & ETH_DMACSR_TEB_MASK) >> ETH_DMACSR_TEB_SHIFT),
			(unsigned int)res->tdes3, (unsigned int)res->sr, (unsigned int)res->dsr,
			(unsigned int)((res->dsr & ETH_DMADSR_TPS0_MASK) >> ETH_DMADSR_TPS0_SHIFT), res->us);
}


/*
 * Verify that the ETH1 bus master can read descriptors from the TX ring (cacheable, DSL = 2) and frame buffers
 * in AXISRAM2 / AXISRAM3-6: transmit one broadcast frame from each buffer.
 * Runs once, from the link thread, after the first link up. TX DMA and MAC TX are stopped afterwards.
 */
static void eth_dmaSmokeTest(eth_state_t *state)
{
	eth_smokeResult_t res[SMOKE_BUFS] = {
		{ .name = "AXISRAM2" },
		{ .name = "AXISRAM3-6" },
	};
	uint8_t *buf0, *buf1;
	void *chunk1 = NULL;
	bool fbe = false, idle;
	uint32_t omr;

	eth_printf(state, "DMA smoke: start");

	buf0 = dmammap(SMOKE_BUF_SIZE);
	if (buf0 == NULL) {
		eth_printf(state, "DMA smoke: couldn't allocate buffer");
		return;
	}

	buf1 = eth_smokeAllocAxisram36(state, &chunk1);

	eth_smokeLogRegs(state, "before");
	omr = eth_smokeStart(state);

	/* buffer from dmammap() - normally in AXISRAM2 (axi_app starts at 0x34100000) */
	if (va2pa(buf0) >= SMOKE_AXISRAM3_START) {
		res[0].name = "AXISRAM3-6 (1st)";
	}
	eth_smokeTransmit(state, 0, buf0, &res[0]);
	if ((res[0].sr & ETH_DMACSR_FBE) != 0U) {
		fbe = true;
		eth_smokeLogRegs(state, "FBE");
	}

	/* don't retry after a fatal bus error - DMA channel is stopped until reset */
	if ((buf1 != NULL) && !fbe) {
		eth_smokeTransmit(state, 1, buf1, &res[1]);
		if ((res[1].sr & ETH_DMACSR_FBE) != 0U) {
			fbe = true;
			eth_smokeLogRegs(state, "FBE");
		}
	}

	idle = eth_smokeStop(state, omr, fbe);
	eth_smokeLogRegs(state, "after");

	for (size_t i = 0; i < SMOKE_BUFS; i++) {
		if (!res[i].run && fbe && (buf1 != NULL)) {
			eth_printf(state, "DMA smoke: %s: NOT RUN (FBE)", res[i].name);
		}
		else {
			eth_smokeLogResult(state, &res[i]);
		}
	}

	eth_printf(state, "DMA smoke: done, MACCR=0x%08x DMAC0TXCR=0x%08x", (unsigned int)state->base[eth_maccr], (unsigned int)state->base[eth_dmac0txcr]);

	if (!idle) {
		/* DMA may still access the buffers - don't free them */
		return;
	}

	munmap(buf0, SMOKE_BUF_SIZE);
	if (chunk1 != NULL) {
		munmap(chunk1, SMOKE_PROBE_SIZE);
	}
}


#endif /* STM32ETH_DMA_SMOKE_TEST */


/*
 * NUCLEO-N657X0-Q has no PHY interrupt line (nINT/REFCLKO pin outputs REF_CLK) - poll the PHY.
 * NOTE: LAN8742A ISFR reports an event on every read when polled, so link changes are detected from BMSR.
 */
static void eth_linkThread(void *arg)
{
	eth_state_t *state = arg;

	mutexLock(state->lock);
	for (;;) {
		(void)condWait(state->cond, state->lock, LINK_POLL_INTERVAL_US);
		mutexUnlock(state->lock);

		ephy_pollLink(&state->phy, state->linkUp);

#if STM32ETH_DMA_SMOKE_TEST
		if (state->linkUp && !state->smokeTestDone) {
			state->smokeTestDone = true;
			eth_dmaSmokeTest(state);
		}
#endif

		mutexLock(state->lock);
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
 * DMA, MAC TX/RX and MTL queues are left disabled.
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


static void eth_releaseRings(eth_state_t *state)
{
	if (!state->ringsValid) {
		return;
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

	/* Last step: on failure the rings are not allocated */
	CHECK(eth_initDma(state));

	return 0;
}


static void eth_releaseResources(eth_state_t *state)
{
	eth_releaseRings(state);
	resourceDestroy(state->cond);
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
	atomic_init(&state->txDropped, 0U);
	state->mdioBus = -1;
	state->phyValid = false;
	state->linkUp = false;
	state->ringsValid = false;
#if STM32ETH_DMA_SMOKE_TEST
	state->smokeTestDone = false;
#endif

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
			return err;
		}

		state->phyValid = true;
		eth_logPhyId(state);

		CHECK_MSG(beginthread(eth_linkThread, LINK_THREAD_PRIO, state->linkStack, sizeof(state->linkStack), state),
				state, "Couldn't begin link thread: %s (%d)", strerror(-_ret), _ret);
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
