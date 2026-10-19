/*
 * Phoenix-RTOS --- networking stack
 *
 * STM32 ETH network module driver
 *
 * Driver skeleton: RIF, clocks, pins, MAC reset, MAC address, MDIO bus and
 * PHY link state polling. Data path (descriptors, DMA, RX/TX) is not implemented yet.
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


#define ETH_DEBUG  0
#define MDIO_DEBUG 0

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
	v |= ETH_ENABLE_FLOW_CONTROL ? (ETH_MACQ0TXFCR_DZPQ | ETH_MACQ0TXFCR_TFE) : 0;
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

	return 0;
}


static void eth_releaseResources(eth_state_t *state)
{
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
