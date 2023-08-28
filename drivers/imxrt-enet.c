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

#define USE_ENET_EXT_DESCRIPTORS	0
#define USE_RMII			1
#define ENABLE_FLOW_CONTROL		1
#define ENABLE_PROMISC			0
#define ENABLE_RX_PAD_REMOVE		1
#define MDIO_DEBUG			1


#if USE_ENET_EXT_DESCRIPTORS
typedef enet_long_desc_t enet_buf_desc_t;
#else
typedef enet_short_desc_t enet_buf_desc_t;
#endif

static int enet_readFusedMac(uint32_t *buf)
{
	volatile uint32_t *va = physmmap(0x401f4000, 0x1000);

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
	volatile uint32_t *va = physmmap(0x401f4000, 0x1000);
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

	if (state->devphys == 0x402D8000 /* imxrt1064.ENET1 */ && !enet_readFusedMac(buf)) {
		mac[0] = get_byte(buf[1], 1);
		mac[1] = get_byte(buf[1], 0);
		mac[2] = get_byte(buf[0], 3);
		mac[3] = get_byte(buf[0], 2);
		mac[4] = get_byte(buf[0], 1);
		mac[5] = get_byte(buf[0], 0);
	} else if (state->devphys == 0x402D4000 /* imxrt1064.ENET2 */ && !enet_readFusedMac(buf)) {
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
#ifdef ENET_VERBOSE
	enet_printf(state, "configuring MDIO pins");
#endif

	static const platformctl_t pctl_enet1[] = {
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_mdio, 1 } },

		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_emc_40, 1, 0, 1, 1, 0, 2, 6, 0 } },
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_emc_41, 1, 0, 1, 1, 0, 2, 6, 0 } },

		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_emc_40, 1, 4 } }, //enet_mdc
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_emc_41, 1, 4 } }, //enet_mdio
	};
	static const platformctl_t pctl_enet2[] = {
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet2_ipp_ind_mac0_mdio, 1 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b0_01, 0, 8 } },
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b0_00, 0, 8 } },
	};

	int err;

	if (state->devphys == 0x402D8000 /* imxrt1064.ENET1 */)
		err = platformctl_seq(pctl_enet1, sizeof(pctl_enet1) / sizeof(*pctl_enet1));
	else if (state->devphys == 0x402D4000 /* imxrt1064.ENET2 */)
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

	/* set enet1,enet2 for 50MHz, enable PLL */
	*((uint32_t*)0x400d80e4) = 1 | (1 << 2) | (1 << 13) | (1 << 20) | (1 << 21);
	*((uint32_t*)0x400d80e8) = (1 << 12);

	/* set ENET_IPG_CLK_S_EN in (IOMUXC_GPR_GPR1) */
	*((uint32_t*)0x400AC004) |= (1 << 23);
	
	/* tx_clk daisy chain alt3 */
	*((uint32_t*)0x401F8448) |= 1;

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
		{ pctl_set, pctl_iogpr, .iogpr = { pctl_gpr_enet1_clk_sel, 0} },
		{ pctl_set, pctl_iogpr, .iogpr = { pctl_gpr_enet1_tx_clk_dir, 1 } },

		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_txclk, 1 } },
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet0_timer, 2 } },
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_rxerr, 1 } },
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_rxen, 1 } },
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet1_rxdata, 1 } },
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet0_rxdata, 1 } },
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_mdio, 1 } },
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet_ipg_clk_rmi, 1 } },

		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_b1_04, 1, 2, 1, 1, 0, 2, 6, 0 } }, //enet1_rx0
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_b1_05, 1, 2, 1, 1, 0, 2, 6, 0 } }, //enet1_rx1
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_b1_06, 1, 2, 1, 1, 0, 2, 6, 0 } }, //enet1_rxen
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_b1_11, 1, 2, 1, 1, 0, 2, 6, 0 } }, //enet1_rxer
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_b1_07, 1, 2, 1, 1, 0, 2, 6, 0 } }, //enet1_tx0
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_b1_08, 1, 2, 1, 1, 0, 2, 6, 0 } }, //enet1_tx1
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_b1_09, 1, 2, 1, 1, 0, 2, 6, 0 } }, //enet1_txen
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_b1_10, 1, 2, 1, 1, 0, 2, 6, 0 } }, //enet1_txclk
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_b1_12, 1, 2, 1, 1, 0, 2, 6, 0 } }, //enet_1588_event0_in
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_b1_13, 1, 2, 1, 1, 0, 2, 6, 0 } }, //enet_1588_event0_out

		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_04, 1, 3 } }, //enet1_rx0
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_05, 1, 3 } }, //enet1_rx1
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_06, 1, 3 } }, //enet1_rxen
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_11, 1, 3 } }, //enet1_rxer
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_07, 1, 3 } }, //enet1_tx0
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_08, 1, 3 } }, //enet1_tx1
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_09, 1, 3 } }, //enet1_txen
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_10, 1, 6 } }, //enet_ref_clk
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_12, 1, 3 } }, //enet_1588_event0_in
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_13, 1, 3 } }, //enet_1588_event0_out
		// SION(1) = enable clk loopback to ENET module?
		// (RX does not work without it)
	};
	static const platformctl_t pctl_enet2[] = {
		{ pctl_set, pctl_iogpr, .iogpr = { pctl_gpr_enet2_clk_sel, 0 } },
		{ pctl_set, pctl_iogpr, .iogpr = { pctl_gpr_enet2_tx_clk_dir, 1 } },
		{ pctl_set, pctl_ioisel, .ioisel = { pctl_isel_enet2_ipg_clk_rmii, 2 } },

		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_b1_01, 1, 2, 1, 1, 0, 2, 6, 0 } }, //pctl_pad_enet2_rx
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_b1_02, 1, 2, 1, 1, 0, 2, 6, 0 } }, //pctl_pad_enet2_rx1
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_b1_03, 1, 2, 1, 1, 0, 2, 6, 0 } }, //pctl_pad_enet2_rxen
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_b1_00, 1, 2, 1, 1, 0, 2, 6, 0 } }, //pctl_pad_enet2_rxer
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_b1_14, 1, 2, 1, 1, 0, 2, 6, 0 } }, //pctl_pad_enet2_tx0
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_b1_15, 1, 2, 1, 1, 0, 2, 6, 0 } }, //pctl_pad_enet2_tx1
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_b0_14, 1, 2, 1, 1, 0, 2, 6, 0 } }, //pctl_pad_enet2_txen
		{ pctl_set, pctl_iopad, .iopad = { pctl_pad_gpio_b0_15, 1, 0, 0, 0, 0, 0, 6, 1 } }, //pctl_pad_enet2_txclk

		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_01, 1, 8 } }, //pctl_mux_enet2_rx0
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_02, 1, 8 } }, //pctl_mux_enet2_rx1
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_03, 1, 8 } }, //pctl_mux_enet2_rxen
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_00, 1, 8 } }, //pctl_mux_enet2_rxer
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_14, 1, 8 } }, //pctl_mux_enet2_tx0
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b1_15, 1, 8 } }, //pctl_mux_enet2_tx1
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b0_14, 1, 8 } }, //pctl_mux_enet2_txen
		{ pctl_set, pctl_iomux, .iomux = { pctl_mux_gpio_b0_15, 1, 8 } }, //pctl_mux_enet2_txclk
	};

	int err;

	if (state->devphys == 0x402D8000 /* imxrt1064.ENET1 */) {
#ifdef ENET_VERBOSE
		enet_printf(state, "configure ENET1 pins");
#endif
		err = platformctl_seq(pctl_enet1, sizeof(pctl_enet1) / sizeof(*pctl_enet1));
	}
	else if (state->devphys == 0x402D4000 /* imxrt1064.ENET2 */) {
#ifdef ENET_VERBOSE
		enet_printf(state, "configure ENET2 pins");
#endif
		err = platformctl_seq(pctl_enet2, sizeof(pctl_enet2) / sizeof(*pctl_enet2));
	}
	else {
		err = 0;
	}

	if (err < 0) {
		enet_printf(state, "Can't configure ENET pins");
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

	usleep(1000000);

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

#ifdef ENET_VERBOSE
	printf("\tPLL_ENET: %08x\n", *((uint32_t*)0x400d80e0));
	printf("\tCCGR1: %08x\n", *((uint32_t*)0x400FC06C));
	printf("\tGPR1: %08x\n", *((uint32_t*)0x400AC004));
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
