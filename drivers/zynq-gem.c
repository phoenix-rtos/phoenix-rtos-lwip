/*
 * Phoenix-RTOS --- networking stack
 *
 * Xilinx ZynqMP Ultrasoc+ GEM (Gigabity Ethernet MAC) driver.
 *
 * Copyright 2025 Phoenix Systems
 * Author: Norbert Niderla
 *
 * %LICENSE%
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/platform.h>
#include <sys/threads.h>
#include "netif-driver.h"
#include "ephy.h"
#include "bdring.h"
#include "physmmap.h"

#include <phoenix/arch/aarch64/zynqmp/zynqmp.h>

#define LOG_ENABLE 0

/**
 * mmio - uint32_t pointer to mapped GEM register.
 * reg - register offset
 */
#define reg(mmio, reg) (*((mmio) + ((reg) >> 2)))
#define mbarrier()     __asm__ volatile("dmb ish")
#define log(fmt, ...) \
	do { \
		if (LOG_ENABLE) \
			printf("zynq-gem: " fmt "\n", ##__VA_ARGS__); \
	} while (0)

#define GEM_MMIO_MODULE_SIZE 0x1000
#define GEM_PACKET_MAX_SIZE  1536

/* network_control register definitions */
#define NWCTRL_EN_RX         (1 << 2)
#define NWCTRL_EN_TX         (1 << 3)
#define NWCTRL_MAN_PORT_EN   (1 << 4)
#define NWCTRL_CLEAR_STATS   (1 << 5)
#define NWCTRL_TX_START_PCLK (1 << 9)

/* network_config register definitions */
#define NWCFG_FULL_DUPLEX      (1 << 1)
#define NWCFG_COPY_ALL_FRAMES  (1 << 4)
#define NWCFG_FCS_REMOVE       (1 << 17)
#define NWCFG_MDC_CLK_DIV_MASK (7 << 18)
#define NWCFG_MDC_CLK_DIV_8    (0 << 18)
#define NWCFG_MDC_CLK_DIV_16   (1 << 18)
#define NWCFG_MDC_CLK_DIV_32   (2 << 18)
#define NWCFG_MDC_CLK_DIV_48   (3 << 18)
#define NWCFG_MDC_CLK_DIV_64   (4 << 18)
#define NWCFG_MDC_CLK_DIV_96   (5 << 18)
#define NWCFG_MDC_CLK_DIV_128  (6 << 18)
#define NWCFG_MDC_CLK_DIV_224  (7 << 18)

/* network_status register definitions */
#define NWSTATUS_MAN_DONE (1 << 2)

/* dma_config register definitions */
#define DMACFG_RX_BUF_SIZE_MASK  (0xFF << 16)
#define DMACFG_RX_BUF_SIZE_1536  ((1536 / 64) << 16)
#define DMACFG_PACKET_BIG_ENDIAN (1 << 7)

/* phy_management register definitions */
#define PHYMNG_CLAUSE22_READ  ((1 << 30) | (2 << 28) | (2 << 16))
#define PHYMNG_CLAUSE22_WRITE ((1 << 30) | (1 << 28) | (2 << 16))

/* GEM interrupts definitions */
#define IRQ_PHYMNG_FRAME_SENT             (1 << 0)
#define IRQ_RX_CPLT                       (1 << 1)
#define IRQ_RX_USED_BIT_READ              (1 << 2)
#define IRQ_TX_USED_BIT_READ              (1 << 3)
#define IRQ_TRANSMIT_UNDER_RUN            (1 << 4)
#define IRQ_RETRY_LIMIT_OR_LATE_COLLISION (1 << 5)
#define IRQ_AMBA_ERROR                    (1 << 6)
#define IRQ_TX_CPLT                       (1 << 7)
#define IRQ_LINK_CHANGE                   (1 << 9)
#define IRQ_RX_OVERRUN                    (1 << 10)
#define IRQ_RESP_NOT_OK                   (1 << 11)

/* receive_status register definitions */
#define RXSTATUS_BUFFER_NOT_AVAIL (1 << 0)
#define RXSTATUS_FRAME_RCVD       (1 << 1)
#define RXSTATUS_RX_OVERRUN       (1 << 2)
#define RXSTATUS_RESP_NOT_OK      (1 << 3)

/* transmit_status register definitions */
#define TXSTATUS_USED_BIT_READ        (1 << 0)
#define TXSTATUS_COLLISION            (1 << 1)
#define TXSTATUS_RETRY_LIMIT_EXCEEDED (1 << 2)
#define TXSTATUS_TRANSMIT_GO          (1 << 3)
#define TXSTATUS_AMBA_ERROR           (1 << 4)
#define TXSTATUS_TRANSMIT_CPLT        (1 << 5)
#define TXSTATUS_TRANSMIT_UNDER_RUN   (1 << 6)
#define TXSTATUS_LATE_COLLISION       (1 << 7)
#define TXSTATUS_RESP_NOT_OK          (1 << 8)

/* Size of buffer descriptor rings. */
#define BD_RING_SIZE 8

/* buffer descriptors definitions */
#define DESC_TX_SZ_MASK   (0x3FFF << 0)
#define DESC_TX_LAST      (1 << 15)
#define DESC_TX_WRAP      (1 << 30)
#define DESC_TX_CPU_OWN   (1 << 31)
#define DESC_RX_CPU_OWN   (1 << 0)
#define DESC_RX_WRAP      (1 << 1)
#define DESC_RX_ADDR_MASK (0x3FFFFFFF << 2)
#define DESC_RX_LEN_MASK  (0x1FFF << 0)

/* GEM register offsets */
#define NWCTRL     0x0
#define NWCFG      0x4
#define NWSTATUS   0x8
#define DMACFG     0x10
#define TXSTATUS   0x14
#define RXQPTR     0x18
#define TXQPTR     0x1c
#define RXSTATUS   0x20
#define IRQSTATUS  0x24
#define IRQENABLE  0x28
#define IRQDISABLE 0x2c
#define PHYMNG     0x34
#define TXQ1PTR    0x440
#define RXQ1PTR    0x480


static const uint8_t xilinxMac[6] = { 0x00, 0x0a, 0x35, 0x00, 0x00, 0x00 };


typedef struct gembd {
	uint32_t addr;   /* Word 0 */
	uint32_t status; /* Word 1*/
} gembd_t;


typedef struct gem {
	eth_phy_state_t phy;
	struct netif *netif;
	volatile uint32_t *mmio;
	net_bufdesc_ring_t bd[2];
	net_bufdesc_ring_t *tx;
	net_bufdesc_ring_t *rx;

	volatile gembd_t *bdSec[2];

	uint32_t threadStack[1024] __attribute__((aligned(16)));
} gem_t;


static int gem_mdioSetup(void *arg, unsigned max_khz, unsigned min_hold_ns, unsigned opt_preamble)
{
	gem_t *gem = (gem_t *)arg;
	int ret;

	/* TODO Shouldn't pin numbers be passed through configuration command? */

	platformctl_t mdioPinCtl = {
		.type = pctl_mio,
		.action = pctl_set,
		.mio = {
			.pin = pctl_mio_pin_76,
			.l0 = 0,
			.l1 = 0,
			.l2 = 0,
			.l3 = 6,
			.config = 0 }
	};

	platformctl_t mdcPinCtl = {
		.type = pctl_mio,
		.action = pctl_set,
		.mio = {
			.pin = pctl_mio_pin_77,
			.l0 = 0,
			.l1 = 0,
			.l2 = 0,
			.l3 = 6,
			.config = 0 }
	};

	if ((ret = platformctl(&mdioPinCtl)) != 0) {
		return ret;
	}

	if ((ret = platformctl(&mdcPinCtl)) != 0) {
		return ret;
	}

	/* Set highest possible divider, the only limit is that CLK cannot be faster than 2.5MHz on MDIO. There is not much communication on MDIO interface after configuration. */
	reg(gem->mmio, NWCFG) = (reg(gem->mmio, NWCFG) & (~NWCFG_MDC_CLK_DIV_MASK)) | NWCFG_MDC_CLK_DIV_224;
	reg(gem->mmio, NWCTRL) |= NWCTRL_MAN_PORT_EN;

	log("successful gem_mdio setup");
	return 0;
}


static uint16_t gem_mdioRead(void *arg, unsigned addr, uint16_t reg)
{
	gem_t *gem = (gem_t *)arg;

	/* Clause22, Read Operation */
	reg(gem->mmio, PHYMNG) = PHYMNG_CLAUSE22_READ | ((addr & 0x1F) << 23) | ((reg & 0x1F) << 18);

	while ((reg(gem->mmio, NWSTATUS) & NWSTATUS_MAN_DONE) == 0) {
		/* Waiting for this operation to end. */
		/* TODO: timeout ? */
	}

	return reg(gem->mmio, PHYMNG) & 0xFFFF;
}


static void gem_mdioWrite(void *arg, unsigned addr, uint16_t reg, uint16_t val)
{
	gem_t *gem = (gem_t *)arg;

	reg(gem->mmio, PHYMNG) = PHYMNG_CLAUSE22_WRITE | ((addr & 0x1F) << 23) | ((reg & 0x1F) << 18) | (uint32_t)val;

	while ((reg(gem->mmio, NWSTATUS) & NWSTATUS_MAN_DONE) == 0) {
		/* Waiting for this operation to end */
		/* TODO: timeout? */
	}
}


static const mdio_bus_ops_t mdioBusOps = {
	.setup = gem_mdioSetup,
	.read = gem_mdioRead,
	.write = gem_mdioWrite
};


static size_t gem_nextRxBufferSize(const net_bufdesc_ring_t *ring, size_t i)
{
	volatile gembd_t *bd = ((volatile gembd_t *)ring->ring) + i;
	size_t sz;

	if ((bd->addr & DESC_RX_CPU_OWN) == 0) {
		return 0;
	}

	sz = bd->status & DESC_RX_LEN_MASK;

	if (sz == 0) {
		/* Error, set 1 and go on */
		sz = 1;
	}

	/* TODO Should I add here ETH_PAD_SIZE? */
	return sz + ETH_PAD_SIZE;
}


static int gem_pktRxFinished(const net_bufdesc_ring_t *ring, size_t i)
{
	volatile gembd_t *bd = ((volatile gembd_t *)ring->ring) + i;
	int ret = (bd->addr & DESC_RX_CPU_OWN) > 0;
	return ret;
}


static void gem_fillRxDesc(const net_bufdesc_ring_t *ring, size_t i, addr_t pa, size_t sz, unsigned seg)
{
	volatile gembd_t *bd = ((volatile gembd_t *)ring->ring) + i;
	bd->addr = (pa & DESC_RX_ADDR_MASK) | ((i == ring->last) ? DESC_RX_WRAP : 0);
	mbarrier();
}


static int gem_nextTxDone(const net_bufdesc_ring_t *ring, size_t i)
{
	volatile gembd_t *bd = ((volatile gembd_t *)ring->ring) + i;
	return (bd->status & DESC_TX_CPU_OWN) > 0;
}


static void gem_fillTxDesc(const net_bufdesc_ring_t *ring, size_t i, addr_t pa, size_t sz, unsigned seg)
{
	volatile gembd_t *bd = ((volatile gembd_t *)ring->ring) + i;

	bd->addr = pa;
	bd->status = (sz & DESC_TX_SZ_MASK) |
			((i == ring->last) ? DESC_TX_WRAP : 0) |
			((seg & BDRING_SEG_LAST) ? DESC_TX_LAST : 0);
	mbarrier();
}


static const net_bufdesc_ops_t netBufdescOps = {
	.nextRxBufferSize = gem_nextRxBufferSize,
	.pktRxFinished = gem_pktRxFinished,
	.fillRxDesc = gem_fillRxDesc,
	.nextTxDone = gem_nextTxDone,
	.fillTxDesc = gem_fillTxDesc,
	.desc_size = sizeof(gembd_t),
	.pkt_buf_sz = GEM_PACKET_MAX_SIZE,
	.ring_alignment = 64,
	.max_tx_frag = 0xFFFF,
};


static err_t gem_send(struct netif *netif, struct pbuf *p)
{
	gem_t *gem = (gem_t *)netif->state;
	size_t nf;

#if (ETH_PAD_SIZE != 0)
	(void)pbuf_header(p, -ETH_PAD_SIZE); /* drop the padding word (not supported by HW) */
#endif

	/* TODO: I don't think that mutex is needed here, because inside the ringbuffer
	there is another mutex implemented. */
	nf = net_transmitPacket(gem->tx, p);

	if (nf != 0) {

		reg(gem->mmio, NWCTRL) |= NWCTRL_TX_START_PCLK;
	}

	return nf ? ERR_OK : ERR_BUF;
}


static int64_t gem_confParseBase(char *cfg)
{
	char *next;
	int64_t base = strtoul(cfg, &next, 0);

	if ((cfg == next) || (errno == ERANGE)) {
		return -EINVAL;
	}

	return base;
}


static char *gem_confParsePhy(char *cfg)
{
	char *curr;
	char *next = strchr(cfg, ':');

	if (next == NULL) {
		return NULL;
	}

	curr = next + 1;

	if (*curr == '\0') {
		return NULL;
	}

	if (strncmp(curr, "PHY:", 4) == 0) {
		if (*(curr + 4) == '\0') {
			return NULL;
		}

		return curr + 4;
	}
	else {
		return NULL;
	}
}


static int gem_platformConfigClk(gem_t *gem, int speed)
{
	/* TODO: Should GEM number be provided through input command arguments? */
	/* TODO: Should clock config, or at least IOPLL frequency be provided through command arguments? */
	platformctl_t pctl = {
		.type = pctl_devclock,
		.action = pctl_set,
		.devclock = {
			.dev = pctl_devclock_lpd_gem3,
			.src = 0,
			.active = 3,
		}
	};

	/* IOPLL frequency assumption: 1000MHz */
	switch (speed) {
		case 10:
			pctl.devclock.div0 = 50;
			pctl.devclock.div1 = 8;
			break;
		case 100:
			pctl.devclock.div0 = 10;
			pctl.devclock.div1 = 4;
			break;
		case 1000:
			pctl.devclock.div0 = 4;
			pctl.devclock.div1 = 2;
			break;
		default:
			return -1;
	}

	return platformctl(&pctl);
}


static int gem_platformConfigReset(gem_t *gem)
{
	platformctl_t pctl = {
		.type = pctl_devreset,
		.action = pctl_set,
		.devreset = {
			.dev = pctl_devreset_lpd_gem3,
			.state = 0 }
	};

	return platformctl(&pctl);
}


static int gem_platformConfigRgmii(gem_t *gem)
{
	/* TODO: Shouldn't those pins be passed as input arguments? */
	int ret;

	platformctl_t pctlMio[] = {
		{ .type = pctl_mio, .action = pctl_set, .mio = { .pin = pctl_mio_pin_64, .l0 = 1, .l1 = 0, .l2 = 0, .l3 = 0, .config = 0 } },
		{ .type = pctl_mio, .action = pctl_set, .mio = { .pin = pctl_mio_pin_65, .l0 = 1, .l1 = 0, .l2 = 0, .l3 = 0, .config = 0 } },
		{ .type = pctl_mio, .action = pctl_set, .mio = { .pin = pctl_mio_pin_66, .l0 = 1, .l1 = 0, .l2 = 0, .l3 = 0, .config = 0 } },
		{ .type = pctl_mio, .action = pctl_set, .mio = { .pin = pctl_mio_pin_67, .l0 = 1, .l1 = 0, .l2 = 0, .l3 = 0, .config = 0 } },
		{ .type = pctl_mio, .action = pctl_set, .mio = { .pin = pctl_mio_pin_68, .l0 = 1, .l1 = 0, .l2 = 0, .l3 = 0, .config = 0 } },
		{ .type = pctl_mio, .action = pctl_set, .mio = { .pin = pctl_mio_pin_69, .l0 = 1, .l1 = 0, .l2 = 0, .l3 = 0, .config = 0 } },
		{ .type = pctl_mio, .action = pctl_set, .mio = { .pin = pctl_mio_pin_70, .l0 = 1, .l1 = 0, .l2 = 0, .l3 = 0, .config = 0 } },
		{ .type = pctl_mio, .action = pctl_set, .mio = { .pin = pctl_mio_pin_71, .l0 = 1, .l1 = 0, .l2 = 0, .l3 = 0, .config = 0 } },
		{ .type = pctl_mio, .action = pctl_set, .mio = { .pin = pctl_mio_pin_72, .l0 = 1, .l1 = 0, .l2 = 0, .l3 = 0, .config = 0 } },
		{ .type = pctl_mio, .action = pctl_set, .mio = { .pin = pctl_mio_pin_73, .l0 = 1, .l1 = 0, .l2 = 0, .l3 = 0, .config = 0 } },
		{ .type = pctl_mio, .action = pctl_set, .mio = { .pin = pctl_mio_pin_74, .l0 = 1, .l1 = 0, .l2 = 0, .l3 = 0, .config = 0 } },
		{ .type = pctl_mio, .action = pctl_set, .mio = { .pin = pctl_mio_pin_75, .l0 = 1, .l1 = 0, .l2 = 0, .l3 = 0, .config = 0 } },
	};

	for (int i = 0; i < sizeof(pctlMio) / sizeof(pctlMio[0]); i++) {
		if ((ret = platformctl(&pctlMio[i])) != 0) {
			return ret;
		}
	}

	return ret;
}


static void gem_syncSpeedWithPhy(gem_t *gem)
{
	int speed, fullDuplex;

	speed = ephy_linkSpeed(&gem->phy, &fullDuplex);

	/* Currently I advertise only 10Mbps so I don't care about configuration here .*/
	/* TODO: Real clock synchronization with PHY. */
	(void)speed;
}


static void gem_linkStateSet(void *arg, int state)
{
	struct netif *netif = arg;

	if (state == 0) {
		log("set link down");
		netif_set_link_down(netif);
	}
	else {
		log("set link up");
		gem_syncSpeedWithPhy((gem_t *)netif->state);
		netif_set_link_up(netif);
	}
}


static void gem_run(void *arg)
{
	gem_t *gem = (gem_t *)arg;
	uint32_t ts, rs, irq;
	size_t rxDone;
	int linkState = 0;

	log("gem driver thread started");
	gem_syncSpeedWithPhy(gem);

	while (1) {
		ts = reg(gem->mmio, TXSTATUS);
		reg(gem->mmio, TXSTATUS) = ts;

		rs = reg(gem->mmio, RXSTATUS);
		reg(gem->mmio, RXSTATUS) = rs;

		irq = reg(gem->mmio, IRQSTATUS);
		reg(gem->mmio, IRQSTATUS) = irq;

		if (rs & RXSTATUS_BUFFER_NOT_AVAIL) {
			log("rx status: buffer not available");
		}

		if (rs & RXSTATUS_FRAME_RCVD) {
			rxDone = net_receivePackets(gem->rx, gem->netif, 0);
			if ((rxDone > 0) || (net_rxFullyFilled(gem->rx) == 0)) {
				net_refillRx(gem->rx, ETH_PAD_SIZE);
			}
		}

		if (rs & RXSTATUS_RX_OVERRUN) {
			log("rx status: rx overrun");
		}

		if (rs & RXSTATUS_RESP_NOT_OK) {
			log("rx status: resp not ok");
		}

		if (ts & TXSTATUS_USED_BIT_READ) {
			log("tx status: used bit read");
		}

		if (ts & TXSTATUS_COLLISION) {
			log("tx status: collision");
		}

		if (ts & TXSTATUS_RETRY_LIMIT_EXCEEDED) {
			log("tx status: retry limit exceeded");
		}

		if (ts & TXSTATUS_TRANSMIT_GO) {
			log("tx status: transmit go");
		}

		if (ts & TXSTATUS_AMBA_ERROR) {
			log("tx status: amba error");
		}

		if (ts & TXSTATUS_TRANSMIT_CPLT) {
			log("tx status: transmit completed");
			net_reapTxFinished(gem->tx);
		}

		if (ts & TXSTATUS_TRANSMIT_UNDER_RUN) {
			log("tx status: transmit under run");
		}

		if (ts & TXSTATUS_LATE_COLLISION) {
			log("tx status: late collision");
		}

		if (ts & TXSTATUS_RESP_NOT_OK) {
			log("tx status: resp not ok");
		}

		if (ephy_linkStateGet(&gem->phy) != linkState) {
			if (linkState == 0) {
				linkState = 1;
			}
			else {
				linkState = 0;
			}

			ephy_macInterrupt(&gem->phy);
		}
	}
}


static int gem_init(struct netif *netif, char *cfg)
{
	int ret;
	int64_t gemBase;
	char *phyConf;
	gem_t *gem = (gem_t *)netif->state;
	const size_t bdSize[2] = { BD_RING_SIZE, BD_RING_SIZE };

	if ((netif == NULL) || (cfg == NULL)) {
		log("invalid input arguments");
		return -EINVAL;
	}

	gem->netif = netif;
	gem->netif->linkoutput = gem_send;

	gem->netif->hwaddr[0] = xilinxMac[0];
	gem->netif->hwaddr[1] = xilinxMac[1];
	gem->netif->hwaddr[2] = xilinxMac[2];
	gem->netif->hwaddr[3] = xilinxMac[3];
	gem->netif->hwaddr[4] = xilinxMac[4];
	gem->netif->hwaddr[5] = xilinxMac[5] + 1;

	if ((gemBase = gem_confParseBase(cfg)) <= 0) {
		log("invalid base address in input configuration");
		return -EINVAL;
	}

	if ((phyConf = gem_confParsePhy(cfg)) == NULL) {
		log("invalid phy model in input configuration");
		return -EINVAL;
	}

	if ((gem->mmio = (volatile uint32_t *)physmmap(gemBase, GEM_MMIO_MODULE_SIZE)) == MAP_FAILED) {
		log("failed to map physical registers");
		return -ENOMEM;
	}

	if ((ret = register_mdio_bus(&mdioBusOps, gem)) < 0) {
		log("failed to register mdio bus");
		return ret;
	}

	gem->phy.bus = ret;

	if ((ret = net_initRings(gem->bd, bdSize, 2, &netBufdescOps)) < 0) {
		log("failed to initialize net rings");
		return ret;
	}

	gem->tx = &gem->bd[0];
	gem->rx = &gem->bd[1];

	net_refillRx(gem->rx, ETH_PAD_SIZE);

	/* Have to set wrap bit manually, net_refillRx() is not filling last bd in the first call, and tx is filled only for bds that are about to be sent. */
	((volatile gembd_t *)gem->rx->ring)[BD_RING_SIZE - 1].addr |= (DESC_RX_WRAP);
	((volatile gembd_t *)gem->tx->ring)[BD_RING_SIZE - 1].status |= DESC_TX_WRAP;

	for (int i = 0; i < BD_RING_SIZE; i++) {
		((volatile gembd_t *)gem->tx->ring)[i].status |= (DESC_TX_CPU_OWN);
	}

	/* Secondary queue in GEM has to be correctly terminated. I allocate dummy buffer descriptor for that purpose, I don't know what is the best way to handle that problem. */
	if ((gem->bdSec[0] = (volatile gembd_t *)dmammap(BD_RING_SIZE * sizeof(gembd_t))) == MAP_FAILED) {
		log("failed to allocate memory for dummy tx bd ring");
		return -1;
	}

	if ((gem->bdSec[1] = (volatile gembd_t *)dmammap(BD_RING_SIZE * sizeof(gembd_t))) == MAP_FAILED) {
		log("failed to allocate memory for dummy rx bd ring");
		return -1;
	}

	gem->bdSec[1][0].addr = 0 | DESC_RX_WRAP | DESC_RX_CPU_OWN;
	gem->bdSec[0][0].addr = 0;
	gem->bdSec[0][0].status = DESC_TX_LAST | DESC_TX_WRAP | DESC_TX_CPU_OWN;
	mbarrier();

	if ((ret = gem_platformConfigClk(gem, 10)) < 0) {
		log("failed to configure gem clock");
		return ret;
	}

	if ((ret = gem_platformConfigReset(gem)) < 0) {
		log("failed to configure gem reset");
		return ret;
	}

	if ((ret = gem_platformConfigRgmii(gem)) < 0) {
		log("failed to configure RGMII interface on MIO pins");
		return ret;
	}

	reg(gem->mmio, IRQDISABLE) = 0xFFFFFFFF;
	reg(gem->mmio, RXSTATUS) = 0xFFFFFFFF;
	reg(gem->mmio, TXSTATUS) = 0xFFFFFFFF;
	reg(gem->mmio, RXQPTR) = gem->rx->phys;
	reg(gem->mmio, TXQPTR) = gem->tx->phys;
	reg(gem->mmio, RXQ1PTR) = va2pa((void *)(gem->bdSec[1]));
	reg(gem->mmio, TXQ1PTR) = va2pa((void *)(gem->bdSec[0]));
	reg(gem->mmio, DMACFG) = (reg(gem->mmio, DMACFG) & (~DMACFG_RX_BUF_SIZE_MASK)) | DMACFG_RX_BUF_SIZE_1536;
	reg(gem->mmio, DMACFG) &= (~DMACFG_PACKET_BIG_ENDIAN);
	reg(gem->mmio, NWCFG) |= (NWCFG_FULL_DUPLEX | NWCFG_FCS_REMOVE | NWCFG_COPY_ALL_FRAMES);
	reg(gem->mmio, NWCTRL) |= (NWCTRL_EN_RX | NWCTRL_EN_TX | NWCTRL_CLEAR_STATS);
	reg(gem->mmio, IRQENABLE) |= IRQ_LINK_CHANGE;

	if ((ret = ephy_init(&gem->phy, phyConf, 0, gem_linkStateSet, netif)) < 0) {
		return ret;
	}

	if ((ret = beginthread(gem_run, 1, gem->threadStack, sizeof(gem->threadStack), gem)) != 0) {
		log("failed to start driver thread");
		return ret;
	}

	return 0;
}


static const char *gem_media(struct netif *netif)
{
	gem_t *gem = (gem_t *)netif->state;
	int full_duplex;
	int speed = ephy_linkSpeed(&gem->phy, &full_duplex);

	switch (speed) {
		case 0:
			return "unspecified";
		case 10:
			return full_duplex != 0 ? "10Mbps/Full" : "10Mbps/Half";
		case 100:
			return full_duplex != 0 ? "100Mbps/Full" : "100Mbps/Half";
		case 1000:
			return full_duplex != 0 ? "1000Mbps/Full" : "1000Mbps/Half";
		default:
			return "unrecognized";
	}
}


static netif_driver_t gemDrv = {
	.init = gem_init,
	.name = "zynq",
	.state_sz = sizeof(gem_t),
	.state_align = _Alignof(gem_t),
	.media = gem_media,
};


__constructor__(1000) void register_driver_zynq_gem(void)
{
	register_netif_driver(&gemDrv);
}
