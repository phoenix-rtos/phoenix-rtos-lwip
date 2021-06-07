/*
 * Phoenix-RTOS --- networking stack
 *
 * Ethernet PHY common routines
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * %LICENSE%
 */
#include "ephy.h"
#include "gpio.h"
#include "netif-driver.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/msg.h>
#include <sys/threads.h>


//#define EPHY_KSZ8081RND


static uint16_t ephy_reg_read(eth_phy_state_t *phy, uint16_t reg)
{
	return mdio_read(phy->bus, phy->addr, reg);
}


static void ephy_reg_write(eth_phy_state_t *phy, uint16_t reg, uint16_t val)
{
	mdio_write(phy->bus, phy->addr, reg, val);
	ephy_reg_read(phy, reg);
}


static void ephy_reset(eth_phy_state_t *phy)
{
	if (gpio_valid(&phy->reset)) {
		// TODO: prepare bootstrap pins
		gpio_set(&phy->reset, 1);
		usleep(phy->reset_hold_time_us);
		mdio_lock_bus(phy->bus);
		gpio_set(&phy->reset, 0);
		usleep(phy->reset_release_time_us);
		mdio_unlock_bus(phy->bus);
	} else {
		int err = 0, n = 10;

		ephy_reg_write(phy, 0, 0x8000);
		usleep(phy->reset_release_time_us);

		while (n--) {
			err = ephy_reg_read(phy, 0);
			if (~err & 0x8000)
				break;
		}

		if (err & 0x8000)
			printf("lwip: ephy%u.%u soft-reset timed out\n", phy->bus, phy->addr);
	}
}


static uint32_t ephy_show_id(eth_phy_state_t *phy)
{
	uint32_t oui = 0;
	uint32_t phyid = 0;
	uint16_t ret;

	ret = ephy_reg_read(phy, 0x02);
	phyid = ret << 16;
	oui |= ret << 2;

	ret = ephy_reg_read(phy, 0x03);
	phyid |= ret;
	oui |= (ret & 0xFC00) << (18-10);

/*
	printf("lwip: ephy%u.%u id 0x%08x (vendor 0x%06x model 0x%02x rev %u)\n",
		phy->bus, phy->addr, phyid, oui, (ret >> 4) & 0x3F, ret & 0x0F);
*/

	oui = ephy_reg_read(phy, 0x10);
	ret = ephy_reg_read(phy, 0x11);

/*
	printf("lwip: ephy%u.%u DigCtl 0x%04x AFECtl1 0x%04x\n",
		phy->bus, phy->addr, oui, ret);
*/

	return phyid;
}


static void ephy_show_link_state(eth_phy_state_t *phy)
{
	uint16_t bctl, bstat, adv, lpa, pc1, pc2;
	int speed, full_duplex;

	bctl = ephy_reg_read(phy, 0x00);
	bstat = ephy_reg_read(phy, 0x01);
	bstat = ephy_reg_read(phy, 0x01);
	adv = ephy_reg_read(phy, 0x04);
	lpa = ephy_reg_read(phy, 0x05);
	pc1 = ephy_reg_read(phy, 0x1e);
	pc2 = ephy_reg_read(phy, 0x1f);
	speed = ephy_link_speed(phy, &full_duplex);

	int linkup = (bstat & 4) != 0;

	if (phy->link_state_callback)
		phy->link_state_callback(phy->link_state_callback_arg, linkup);


	printf("lwip: ephy%u.%u link is %s %uMbps/%s (ctl %04x, status %04x, adv %04x, lpa %04x, pctl %04x,%04x)\n",
		phy->bus, phy->addr, linkup ? "UP  " : "DOWN", speed, full_duplex ? "Full" : "Half",
		bctl, bstat, adv, lpa, pc1, pc2);
}


int ephy_link_speed(eth_phy_state_t *phy, int *full_duplex)
{
	uint16_t pc1 = ephy_reg_read(phy, 0x1e);

	if (!(pc1 & 7))
		return 0;

	*full_duplex = pc1 & 4;
	return pc1 & 1 ? 10 : 100;
}


static void ephy_restart_an(eth_phy_state_t *phy)
{
	// adv: no-next-page, no-rem-fault, no-pause, no-T4, 100M/10M-FD & 10M-HD, 802.3
	ephy_reg_write(phy, 4, 0x0161);
	// 100M-FD, AN, restart-AN
	ephy_reg_write(phy, 0, 0x3300);
}


/* link-detect thread */
static void ephy_link_thread(void *arg)
{
	eth_phy_state_t *phy = arg;
	int stat;

	for (;;) {
		gpio_wait(&phy->irq_gpio, 1, 0);
		// FIXME: thread exit

		stat = ephy_reg_read(phy, 0x1b);
		if (stat >= 0 && (stat & 0xFF)) {
			/*printf("ephy%u.%u: irq status = 0x%04x\n", phy->bus, phy->addr, stat);*/
			ephy_show_link_state(phy);
		}
	}

	printf("lwip ephy%u.%u thread finished.\n", phy->bus, phy->addr);
	endthread();
}


// ARGS: pfx[-]n:/dev/gpioX[:...]
static char *parse_pin_arg(char *cfg, const char *pfx, size_t pfx_len, gpio_info_t *pin, unsigned flags)
{
	char *p;
	int err;

	if (strncmp(pfx, cfg, pfx_len))
		return cfg;
	cfg += pfx_len;

	p = strchr(cfg, ':');
	if (!p) {
		printf("ephy: %s missing pin GPIO node\n", pfx);
		return cfg - pfx_len;
	}
	p = strchr(p + 1, ':');
	if (p)
		*p++ = 0;

	err = gpio_init(pin, cfg, flags);
	if (err) {
		printf("ephy: %s bad pin info: %s (%d)\n", pfx, strerror(err), err);
		return cfg - pfx_len;
	}

	return p;
}


// printf("This is an Ethernet PHY driver. use: %s id mdio-bus phy-addr [irq=[-]n,/dev/gpio/X] [reset=[-]n,/dev/gpio/X]\n", argv[0]);
// ARGS: [bus.]id[:reset:[-]n:/dev/gpioX][:irq:[-]n:/dev/gpioX]

static int ephy_config(eth_phy_state_t *phy, char *cfg)
{
	char *p;

	if (!*cfg)
		return -EINVAL;

	/*printf("ephy: config: %s\n", cfg);*/

	phy->addr = strtoul(cfg, &p, 0);
	if (*p == '.') {
		phy->bus = phy->addr;
		cfg = ++p;

		if (!*cfg)
			return -EINVAL;

		phy->addr = strtoul(cfg, &p, 0);
	} else
		phy->bus = 0;

	if (phy->addr & ~NETDEV_MDIO_ADDR_MASK) {
		printf("ephy: bad PHY address: 0x%x (valid bits: 0x%x)\n", phy->addr, NETDEV_MDIO_ADDR_MASK);
		return -EINVAL;
	}

	if (!*p)
		return 0;

	if (*p++ != ':')
		return -EINVAL;

	while (p && *p) {
		cfg = p;

		p = parse_pin_arg(p, "irq:", 4, &phy->irq_gpio, GPIO_INPUT);
		if (p == cfg)
			p = parse_pin_arg(p, "reset:", 6, &phy->reset, GPIO_OUTPUT | GPIO_ACTIVE);
		if (p == cfg) {
			printf("ephy: unparsed args: %s\n", cfg);
			return -EINVAL;
		}
	}

	return 0;
}

int ephy_init(eth_phy_state_t *phy, char *conf, link_state_cb_t cb, void *cb_arg)
{
	uint32_t phyid;
	int err;

	memset(phy, 0, sizeof(*phy));

	if (ephy_config(phy, conf))
		return -EINVAL;

	/* for KSZ8081RNA/D, KSZ8081RNB:
	 * MDC max. 10MHz, std. 2.5MHz
	 * MDIO hold min. 10 ns
	 * preamble mandatory
	 */

	phy->reset_hold_time_us = 500 /* us */;
	phy->reset_release_time_us = 100 /* us */;

	if ((err = mdio_setup(phy->bus, 2500 /* kHz */, 10 /* ns */, 0 /* with-preamble */)))
		return err;

	ephy_reset(phy);

	phyid = ephy_show_id(phy);
	if (!phyid || !~phyid) {
		gpio_set(&phy->reset, 1);
		return -ENODEV;
	}

	// FIXME: check phyid

	/* make address 0 not broadcast, disable NAND-tree mode */
	ephy_reg_write(phy, 0x16, 0x0202);

#ifndef EPHY_KSZ8081RND
	/* 50MHz RMII clock; keep auto-MDI-X */
	ephy_reg_write(phy, 0x1f, 0x8180);
#endif

	phy->link_state_callback = cb;
	phy->link_state_callback_arg = cb_arg;
	ephy_show_link_state(phy);

	if (gpio_valid(&phy->irq_gpio)) {
		if ((err = beginthread(ephy_link_thread, 0, phy->th_stack, sizeof(phy->th_stack), phy))) {
			gpio_set(&phy->reset, 1);
			return err;
		}

		// enable link up/down IRQ signal
		ephy_reg_write(phy, 0x1b, 0x0500);
	}

	ephy_restart_an(phy);

	return 0;
}
