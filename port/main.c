/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer - TCP/IP thread wrapper
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "lwipopts.h"

#include "lwip/sockets.h"

#include <string.h>
#include <sys/msg.h>
#include <posix/utils.h>
#include <syslog.h>

#include "netif-driver.h"
#include "route.h"
#include "filter.h"
#include "devs.h"
#include "wifi-api.h"
#include "ipsec-api.h"


static void mainLoop(void)
{
	msg_t msg = { 0 };
	msg_rid_t rid;
	unsigned port;

	if (portCreate(&port) < 0) {
		printf("phoenix-rtos-lwip: can't create port\n");
		return;
	}

	if (devs_init(port) < 0)
		return;

	for (;;) {
		if (msgRecv(port, &msg, &rid) < 0)
			continue;

		switch (msg.type) {
			case mtOpen:
				msg.o.io.err = dev_open(msg.i.openclose.oid.id, msg.i.openclose.flags);
				break;

			case mtClose:
				msg.o.io.err = dev_close(msg.i.openclose.oid.id);
				break;

			case mtRead:
				msg.o.io.err = dev_read(msg.i.openclose.oid.id, msg.o.data, msg.o.size, msg.i.io.offs);
				break;

			case mtWrite:
				msg.o.io.err = dev_write(msg.i.openclose.oid.id, msg.i.data, msg.i.size, msg.i.io.offs);
				break;

			default:
				break;
		}

		msgRespond(port, &msg, rid);
	}
}


int main(int argc, char **argv)
{
	size_t have_intfs = 0;

	openlog("lwip", LOG_NDELAY, LOG_DAEMON);

#ifndef HAVE_WORKING_INIT_ARRAY
	void init_lwip_tcpip(void);
	void init_lwip_sockets(void);
	void register_driver_rtl(void);
	void register_driver_enet(void);
	void register_driver_pppos(void);
	void register_driver_pppou(void);
	void register_driver_tun(void);
	void register_driver_tap(void);

	init_lwip_tcpip();
	init_lwip_sockets();
#ifdef HAVE_DRIVER_rtl
	register_driver_rtl();
#endif
#ifdef HAVE_DRIVER_enet
	register_driver_enet();
#endif
#ifdef HAVE_DRIVER_pppos
	register_driver_pppos();
#endif
#ifdef HAVE_DRIVER_pppou
	register_driver_pppou();
#endif
#ifdef HAVE_DRIVER_tuntap
	register_driver_tun();
	register_driver_tap();
#endif
#endif

	route_init();

#if LWIP_EXT_PF
	init_filters();
#endif

#if LWIP_WIFI
	init_wifi();
#endif

	while (++argv, --argc) {
		int err = create_netif(*argv);

		if (!err)
			++have_intfs;
		else
			printf("phoenix-rtos-lwip: can't init netif from cfg \"%s\": %s\n", *argv, strerror(err));
	}

	/* printf("netsrv: %zu interface%s\n", have_intfs, have_intfs == 1 ? "" : "s"); */
	if (!have_intfs)
		exit(1);

#if LWIP_IPSEC
	ipsecdev_attach(LWIP_IPSEC_DEV);
#endif

	mainLoop();

	return 1;
}
