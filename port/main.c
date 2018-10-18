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
#include "arch/cc.h"
#include "lwip/tcpip.h"
#include "netif-driver.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


int main(int argc, char **argv)
{
	size_t have_intfs = 0;

#ifndef HAVE_WORKING_INIT_ARRAY
	void init_lwip_tcpip(void);
	void init_lwip_sockets(void);
	void register_driver_rtl(void);
	void register_driver_enet(void);
	void register_driver_pppos(void);

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
#endif

	while (++argv, --argc) {
		int err = create_netif(*argv);

		if (!err)
			++have_intfs;
		else
			printf("can't init netif from cfg \"%s\": %s\n", *argv, strerror(err));
	}

	printf("netsrv: %zu interface%s\n", have_intfs, have_intfs == 1 ? "" : "s");
	if (!have_intfs)
		exit(1);

	for (;;)
		usleep(120000000);
}
