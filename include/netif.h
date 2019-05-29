/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP netif
 *
 * Copyright 2019 Phoenix Systems
 * Author: Kamil Amanowicz
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef PHOENIX_NETIF_H_
#define PHOENIX_NETIF_H_


#include <lwip/netif.h>
#include <lwip/dhcp.h>


#define netif_is_ppp(_netif) (((_netif)->name[0] == 'p') && ((_netif)->name[1] == 'p'))
#define netif_is_tun(_netif) (((_netif)->name[0] == 't') && ((_netif)->name[1] == 'u'))

#ifdef LWIP_DHCP
static inline int netif_is_dhcp(struct netif *netif)
{
		struct dhcp *dhcp;
		dhcp = netif_dhcp_data(netif);
		if (dhcp != NULL && dhcp->pcb_allocated != 0)
			return 1;
		else
			return 0;
}
#endif


#endif
