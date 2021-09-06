/*
 * embedded IPsec
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 */

/** @file ipsecdev.h
 *  @brief Header of IPsec network adapter for lwIP
 *
 *  @author Christian Scheurer <http://www.christianscheurer.ch>
 *
 *
 *  <B>OUTLINE:</B>
 *
 *  This network interface will be inserted between the TCP/IP stack and the
 *  driver of the physical network adapter. With this, all inbound and outbound
 *  traffic can be intercepted and forwarded to the IPsec stack if required.
 *
 *  <B>IMPLEMENTATION:</B>
 *
 *  The main duty of ipsecdev device is to identify the network traffic and
 *  forward it to the appropriate protocol handler:
 *
 *     - AH/ESP => forward to ipsec_input()
 *     - IP traffic with policy BYPASS => forward to ip_input()
 *     - IP traffic with policy DISCARD, or traffic with policy APPLY but without
 *       IPsec header
 *
 *  To decide how packets must be processed, a lookup in the Security Policy
 *  Database is required. With this, all IPsec logic and IPsec related processing
 *  is put outside ipsecdev. The motivation is to separate IPsec processing from
 *  TCP/IP-Stack and network driver peculiarities.
 *  If the ipsec stack need to be ported to an other target, all major changes
 *  can be done in this module while the rest can be left untouched.
 *
 *  <B>NOTES:</B>
 *
 * This version of ipsecdev is able to handle traffic passed by a cs8900 driver
 * in combination with lwIP 0.6.3 STABLE. It has a similar structure as dumpdev
 * or cs9800if.
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */


#ifndef __IPSECDEV_H__
#define __IPSECDEV_H__

#include "sa.h"

#include "lwip/def.h"


db_set_netif *ipsecdev_dbsget(void);
void ipsecdev_enable(void);
void ipsecdev_disable(void);
u32_t ipsecdev_getIP(void);
int ipsecdev_attach(const char *dev);

#endif
