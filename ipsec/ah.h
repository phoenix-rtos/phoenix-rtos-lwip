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

/** @file ah.h
 *  @brief Header of IP Authentication Header (AH)
 *
 *  @author Christian Scheurer <http://www.christianscheurer.ch>
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.<BR>
 * This file contains code from the OpenSSL Project<BR>
 * portions Copyright (c) 1998-2003 OpenSSL (www.openssl.org)
 *</EM><HR>
 */

#ifndef __AH_H__
#define __AH_H__

#include "ipsec.h"
#include "sa.h"

#include "lwip/def.h"


#define IPSEC_AH_HDR_SIZE (12) /**< AH header size without ICV */


typedef struct ah_hdr_struct {
	u8_t nexthdr;                 /**< type of next payload (protocol nr) */
	u8_t len;                     /**< type of service */
	u16_t reserved;               /**< MUST be 0x0000 (reserved for future use) */
	u32_t spi;                    /**< Security Parameter Index (0, 1..255 are special cases RFC2402, p.4) */
	u32_t sequence;               /**< sequence number (increasing strictly), used by anti-replay feature */
	u8_t ah_data[IPSEC_AUTH_ICV]; /**< ICV (Integrity Check Value), variable-length data. 12 bytes (96 bits) for HMAC-SHA1-96 and HMAC-MD5-96 */
} ipsec_ah_header;


extern u32_t ipsec_ah_bitmap;  /**< bitmap used for anti-replay service */
extern u32_t ipsec_ah_lastSeq; /**< last seen sequence number, used for anit-replay service */

int ipsec_ah_check(struct ip_hdr *, int *, int *, sad_entry_t *);
int ipsec_ah_encapsulate(struct ip_hdr *, int *, int *, sad_entry_t *, u32_t, u32_t);

#endif
