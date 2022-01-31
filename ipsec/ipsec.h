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

/** @file ipsec.h
 *  @brief Header of embedded IPsec implementation
 *
 *  @author Christian Scheurer <http://www.christianscheurer.ch> 
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */


#ifndef __IPSEC_H__
#define __IPSEC_H__

#include <phoenix/ipsec.h>

#include "lwip/ip_addr.h"


#define IPSEC_HLEN (PBUF_IP_HLEN + 28 + PBUF_TRANSPORT_HLEN) /**< Add room for an other IP header and AH(28 bytes with HMAC-xxx-96)/ESP(8 bytes) data */

#define IPSEC_DES_KEY_LEN    (8)                     /**< Defines the size of a DES key in bytes */
#define IPSEC_3DES_KEY_LEN   (IPSEC_DES_KEY_LEN * 3) /**< Defines the length of a 3DES key in bytes */
#define IPSEC_AES_KEY_LEN    (32)
#define IPSEC_MAX_ENCKEY_LEN (IPSEC_AES_KEY_LEN) /**< Defines the maximum encryption key length of our IPsec system */

#define IPSEC_AUTH_ICV            (16)                        /**< Defines the authentication key length in bytes (12 bytes for 96bit keys) */
#define IPSEC_AUTH_MD5_KEY_LEN    (16)                        /**< Length of MD5 secret key  */
#define IPSEC_AUTH_SHA1_KEY_LEN   (20)                        /**< Length of SHA1 secret key */
#define IPSEC_AUTH_SHA256_KEY_LEN (32)                        /**< Length of SHA1 secret key */
#define IPSEC_MAX_AUTHKEY_LEN     (IPSEC_AUTH_SHA256_KEY_LEN) /**< Maximum length of authentication keys */

#define IPSEC_MIN_IPHDR_SIZE (20) /**< Defines the minimum IP header size (in bytes).*/
#define IPSEC_SEQ_MAX_WINDOW (32) /**< Defines the maximum window for Sequence Number checks (used as anti-replay protection) */
#define IPSEC_CIPHER_ENCRYPT (0x1000)
#define IPSEC_CIPHER_DECRYPT (0x0000)

struct sad_entry_s;
struct db_set_netif_s;

/**
 * IPsec input processing
 *
 * This function is called by the ipsec device driver when a packet arrives having AH or ESP in the
 * protocol field. A SA lookup gets the appropriate SA which is then passed to the packet processing
 * function ipsec_ah_check() or ipsec_esp_decapsulate(). After successfully processing an IPsec packet
 * an check together with an SPD lookup verifies if the packet was processed according the right SA.
 *
 * @param  packet         pointer used to access the intercepted original packet
 * @param  packet_size    length of the intercepted packet
 * @param  payload_offset pointer used to return offset of the new IP packet relative to original packet pointer
 * @param  payload_size   pointer used to return total size of the new IP packet
 * @param  databases      Collection of all security policy databases for the active IPsec device
 * @return int 			  return status code
 */

int ipsec_input(unsigned char *, int, int *, int *, struct db_set_netif_s *);


/**
 *  IPsec output processing
 *
 * This function is called when outbound packets need IPsec processing. Depending the SA, passed via
 * the SPD entry ipsec_ah_check() and ipsec_esp_encapsulate() is called to encapsulate the packet in a
 * IPsec header.
 *
 * @param  packet         pointer used to access the intercepted original packet
 * @param  packet_size    length of the intercepted packet
 * @param  payload_offset pointer used to return offset of the new IP packet relative to original packet pointer
 * @param  payload_size   pointer used to return total size of the new IP packet
 * @param  src            IP address of the local tunnel start point (external IP address)
 * @param  dst            IP address of the remote tunnel end point (external IP address)
 * @param  spd            pointer to security policy database where the rules for IPsec processing are stored
 * @return int 			  return status code
 */

int ipsec_output(unsigned char *, int, int *, int *, ip_addr_t, struct sad_entry_s *);

#endif
