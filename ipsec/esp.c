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

/** @file esp.c
 *  @brief This module contains the Encapsulating Security Payload code
 *
 *  @author  Niklaus Schild <n.schild@gmx.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 *
 *  <B>IMPLEMENTATION:</B>
 * All functions work in-place (i.g. mainipulate directly the original
 * packet without copying any data). For the encapsulation routine,
 * the caller must ensure that space for the new IP and ESP header are
 * available in front of the packet:
 *
 *  <pre>
 *                              | pointer to packet header
 *     ________________________\/________________________________________________
 *    |          �       �      �                             � padd       � ev. |
 *    | Ethernet � newIP � ESP  �   original (inner) packet   � next-proto � ICV |
 *    |__________�_______�______�_____________________________�____________�_____|
 *    �                         �                             �                  � 
 *    �<-room for new headers-->�                             �<-   room tail  ->� 
 *  </pre>
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.<BR>
 * This file contains code from the OpenSSL Project<BR>
 * portions Copyright (c) 1998-2003 OpenSSL (www.openssl.org)
 *</EM><HR>
 */

#include "esp.h"

#include "aes.h"
#include "debug.h"
#include "des.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"

#include "lwip/udp.h"
#include "lwip/inet_chksum.h"

#include <string.h>
#include <time.h>


u32_t ipsec_esp_bitmap = 0;  /**< save session state to detect replays - must be 32 bits. 
											 *   Note: must be initialized with zero (0x00000000) when
											 *         a new SA is established! */
u32_t ipsec_esp_lastSeq = 0; /**< save session state to detect replays
											 *   Note: must be initialized with zero (0x00000000) when
											 *         a new SA is established! */


/**
 * Decapsulates an IP packet containing an ESP header.
 *
 * @param	packet 	pointer to the ESP header
 * @param 	offset	pointer to the offset which is passed back
 * @param 	len		pointer to the length of the decapsulated packet
 * @param 	sa		pointer to the SA
 * @return IPSEC_STATUS_SUCCESS 	if the packet could be decapsulated properly
 * @return IPSEC_STATUS_FAILURE		if the SA's authentication algorithm was invalid or if ICV comparison failed
 * @return IPSEC_STATUS_BAD_PACKET	if the decryption gave back a strange packet
 */
ipsec_status ipsec_esp_decapsulate(struct ip_hdr *packet, int *offset, int *len, sad_entry_t *sa)
{
	int ret_val = IPSEC_STATUS_NOT_INITIALIZED; /* by default, the return value is undefined */
	u8_t ip_header_len;
	int local_len;
	int payload_offset;
	int payload_len;
	struct ip_hdr *new_ip_packet;
	esp_packet *esp_header;
	u8_t cbc_iv[16];
	unsigned char digest[IPSEC_MAX_AUTHKEY_LEN];


	ip_header_len = (packet->_v_hl & 0x0f) * 4;
	payload_offset = ip_header_len + IPSEC_ESP_HDR_SIZE;
	if (sa->natt_mode == UDP_ENCAP_ESPINUDP)
		payload_offset += sizeof(struct udp_hdr);
	else if (sa->natt_mode == UDP_ENCAP_ESPINUDP_NON_IKE)
		payload_offset += sizeof(struct udp_hdr) + 8;
	payload_len = lwip_ntohs(packet->_len) - payload_offset;
	esp_header = (esp_packet *)((u8_t *)packet + payload_offset - IPSEC_ESP_HDR_SIZE);

	if (sa->auth_alg != SADB_AALG_NONE) {

		/* preliminary anti-replay check (without updating the global sequence number window)     */
		/* This check prevents useless ICV calculation if the Sequence Number is obviously wrong  */
		ret_val = ipsec_check_replay_window(lwip_ntohl(esp_header->sequence), ipsec_esp_lastSeq, ipsec_esp_bitmap);
		if (ret_val != IPSEC_AUDIT_SUCCESS) {
			IPSEC_LOG_AUD(IPSEC_AUDIT_SEQ_MISMATCH, "packet rejected by anti-replay check (lastSeq=%08x, seq=%08x, window size=%d)", ipsec_esp_lastSeq, lwip_ntohl(esp_header->sequence), IPSEC_SEQ_MAX_WINDOW);
			return ret_val;
		}

		/* recalcualte ICV */
		switch (sa->auth_alg) {

			case SADB_AALG_MD5HMAC:
				hmac_md5((unsigned char *)esp_header, payload_len - IPSEC_AUTH_ICV + IPSEC_ESP_HDR_SIZE,
					(unsigned char *)sa->authkey, IPSEC_AUTH_MD5_KEY_LEN, (unsigned char *)&digest);
				ret_val = IPSEC_STATUS_SUCCESS;
				break;
			case SADB_AALG_SHA1HMAC:
				hmac_sha1((unsigned char *)esp_header, payload_len - IPSEC_AUTH_ICV + IPSEC_ESP_HDR_SIZE,
					(unsigned char *)sa->authkey, IPSEC_AUTH_SHA1_KEY_LEN, (unsigned char *)&digest);
				ret_val = IPSEC_STATUS_SUCCESS;
				break;
			case SADB_X_AALG_SHA2_256:
				hmac_sha256((unsigned char *)esp_header, payload_len - IPSEC_AUTH_ICV + IPSEC_ESP_HDR_SIZE,
					(unsigned char *)sa->authkey, IPSEC_AUTH_SHA256_KEY_LEN, (unsigned char *)&digest);
				ret_val = IPSEC_STATUS_SUCCESS;
				break;
			default:
				IPSEC_LOG_ERR(IPSEC_STATUS_FAILURE, "unknown HASH algorithm for this ESP");
				IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "return = %d", IPSEC_STATUS_FAILURE);
				return IPSEC_STATUS_FAILURE;
		}

		/* compare ICV */
		if (memcmp(((char *)esp_header) + IPSEC_ESP_HDR_SIZE + payload_len - IPSEC_AUTH_ICV, digest, IPSEC_AUTH_ICV) != 0) {
			IPSEC_LOG_ERR(IPSEC_STATUS_FAILURE, "ESP ICV does not match");
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "return = %d", IPSEC_STATUS_FAILURE);
			return IPSEC_STATUS_FAILURE;
		}

		/* reduce payload by ICV */
		payload_len -= IPSEC_AUTH_ICV;

		/* post-ICV calculation anti-replay check (this call will update the global sequence number window) */
		ret_val = ipsec_update_replay_window(lwip_ntohl(esp_header->sequence), (u32_t *)&ipsec_esp_lastSeq, (u32_t *)&ipsec_esp_bitmap);
		if (ret_val != IPSEC_AUDIT_SUCCESS) {
			IPSEC_LOG_AUD(IPSEC_AUDIT_SEQ_MISMATCH, "packet rejected by anti-replay update (lastSeq=%08x, seq=%08x, window size=%d)", ipsec_esp_lastSeq, lwip_ntohl(esp_header->sequence), IPSEC_SEQ_MAX_WINDOW);
			return ret_val;
		}
	}


	/* decapsulate the packet according the SA */
	if (sa->enc_alg == SADB_EALG_3DESCBC) {
		/* copy IV from ESP payload */
		memcpy(cbc_iv, ((char *)packet) + payload_offset, IPSEC_ESP_IV_SIZE);

		/* decrypt ESP packet */
		cipher_3des_cbc(((unsigned char *)packet) + payload_offset + IPSEC_ESP_IV_SIZE, payload_len - IPSEC_ESP_IV_SIZE,
			(unsigned char *)sa->enckey, cbc_iv,
			IPSEC_CIPHER_DECRYPT, ((unsigned char *)packet) + payload_offset + IPSEC_ESP_IV_SIZE);
		*offset = payload_offset + IPSEC_ESP_IV_SIZE;
		new_ip_packet = (struct ip_hdr *)((u8_t *)packet + payload_offset + IPSEC_ESP_IV_SIZE);
	}
	else /* if (sa->enc_alg == SADB_X_EALG_AES) */ {
		/* copy IV from ESP payload */
		memcpy(cbc_iv, ((char *)packet) + payload_offset, 16);

		/* decrypt ESP packet */
		ipsec_cipher_aes((u8_t *)packet + payload_offset + 16, payload_len - 16,
			sa->enckey, sa->enckey_len, cbc_iv,
			IPSEC_CIPHER_DECRYPT | AES_CBC, (u8_t *)packet + payload_offset + 16);
		*offset = payload_offset + 16;
		new_ip_packet = (struct ip_hdr *)((u8_t *)packet + payload_offset + 16);
	}


	local_len = lwip_ntohs(new_ip_packet->_len);

	if (local_len < IPSEC_MIN_IPHDR_SIZE) {
		IPSEC_LOG_ERR(IPSEC_STATUS_FAILURE, "decapsulated strange packet");
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "return = %d", IPSEC_STATUS_BAD_PACKET);
		return IPSEC_STATUS_BAD_PACKET;
	}
	*len = local_len;

	sa->seqnum++;
	return IPSEC_STATUS_SUCCESS;
}

/**
 * Encapsulates an IP packet into an ESP packet which will again be added to an IP packet.
 * 
 * @param	packet		pointer to the IP packet 
 * @param 	offset		pointer to the offset which will point to the new encapsulated packet
 * @param 	len			pointer to the length of the new encapsulated packet
 * @param 	sa			pointer to the SA
 * @param 	src_addr	source IP address of the outer IP header
 * @param 	dest_addr	destination IP address of the outer IP header 
 * @return 	IPSEC_STATUS_SUCCESS		if the packet was properly encapsulated
 * @return 	IPSEC_STATUS_TTL_EXPIRED	if the TTL expired
 * @return  IPSEC_STATUS_FAILURE		if the SA contained a bad authentication algorithm
 */
ipsec_status ipsec_esp_encapsulate(struct ip_hdr *packet, int *offset, int *len, sad_entry_t *sa, u32_t src_addr, u32_t dest_addr)
{
	int ret_val = IPSEC_STATUS_NOT_INITIALIZED; /* by default, the return value is undefined */
	u8_t tos;
	int inner_len;
	int payload_offset;
	int payload_len;
	u8_t padd_len;
	char *pos;
	u8_t padd;
	struct ip_hdr *new_ip_header;
	ipsec_esp_header *new_esp_header;
	struct udp_hdr *new_udp_header;
	unsigned char iv[IPSEC_ESP_IV_SIZE] = { 0xD4, 0xDB, 0xAB, 0x9A, 0x9A, 0xDB, 0xD1, 0x94 };
	unsigned char cbc_iv[16];
	unsigned char digest[IPSEC_MAX_AUTHKEY_LEN];


	inner_len = lwip_ntohs(packet->_len);

	/* save TOS from inner header */
	tos = packet->_tos;

	/** @todo fix TTL update and checksum calculation */
	// packet->ttl--;
	// packet->chksum = ip_chksum(packet, sizeof(ip_header));
	if (packet->_ttl == 0) {
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "return = %d", IPSEC_STATUS_TTL_EXPIRED);
		return IPSEC_STATUS_TTL_EXPIRED;
	}

	/* encapsulate the packet according the SA */
	if (sa->enc_alg == SADB_EALG_3DESCBC) {
		/* add padding if needed */
		padd_len = IPSEC_ESP_PADDING - ((inner_len + 2) & (IPSEC_ESP_PADDING - 1));
		pos = (char *)packet + inner_len;
		for (padd = 1; padd <= padd_len; *pos++ = padd++)
			;
		/* append padding length and next protocol field to the payload */
		*pos++ = padd_len;
		/* in tunnel mode the next protocol field is always IP */
		*pos = 0x04;

		/* set new packet header pointers */
		new_esp_header = (ipsec_esp_header *)(((char *)packet) - IPSEC_ESP_IV_SIZE - IPSEC_ESP_HDR_SIZE);
		payload_len = inner_len + IPSEC_ESP_HDR_SIZE + IPSEC_ESP_IV_SIZE + padd_len + 2;

		/* get IV from SA */
		memcpy(cbc_iv, sa->iv, IPSEC_ESP_IV_SIZE);

		/* encrypt ESP packet */
		cipher_3des_cbc((u8_t *)packet, inner_len + padd_len + 2, sa->enckey, cbc_iv, IPSEC_CIPHER_ENCRYPT, (u8_t *)packet);
		/* insert IV in front of packet */
		memcpy(((char *)packet) - IPSEC_ESP_IV_SIZE, iv, IPSEC_ESP_IV_SIZE);
	}
	else /* if (sa->enc_alg == SADB_X_EALG_AES) */ {
		uint8_t iv[21];
		clock_t seed = clock();

		sha1_hash(iv, (uint8_t *)&seed, sizeof(seed));

		/* add padding if needed */
		padd_len = 16 - ((inner_len + 2) & (16 - 1));
		pos = (char *)packet + inner_len;
		for (padd = 1; padd <= padd_len; *pos++ = padd++)
			;
		/* append padding length and next protocol field to the payload */
		*pos++ = padd_len;
		/* in tunnel mode the next protocol field is always IP */
		*pos = 0x04;

		/* set new packet header pointers */
		new_esp_header = (ipsec_esp_header *)(((char *)packet) - 16 - IPSEC_ESP_HDR_SIZE);
		payload_len = inner_len + IPSEC_ESP_HDR_SIZE + 16 + padd_len + 2;
		/* add padding if needed */
		ipsec_cipher_aes((u8_t *)packet, inner_len + padd_len + 2, sa->enckey, sa->enckey_len, (u8_t *)iv,
			IPSEC_CIPHER_ENCRYPT | AES_CBC, (u8_t *)packet);
		/* insert IV in front of packet */
		memcpy(((char *)packet) - 16, iv, 16);
	}

	switch (sa->natt_mode) {
		case 0:
			new_ip_header = (struct ip_hdr *)((char *)new_esp_header - IPSEC_MIN_IPHDR_SIZE);
			new_udp_header = NULL;
			break;
		case UDP_ENCAP_ESPINUDP_NON_IKE:
			new_ip_header = (struct ip_hdr *)((char *)new_esp_header - IPSEC_MIN_IPHDR_SIZE - sizeof(struct udp_hdr) - 8);
			new_udp_header = (void *)(new_ip_header + 1);
			break;
		case UDP_ENCAP_ESPINUDP:
			new_ip_header = (struct ip_hdr *)((char *)new_esp_header - IPSEC_MIN_IPHDR_SIZE - sizeof(struct udp_hdr));
			new_udp_header = (void *)(new_ip_header + 1);
			break;
		default:
			/* BUG */
			return IPSEC_STATUS_BAD_PROTOCOL;
	}

	/* setup ESP header */
	new_esp_header->spi = sa->spi;
	/** 1st packet needs to be sent out with squ = 1 */
	sa->seqnum++;
	new_esp_header->sequence_number = lwip_htonl(sa->seqnum);

	/* calculate the ICV if needed */
	if (sa->auth_alg != 0) {
		switch (sa->auth_alg) {

			case SADB_AALG_MD5HMAC:
				hmac_md5((unsigned char *)new_esp_header, payload_len,
					(unsigned char *)sa->authkey, IPSEC_AUTH_MD5_KEY_LEN, (unsigned char *)&digest);
				ret_val = IPSEC_STATUS_SUCCESS;
				break;
			case SADB_AALG_SHA1HMAC:
				hmac_sha1((unsigned char *)new_esp_header, payload_len,
					(unsigned char *)sa->authkey, IPSEC_AUTH_SHA1_KEY_LEN, (unsigned char *)&digest);
				ret_val = IPSEC_STATUS_SUCCESS;
				break;
			case SADB_X_AALG_SHA2_256:
				hmac_sha256((unsigned char *)new_esp_header, payload_len,
					(unsigned char *)sa->authkey, IPSEC_AUTH_SHA256_KEY_LEN, (unsigned char *)&digest);
				ret_val = IPSEC_STATUS_SUCCESS;
				break;
			default:
				IPSEC_LOG_ERR(IPSEC_STATUS_FAILURE, "unknown HASH algorithm for this ESP");
				IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "return = %d", IPSEC_STATUS_FAILURE);
				return IPSEC_STATUS_FAILURE;
		}

		/* set ICV */
		memcpy(((char *)new_esp_header) + payload_len, digest, IPSEC_AUTH_ICV);

		/* increase payload by ICV */
		payload_len += IPSEC_AUTH_ICV;
	}

	payload_offset = (char *)packet - (char *)new_ip_header;

	/* setup optional UDP header */
	if (new_udp_header) {
		memset(new_udp_header, 0, (char *)new_esp_header - (char *)new_udp_header);
		new_udp_header->src = sa->natt_sport;
		new_udp_header->dest = sa->natt_dport;
		new_udp_header->len = lwip_htons((char *)new_esp_header + payload_len - (char *)new_udp_header);
	}

	/* setup return values */
	*offset = -payload_offset;
	*len = (char *)new_esp_header + payload_len - (char *)new_ip_header;

	/* setup IP header */
	new_ip_header->_v_hl = 0x45;
	new_ip_header->_tos = tos;
	new_ip_header->_len = lwip_htons(*len);
	new_ip_header->_id = 0;
	new_ip_header->_offset = 0;
	new_ip_header->_ttl = 64;
	new_ip_header->_proto = sa->natt_mode ? IP_PROTO_UDP : IP_PROTO_ESP;
	new_ip_header->_chksum = 0;
	new_ip_header->src.addr = src_addr;
	new_ip_header->dest.addr = dest_addr;

	/* set checksum */
	IPH_CHKSUM_SET(new_ip_header, inet_chksum(new_ip_header, IP_HLEN));

	return ret_val;
}
