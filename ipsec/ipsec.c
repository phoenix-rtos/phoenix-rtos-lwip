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

/** @file ipsec.c
 *  @brief embedded IPsec implementation (tunnel mode with manual keying only)
 *
 *  @author Christian Scheurer <http://www.christianscheurer.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 *
 * The different IPsec functions are glued together at this place. All intercepted
 * inbound and outbound traffic which require IPsec processing is passed to this module. 
 * The packets are then processed processes according their SA.
 *
 *  <B>IMPLEMENTATION:</B>
 *  
 * For SA management code of the sa.c module was used. Then AH and ESP functionality out of
 * ah.c and esp.c was used to process the packets properly.
 *
 *  <B>NOTES:</B>
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */

#include "ipsec.h"

#include "ah.h"
#include "debug.h"
#include "esp.h"
#include "sa.h"

#include "lwip/prot/ip.h"


int ipsec_input(unsigned char *packet, int packet_size, int *payload_offset, int *payload_size, struct db_set_netif_s *databases)
{
	sad_entry_t *sa;
	spd_entry_t *spd;
	struct ip_hdr *ip, *inner_ip;
	int ret_val;

	ip = (struct ip_hdr *)packet;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, "proto=%u", ip->_proto);

	if (ip->_proto == IP_PROTO_UDP)
		sa = ipsec_sad_lookup_natt(ip, &databases->inbound_sad);
	else
		sa = ipsec_sad_lookup(ip->src, ip->_proto, ipsec_sad_get_spi(ip), &databases->inbound_sad);

	if (sa == NULL) {
		if (ip->_proto != IP_PROTO_UDP)
			IPSEC_LOG_AUD(IPSEC_AUDIT_FAILURE, "no matching SA found");
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "return = %d", IPSEC_STATUS_NO_SA_FOUND);
		return IPSEC_STATUS_NO_SA_FOUND;
	}

	if (sa->mode != IPSEC_MODE_TUNNEL) {
		IPSEC_LOG_ERR(IPSEC_STATUS_FAILURE, "unsupported transmission mode (only IPSEC_TUNNEL is supported)");
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "return = %d", IPSEC_STATUS_FAILURE);
		return IPSEC_STATUS_FAILURE;
	}

	if (sa->proto == IP_PROTO_AH) {
		ret_val = ipsec_ah_check((struct ip_hdr *)packet, payload_offset, payload_size, sa);
		if (ret_val != IPSEC_STATUS_SUCCESS) {
			IPSEC_LOG_ERR(ret_val, "ah_packet_check() failed");
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ret_val(ah)=%d", ret_val);
			return ret_val;
		}
	}
	else if (sa->proto == IP_PROTO_ESP) {
		ret_val = ipsec_esp_decapsulate((struct ip_hdr *)packet, payload_offset, payload_size, sa);
		if (ret_val != IPSEC_STATUS_SUCCESS) {
			IPSEC_LOG_ERR(ret_val, "ipsec_esp_decapsulate() failed");
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ret_val(esp)=%d", ret_val);
			return ret_val;
		}
	}
	else {
		IPSEC_LOG_ERR(IPSEC_STATUS_FAILURE, "invalid protocol from SA");
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ret_val=%d", IPSEC_STATUS_FAILURE);
		return IPSEC_STATUS_FAILURE;
	}

	inner_ip = (struct ip_hdr *)(((unsigned char *)ip) + *payload_offset);

	spd = ipsec_spd_lookup(inner_ip, &databases->inbound_spd, IPSEC_MATCH_BOTH);
	if (spd == NULL) {
		IPSEC_LOG_AUD(IPSEC_AUDIT_FAILURE, "no matching SPD found");
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ret_val=%d", IPSEC_STATUS_FAILURE);
		return IPSEC_STATUS_FAILURE;
	}

	if (spd->policy != IPSEC_POLICY_IPSEC) {
		IPSEC_LOG_AUD(IPSEC_AUDIT_POLICY_MISMATCH, "matching SPD does not permit IPsec processing | src %08x dst %08x proto %u",
			lwip_ntohl(inner_ip->src.addr), lwip_ntohl(inner_ip->dest.addr), inner_ip->_proto);
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "return = %d", IPSEC_STATUS_FAILURE);
		return IPSEC_STATUS_FAILURE;
	}

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "return = %d", IPSEC_STATUS_SUCCESS);
	return IPSEC_STATUS_SUCCESS;
}


int ipsec_output(unsigned char *packet, int packet_size, int *payload_offset, int *payload_size,
	ip_addr_t src, struct sad_entry_s *sa)
{
	int ret_val = IPSEC_STATUS_NOT_INITIALIZED; /* by default, the return value is undefined */
	struct ip_hdr *ip;

	ip = (struct ip_hdr *)packet;

	if ((ip == NULL) || (lwip_ntohs(ip->_len) > packet_size)) {
		IPSEC_LOG_DBG(IPSEC_STATUS_NOT_IMPLEMENTED, "bad packet ip=%p, ip->len=%d (must not be >%d bytes)",
			(void *)ip, ip ? lwip_ntohs(ip->_len) : 0, packet_size);

		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "return = %d", IPSEC_STATUS_BAD_PACKET);
		return IPSEC_STATUS_BAD_PACKET;
	}

	if (sa == NULL) {
		/** @todo invoke IKE to generate a proper SA for this SPD entry */
		IPSEC_LOG_DBG(IPSEC_STATUS_NOT_IMPLEMENTED, "unable to generate dynamically an SA (IKE not implemented)");

		IPSEC_LOG_AUD(IPSEC_STATUS_NO_SA_FOUND, "no SA or SPD defined");
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "return = %d", IPSEC_STATUS_NO_SA_FOUND);
		return IPSEC_STATUS_NO_SA_FOUND;
	}

	switch (sa->proto) {
		case IP_PROTO_AH:
			ret_val = ipsec_ah_encapsulate((struct ip_hdr *)packet, payload_offset, payload_size, sa, src.addr, sa->addr.addr);

			if (ret_val != IPSEC_STATUS_SUCCESS) {
				IPSEC_LOG_ERR(ret_val, "ipsec_ah_encapsulate() failed");
			}
			break;

		case IP_PROTO_ESP:
			ret_val = ipsec_esp_encapsulate((struct ip_hdr *)packet, payload_offset, payload_size, sa, src.addr, sa->addr.addr);

			if (ret_val != IPSEC_STATUS_SUCCESS) {
				IPSEC_LOG_ERR(ret_val, "ipsec_esp_encapsulate() failed");
			}
			break;

		default:
			ret_val = IPSEC_STATUS_BAD_PROTOCOL;
			IPSEC_LOG_ERR(ret_val, "unsupported protocol '%d' in spd->sa->protocol", sa->proto);
	}
	return ret_val;
}
