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

/** @file util.c
 *  @brief A collection of common helper functions and macros 
 *         used everywhere in the IPsec library
 *
 *  @author Niklaus Schild <n.schild@gmx.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 *  The following functions are implemented in this module:
 *   - logging
 *
 *  <B>IMPLEMENTATION:</B>
 *
 *  There are no implementation hints to be mentioned.
 *
 *  <B>NOTES:</B>
 *
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.<BR>
 * This file contains code from the lwIP project by Adam Dunkels and others<BR>
 * Copyright (c) 2001, 2002 Swedish Institute of Computer Science.<BR>
 * All rights reserved.</EM><HR>
 */

#include <string.h>
#include <ipv4/lwip/inet.h>
#include <lwip/ip.h>

#include "ipsec.h"
#include "util.h"
#include "debug.h"

/**
 * Prints the header of an IP packet
 *
 * @param header pointer to an IP header
 * @return void
 */
void ipsec_print_ip(struct ip_hdr *header)
{
	char log_message[IPSEC_LOG_MESSAGE_SIZE + 1];
	char port[4 + 1];
	char src[15 + 1];
	char dest[15 + 1];
	u16_t len;

	strcpy(src, inet_ntoa(header->src));
	strcpy(dest, inet_ntoa(header->dest));

	len = lwip_ntohs(header->_len);

	switch (IPH_PROTO(header)) {
		case IP_PROTO_TCP:
			strcpy(port, " TCP");
			break;
		case IP_PROTO_UDP:
			strcpy(port, " UDP");
			break;
		case IP_PROTO_AH:
			strcpy(port, "  AH");
			break;
		case IP_PROTO_ESP:
			strcpy(port, " ESP");
			break;
		case IP_PROTO_ICMP:
			strcpy(port, "ICMP");
			break;
		default:
			strcpy(port, "????");
	}

	main_snprintf(log_message, IPSEC_LOG_MESSAGE_SIZE, "src: %15s dest: %15s protocol: %3s size: %d", src, dest, port, len);
	main_printf(ATTR_INFO, "          %s\n", log_message);

	return;
}


#ifdef IPSEC_TRACE
int __ipsec_trace_indication = 0;      /**< dummy variable to avoid compiler warnings */
int __ipsec_trace_indication__pos = 0; /**< dummy variable to avoid compiler warnings */
#endif

/**
 * Dump (print) a memory location
 *
 * @param prefix print this text at the beginning of each line
 * @param data pointer the buffer which should be printed
 * @param offs offset from the buffer's start address
 * @param length number of bytes to be printed
 *              initialized with IP, netmask and gateway address.
 * @return void
 */
void ipsec_dump_buffer(char *prefix, unsigned char *data, int offs, int length)
{
	unsigned char *ptr;
	unsigned char *tmp_ptr;
	int i;

	main_printf(ATTR_INFO, "%sDumping %d bytes from address 0x%p using an offset of %d bytes\n", prefix, length, data, offs);
	if (length == 0) {
		main_printf(ATTR_INFO, "%s => nothing to dump\n", prefix);
		return;
	}

	for (ptr = (data + offs); ptr < (data + offs + length); ptr++) {
		if (((ptr - (data + offs)) % 16) == 0)
			main_printf(ATTR_INFO, "%s%p:", prefix, ptr);
		main_printf(ATTR_INFO, " %02x", *ptr);
		if (((ptr - (data + offs)) % 16) == 15) {
			main_printf(ATTR_INFO, " :");
			for (tmp_ptr = (ptr - 15); tmp_ptr < ptr; tmp_ptr++) {
				if (*tmp_ptr < 32)
					main_printf(ATTR_INFO, ".");
				else
					main_printf(ATTR_INFO, "%c", *tmp_ptr);
			}
			main_printf(ATTR_INFO, "\n");
		}
	}

	if ((length % 16) > 0) {
		for (i = 0; i < (16 - (length % 16)); i++) {
			main_printf(ATTR_INFO, "   ");
		}

		main_printf(ATTR_INFO, " :");
		for (tmp_ptr = ((data + offs + length) - (length % 16)); tmp_ptr < (data + offs + length); tmp_ptr++) {
			if (*tmp_ptr < 32)
				main_printf(ATTR_INFO, ".");
			else
				main_printf(ATTR_INFO, "%c", *tmp_ptr);
		}
	}

	main_printf(ATTR_INFO, "\n");
}


/**
 * Verify the sequence number of the AH packet is inside the window (defined as IPSEC_SEQ_MAX_WINDOW)
 * Note: this function does NOT update the lastSeq variable and may
 *       safely be called prior to IVC check.
 *
 * @param  seq       sequence number of the current packet
 * @param  lastSeq   sequence number of the last known packet
 * @param  bitField  field used to verify resent data within the window
 * @return IPSEC_AUDIT_SUCCESS if check passed (packet allowed)
 * @return IPSEC_AUDIT_SEQ_MISMATCH if check failed (packet disallowed)
 */
ipsec_audit ipsec_check_replay_window(u32_t seq, u32_t lastSeq, u32_t bitField)
{
#if 0
    u32_t diff;

    if(seq == 0) return IPSEC_AUDIT_SEQ_MISMATCH;    /* first == 0 or wrapped */
    
    if(seq > lastSeq) 					/* new larger sequence number  */
    {  
        diff = seq - lastSeq;

	    /* only accept new number if delta is not > IPSEC_SEQ_MAX_WINDOW */
	    if(diff >= IPSEC_SEQ_MAX_WINDOW) return IPSEC_AUDIT_SEQ_MISMATCH;
    }
    else {								/* new smaller sequence number */
    	diff = lastSeq - seq;

	    /* only accept new number if delta is not > IPSEC_SEQ_MAX_WINDOW */
	    if(diff >= IPSEC_SEQ_MAX_WINDOW) return IPSEC_AUDIT_SEQ_MISMATCH;

	    /* already seen */
	    if(bitField & ((u32_t)1 << diff)) return IPSEC_AUDIT_SEQ_MISMATCH; 
    }
#endif
	return IPSEC_AUDIT_SUCCESS;
}


/**
 * Verify and update the sequence number.
 * Note: this function is UPDATING the lastSeq variable and must be called
 *       only AFTER checking the IVC.
 *
 * This  code  is  based  on  RFC2401,  Appendix  C  --  Sequence  Space  Window  Code  Example 
 *
 * @param  seq       sequence number of the current packet
 * @param  lastSeq   pointer to sequence number of the last known packet
 * @param  bitField  pointer to field used to verify resent data within the window
 * @return IPSEC_AUDIT_SUCCESS if check passed (packet allowed)
 * @return IPSEC_AUDIT_SEQ_MISMATCH if check failed (packet disallowed)
 */
ipsec_audit ipsec_update_replay_window(u32_t seq, u32_t *lastSeq, u32_t *bitField)
{
#if 0 
    u32_t diff;

    if (seq == 0) return IPSEC_AUDIT_SEQ_MISMATCH;     	/* first == 0 or wrapped 	*/
    if (seq > *lastSeq) {               		/* new larger sequence number 		*/
        diff = seq - *lastSeq;
        if (diff < IPSEC_SEQ_MAX_WINDOW) {  	/* In window */
            *bitField <<= diff;
            *bitField |= 1;	         			/* set bit for this packet 			*/
        } else *bitField = 1;					/* This packet has a "way larger" 	*/
        *lastSeq = seq;
        return IPSEC_AUDIT_SUCCESS;  			/* larger is good */
    }
    diff = *lastSeq - seq;
    if (diff >= IPSEC_SEQ_MAX_WINDOW) return IPSEC_AUDIT_SEQ_MISMATCH; /* too old or wrapped */
    if (*bitField & ((u32_t)1 << diff)) return IPSEC_AUDIT_SEQ_MISMATCH; /* already seen 	*/
    *bitField |= ((u32_t)1 << diff);      		/* mark as seen 			*/
#endif
	return IPSEC_AUDIT_SUCCESS; /* out of order but good 	*/
}
