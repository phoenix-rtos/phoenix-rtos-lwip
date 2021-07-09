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

#include "ipsec.h"
#include "util.h"
#include "debug.h"

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
#define HEXFMT_1  " %02x"
#define HEXFMT_4  HEXFMT_1 HEXFMT_1 HEXFMT_1 HEXFMT_1
#define HEXFMT_16 HEXFMT_4 HEXFMT_4 HEXFMT_1 HEXFMT_1
#define TXTFMT_1  " %c"
#define TXTFMT_4  TXTFMT_1 TXTFMT_1 TXTFMT_1 TXTFMT_1
#define TXTFMT_16 TXTFMT_4 TXTFMT_4 TXTFMT_4 TXTFMT_4
#define HEX_1(i)  ptr[i]
#define HEX_4(i)  HEX_1(i), HEX_1(i + 1), HEX_1(i + 2), HEX_1(i + 3)
#define HEX_16(i) HEX_4(i), HEX_4(i + 4), HEX_4(i + 8), HEX_4(i + 12)
#define TXT_1(i)  (ptr[i] < 32 ? '.' : ptr[i])
#define TXT_4(i)  TXT_1(i), TXT_1(i + 1), TXT_1(i + 2), TXT_1(i + 3)
#define TXT_16(i) TXT_4(i), TXT_4(i + 4), TXT_4(i + 8), TXT_4(i + 12)
	unsigned char *ptr;
	unsigned int i, r;
	char hex_buf[46];
	char txt_buf[31];
	char *buf_ptr;

	IPSEC_LOG_MSG("%sDumping %d bytes from address 0x%p using an offset of %d bytes", prefix, length, data, offs);
	if (length == 0) {
		IPSEC_LOG_MSG("%s => nothing to dump", prefix);
		return;
	}

	for (ptr = (data + offs); ptr < (data + offs + length); ptr += 16) {
		IPSEC_LOG_MSG("%s%p:" HEXFMT_16 " :" TXTFMT_16, prefix, ptr, HEX_16(0), TXT_16(0));
	}

	r = length % 16;
	if (r > 0) {
		ptr -= r;
		buf_ptr = hex_buf;
		for (i = 0; i < r; ++i)
			buf_ptr += sprintf(buf_ptr, HEXFMT_1, ptr[i]);
		buf_ptr = txt_buf;
		for (i = 0; i < r; ++i)
			buf_ptr += sprintf(buf_ptr, TXTFMT_1, ptr[i]);
		IPSEC_LOG_MSG("%s%p:%s :%s", prefix, ptr, hex_buf, txt_buf);
	}
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
