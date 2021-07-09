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

/** @file util.h
 *  @brief Header of common helper functions and macros
 *
 *  @author Niklaus Schild <n.schild@gmx.ch>
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.<BR>
 * This file contains code from the lwIP project by Adam Dunkels and others<BR>
 * Copyright (c) 2001, 2002 Swedish Institute of Computer Science.<BR>
 * All rights reserved.</EM><HR>
 */

#ifndef __UTIL_H__
#define __UTIL_H__

#include <lwip/ip4.h>


/** 
 * IP related stuff
 *
 */


#define IPSEC_IP4_ADDR(a, b, c, d) ((u32_t)(d & 0xff) << 24) | ((u32_t)(c & 0xff) << 16) | ((u32_t)(b & 0xff) << 8) | (u32_t)(a & 0xff)

#define ipsec_ip_addr_maskcmp(addr1, addr2, mask) ((addr1 & mask) == (addr2 & mask))
#define ipsec_ip_addr_cmp(addr1, addr2)           (addr1 == addr2)

/** return code convention:
 *
 *  return code < 0 indicates globally defines error messages
 *  return code == 0 indicates success
 *  return code > 0 is used as error count (i.e. "return 20;" means there are 20 errors)
 *
 */
typedef enum ipsec_status_list {        /** This value is returned if ... */
	IPSEC_STATUS_SUCCESS = 0,           /**<  processing was successful */
	IPSEC_STATUS_NOT_IMPLEMENTED = -1,  /**<  the function is already there but the functionality is not yet implemented */
	IPSEC_STATUS_FAILURE = -2,          /**<  failure */
	IPSEC_STATUS_DATA_SIZE_ERROR = -3,  /**<  buffer is (unexpectedly) empty or haves wrong size */
	IPSEC_STATUS_NO_SPACE_IN_SPD = -4,  /**<  ipsec_spd_add() failed because there was no space left in SPD */
	IPSEC_STATUS_NO_POLICY_FOUND = -5,  /**<  no matching SPD policy was found */
	IPSEC_STATUS_NO_SA_FOUND = -6,      /**<  no matching SA was found */
	IPSEC_STATUS_BAD_PACKET = -7,       /**<  packet has a bad format or invalid fields */
	IPSEC_STATUS_BAD_PROTOCOL = -8,     /**<  SA has an unsupported protocol */
	IPSEC_STATUS_BAD_KEY = -9,          /**<  key is invalid or weak and was rejected */
	IPSEC_STATUS_TTL_EXPIRED = -10,     /**<  TTL value of a packet reached 0 */
	IPSEC_STATUS_NOT_INITIALIZED = -100 /**<  variables has never been initialized */
} ipsec_status;


typedef enum ipsec_audit_list {      /** This value is returned if ... */
	IPSEC_AUDIT_SUCCESS = 0,         /**<  processing was successful */
	IPSEC_AUDIT_NOT_IMPLEMENTED = 1, /**<  the function is already there but the functionality is not yet implemented */
	IPSEC_AUDIT_FAILURE = 2,         /**<  failure  */
	IPSEC_AUDIT_APPLY = 3,           /**<  packet must be processed by IPsec */
	IPSEC_AUDIT_BYPASS = 4,          /**<  packet is forwarded (without IPsec processing) */
	IPSEC_AUDIT_DISCARD = 5,         /**<  packet must be dropped */
	IPSEC_AUDIT_SPI_MISMATCH = 6,    /**<  SPI does not match the SPD lookup */
	IPSEC_AUDIT_SEQ_MISMATCH = 7,    /**<  Sequence Number differs more than IPSEC_SEQ_MAX_WINDOW from the previous packets */
	IPSEC_AUDIT_POLICY_MISMATCH = 8  /**<  If a policy for an incoming IPsec packet does not specify APPLY */
} ipsec_audit;


void ipsec_dump_buffer(char *, unsigned char *, int, int);

ipsec_audit ipsec_check_replay_window(u32_t seq, u32_t lastSeq, u32_t bitField);
ipsec_audit ipsec_update_replay_window(u32_t seq, u32_t *lastSeq, u32_t *bitField);


#endif
