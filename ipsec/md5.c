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

/** @file md5.c
 *  @brief RFC 1321 - The MD5 Message-Digest Algorithm and RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
 *
 *  @author  Christian Scheurer <http://www.christianscheurer.ch> <BR>
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.<BR>
 * This file contains code from the OpenSSL Project<BR>
 * portions Copyright (c) 1998-2003 OpenSSL (www.openssl.org)
 *</EM><HR>
 */

#include "md5.h"

#include "debug.h"
#include "md5_imp.h"

#include <string.h>


/**
 * RFC 2104 hmac_md5 function calculates a digest from a given data buffer and a given key.
 *
 * @param text		pointer to data stream
 * @param text_len	length of data stream
 * @param key		pointer to authentication key
 * @param key_len	length of authentication key
 * @param digest	caller digest to be filled in 128-bit
 * @return void
 *
 */
void hmac_md5(unsigned char *text, int text_len, unsigned char *key, int key_len, unsigned char *digest)
{
	md5_context_t context;
	unsigned char k_ipad[64]; /* inner padding - key XORd with ipad */
	unsigned char k_opad[64]; /* outer padding - key XORd with opad */
	unsigned char tk[16];     /* L=16 for MD5 (RFC 2141, 2. Definition of HMAC) */
	int i;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, "text=%p, text_len=%d, key=%p, key_len=%d, digest=%p",
		text, text_len, key, key_len, digest);


	/* if key is longer than 64 bytes reset it to key=MD5(key) */
	if (key_len > 64) {

		md5_context_t tctx;

		ipsec_md5_init(&tctx);
		ipsec_md5_update(&tctx, key, key_len);
		ipsec_md5_final(tk, &tctx);

		key = tk;
		key_len = 16;
	}

	/*
     * the HMAC_MD5 transform looks like:
     *
     * MD5(K XOR opad, MD5(K XOR ipad, text))
     *
     * where K is an n byte key
     * ipad is the byte 0x36 repeated 64 times
     * opad is the byte 0x5c repeated 64 times
     * and text is the data being protected
     */

	/* start out by storing key in pads */
	memset(k_ipad, 0x36, sizeof(k_ipad));
	memset(k_opad, 0x5c, sizeof(k_opad));


	/* XOR key with ipad and opad values */
	for (i = 0; i < key_len; i++) {
		k_ipad[i] ^= key[i];
		k_opad[i] ^= key[i];
	}
	/*
     * perform inner MD5
     */
	ipsec_md5_init(&context);                   /* init context for 1st
                                          * pass */
	ipsec_md5_update(&context, k_ipad, 64);     /* start with inner pad */
	ipsec_md5_update(&context, text, text_len); /* then text of datagram */
	ipsec_md5_final(digest, &context);          /* finish up 1st pass */
	/*
     * perform outer MD5
     */
	ipsec_md5_init(&context);               /* init context for 2nd
                                          * pass */
	ipsec_md5_update(&context, k_opad, 64); /* start with outer pad */
	ipsec_md5_update(&context, digest, 16); /* then results of 1st
                                          * hash */
	ipsec_md5_final(digest, &context);      /* finish up 2nd pass */

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "void");
}
