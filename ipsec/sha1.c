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

/** @file sha1.c
 *  @brief RFC 3174 - US Secure Hash Algorithm 1 (SHA1) and RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
 *
 *  @author  Christian Scheurer <http://www.christianscheurer.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 *   RFC3174 (US Secure Hash Algorithm 1 (SHA1)) implementation.
 *   Requires Infineon C167 MCU and Keil C166 compiler.
 *
 *  <B>IMPLEMENTATION:</B>
 * "This product includes cryptographic software written by
 * Eric Young (eay@cryptsoft.com)" (taken form www.openssl.org)"
 *
 *  <B>NOTES:</B>
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.<BR>
 * This file contains code from the OpenSSL Project<BR>
 * portions Copyright (c) 1998-2003 OpenSSL (www.openssl.org)</EM><HR>
 */

#include "sha1.h"

#include "sha1_imp.h"

#include <string.h>


/*
 * Function: RFC 2104 hmac_sha1 
 *
 *   unsigned char*  text          pointer to data stream
 *   int             text_len      length of data stream
 *   unsigned char*  key           pointer to authentication key
 *   int             key_len       length of authentication key
 *   unsigned char*  digest        caller digest to be filled in
 *
 */
void hmac_sha1(unsigned char *text, int text_len, unsigned char *key, int key_len, unsigned char *digest)
{
	sha1_context_t context;
	unsigned char k_ipad[65]; /* inner padding - key XORd with ipad */
	unsigned char k_opad[65]; /* outer padding - key XORd with opad */
	int i;

	/* if key is longer than 64 bytes reset it to key=SHA1(key) */
	if (key_len > 64) {

		sha1_context_t tctx;

		sha1_init(&tctx);
		sha1_write(&tctx, key, key_len);
		sha1_final(&tctx);

		memcpy(key, tctx.buf, 20);
		key_len = 20;
	}

	/*
     * the HMAC_SHA1 transform looks like:
     *
     * SHA1(K XOR opad, SHA1(K XOR ipad, text))
     *
     * where K is an n byte key
     * ipad is the byte 0x36 repeated 64 times
     * opad is the byte 0x5c repeated 64 times
     * and text is the data being protected
     */

	/* start out by storing key in pads */
	memset(k_ipad, '\0', sizeof(k_ipad));
	memset(k_opad, '\0', sizeof(k_opad));
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);


	/* XOR key with ipad and opad values */
	for (i = 0; i < 64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}
	/*
     * perform inner SHA
     */
	sha1_init(&context);                  /* init context for 1st pass */
	sha1_write(&context, k_ipad, 64);     /* start with inner pad */
	sha1_write(&context, text, text_len); /* then text of datagram */
	sha1_final(&context);                 /* finish up 1st pass */
	memcpy(digest, context.buf, 20);

	/*
     * perform outer SHA
     */
	sha1_init(&context);              /* init context for 2nd pass */
	sha1_write(&context, k_opad, 64); /* start with outer pad */
	sha1_write(&context, digest, 20); /* then results of 1st hash */
	sha1_final(&context);             /* finish up 2nd pass */
	memcpy(digest, context.buf, 20);
}
