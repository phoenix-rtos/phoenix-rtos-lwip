/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/**
  @file sha256.c
  LTC_SHA256 by Tom St Denis
*/
#include "sha256.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <sys/minmax.h>
#include <endian.h>


#if __BYTE_ORDER == __BIG_ENDIAN

#define STORE32H(x, y) \
	do { \
		(y)[0] = (unsigned char)(((x) >> 24) & 255); \
		(y)[1] = (unsigned char)(((x) >> 16) & 255); \
		(y)[2] = (unsigned char)(((x) >> 8) & 255); \
		(y)[3] = (unsigned char)((x)&255); \
	} while (0)

#define LOAD32H(x, y) \
	do { \
		x = ((uint32_t)((y)[0] & 255) << 24) | \
			((uint32_t)((y)[1] & 255) << 16) | \
			((uint32_t)((y)[2] & 255) << 8) | \
			((uint32_t)((y)[3] & 255)); \
	} while (0)

#define STORE64H(x, y) \
	do { \
		(y)[0] = (unsigned char)(((x) >> 56) & 255); \
		(y)[1] = (unsigned char)(((x) >> 48) & 255); \
		(y)[2] = (unsigned char)(((x) >> 40) & 255); \
		(y)[3] = (unsigned char)(((x) >> 32) & 255); \
		(y)[4] = (unsigned char)(((x) >> 24) & 255); \
		(y)[5] = (unsigned char)(((x) >> 16) & 255); \
		(y)[6] = (unsigned char)(((x) >> 8) & 255); \
		(y)[7] = (unsigned char)((x)&255); \
	} while (0)

#elif __BYTE_ORDER == __LITTLE_ENDIAN

#ifdef LTC_HAVE_BSWAP_BUILTIN

#define STORE32H(x, y) \
	do { \
		uint32_t __t = __builtin_bswap32((x)); \
		memcpy((y), &__t, 4); \
	} while (0)

#define LOAD32H(x, y) \
	do { \
		memcpy(&(x), (y), 4); \
		(x) = __builtin_bswap32((x)); \
	} while (0)

#define STORE64H(x, y) \
	do { \
		uint64_t __t = __builtin_bswap64((x)); \
		memcpy((y), &__t, 8); \
	} while (0)

#else

#define STORE32H(x, y) \
	do { \
		(y)[0] = (unsigned char)(((x) >> 24) & 255); \
		(y)[1] = (unsigned char)(((x) >> 16) & 255); \
		(y)[2] = (unsigned char)(((x) >> 8) & 255); \
		(y)[3] = (unsigned char)((x)&255); \
	} while (0)

#define LOAD32H(x, y) \
	do { \
		x = ((uint32_t)((y)[0] & 255) << 24) | \
			((uint32_t)((y)[1] & 255) << 16) | \
			((uint32_t)((y)[2] & 255) << 8) | \
			((uint32_t)((y)[3] & 255)); \
	} while (0)

#define STORE64H(x, y) \
	do { \
		(y)[0] = (unsigned char)(((x) >> 56) & 255); \
		(y)[1] = (unsigned char)(((x) >> 48) & 255); \
		(y)[2] = (unsigned char)(((x) >> 40) & 255); \
		(y)[3] = (unsigned char)(((x) >> 32) & 255); \
		(y)[4] = (unsigned char)(((x) >> 24) & 255); \
		(y)[5] = (unsigned char)(((x) >> 16) & 255); \
		(y)[6] = (unsigned char)(((x) >> 8) & 255); \
		(y)[7] = (unsigned char)((x)&255); \
	} while (0)

#endif

#else /* __BYTE_ORDER */

#error "Unsupported byte order"

#endif

/* Various logical functions */
#define Ch(x, y, z)  (z ^ (x & (y ^ z)))
#define Maj(x, y, z) (((x | y) & z) | (x & y))
#define RORc(x, y)   (((((uint32_t)(x)&0xFFFFFFFFUL) >> (uint32_t)((y)&31)) | ((uint32_t)(x) << (uint32_t)((32 - ((y)&31)) & 31))) & 0xFFFFFFFFUL)
#define S(x, n)      RORc((x), (n))
#define R(x, n)      (((x)&0xFFFFFFFFUL) >> (n))
#define Sigma0(x)    (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)    (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)    (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)    (S(x, 17) ^ S(x, 19) ^ R(x, 10))


struct sha256_state {
	uint64_t length;
	uint32_t state[8], curlen;
	uint8_t buf[64];
};

typedef struct Hash_state {
	struct sha256_state sha256;
} hash_state;

/* compress 512-bits */
static int sha256_compress(hash_state *md, unsigned char *buf)
{
	uint32_t S[8], W[64], t0, t1;
	int i;

	/* copy state into S */
	for (i = 0; i < 8; i++) {
		S[i] = md->sha256.state[i];
	}

	/* copy the state into 512-bits into W[0..15] */
	for (i = 0; i < 16; i++) {
		LOAD32H(W[i], buf + (4 * i));
	}

	/* fill W[16..63] */
	for (i = 16; i < 64; i++) {
		W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
	}

	/* Compress */
#define RND(a, b, c, d, e, f, g, h, i, ki) \
	t0 = h + Sigma1(e) + Ch(e, f, g) + ki + W[i]; \
	t1 = Sigma0(a) + Maj(a, b, c); \
	d += t0; \
	h = t0 + t1;

	RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 0, 0x428a2f98);
	RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 1, 0x71374491);
	RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 2, 0xb5c0fbcf);
	RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 3, 0xe9b5dba5);
	RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 4, 0x3956c25b);
	RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 5, 0x59f111f1);
	RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 6, 0x923f82a4);
	RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 7, 0xab1c5ed5);
	RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 8, 0xd807aa98);
	RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 9, 0x12835b01);
	RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 10, 0x243185be);
	RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 11, 0x550c7dc3);
	RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 12, 0x72be5d74);
	RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 13, 0x80deb1fe);
	RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 14, 0x9bdc06a7);
	RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 15, 0xc19bf174);
	RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 16, 0xe49b69c1);
	RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 17, 0xefbe4786);
	RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 18, 0x0fc19dc6);
	RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 19, 0x240ca1cc);
	RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 20, 0x2de92c6f);
	RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 21, 0x4a7484aa);
	RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 22, 0x5cb0a9dc);
	RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 23, 0x76f988da);
	RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 24, 0x983e5152);
	RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 25, 0xa831c66d);
	RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 26, 0xb00327c8);
	RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 27, 0xbf597fc7);
	RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 28, 0xc6e00bf3);
	RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 29, 0xd5a79147);
	RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 30, 0x06ca6351);
	RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 31, 0x14292967);
	RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 32, 0x27b70a85);
	RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 33, 0x2e1b2138);
	RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 34, 0x4d2c6dfc);
	RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 35, 0x53380d13);
	RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 36, 0x650a7354);
	RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 37, 0x766a0abb);
	RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 38, 0x81c2c92e);
	RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 39, 0x92722c85);
	RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 40, 0xa2bfe8a1);
	RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 41, 0xa81a664b);
	RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 42, 0xc24b8b70);
	RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 43, 0xc76c51a3);
	RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 44, 0xd192e819);
	RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 45, 0xd6990624);
	RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 46, 0xf40e3585);
	RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 47, 0x106aa070);
	RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 48, 0x19a4c116);
	RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 49, 0x1e376c08);
	RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 50, 0x2748774c);
	RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 51, 0x34b0bcb5);
	RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 52, 0x391c0cb3);
	RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 53, 0x4ed8aa4a);
	RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 54, 0x5b9cca4f);
	RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 55, 0x682e6ff3);
	RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 56, 0x748f82ee);
	RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 57, 0x78a5636f);
	RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 58, 0x84c87814);
	RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 59, 0x8cc70208);
	RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 60, 0x90befffa);
	RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 61, 0xa4506ceb);
	RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 62, 0xbef9a3f7);
	RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 63, 0xc67178f2);

#undef RND


	/* feedback */
	for (i = 0; i < 8; i++) {
		md->sha256.state[i] = md->sha256.state[i] + S[i];
	}
	return EOK;
}

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return EOK if successful
*/
static int sha256_init(hash_state *md)
{
	md->sha256.curlen = 0;
	md->sha256.length = 0;
	md->sha256.state[0] = 0x6A09E667UL;
	md->sha256.state[1] = 0xBB67AE85UL;
	md->sha256.state[2] = 0x3C6EF372UL;
	md->sha256.state[3] = 0xA54FF53AUL;
	md->sha256.state[4] = 0x510E527FUL;
	md->sha256.state[5] = 0x9B05688CUL;
	md->sha256.state[6] = 0x1F83D9ABUL;
	md->sha256.state[7] = 0x5BE0CD19UL;
	return EOK;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return EOK if successful
*/
static int sha256_update(hash_state *md, const uint8_t *in, size_t inlen)
{
	unsigned long n;
	int err;

	if (md->sha256.curlen > sizeof(md->sha256.buf)) {
		return -EINVAL;
	}
	if ((md->sha256.length + inlen) < md->sha256.length) {
		return -E2BIG;
	}
	while (inlen > 0) {
		if (md->sha256.curlen == 0 && inlen >= 64) {
			if ((err = sha256_compress(md, (unsigned char *)in)) != EOK) {
				return err;
			}
			md->sha256.length += 64 * 8;
			in += 64;
			inlen -= 64;
		}
		else {
			n = min(inlen, (64 - md->sha256.curlen));
			memcpy(md->sha256.buf + md->sha256.curlen, in, (size_t)n);
			md->sha256.curlen += n;
			in += n;
			inlen -= n;
			if (md->sha256.curlen == 64) {
				if ((err = sha256_compress(md, md->sha256.buf)) != EOK) {
					return err;
				}
				md->sha256.length += 8 * 64;
				md->sha256.curlen = 0;
			}
		}
	}
	return EOK;
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (32 bytes)
   @return EOK if successful
*/
static int sha256_final(hash_state *md, uint8_t *out)
{
	int i;

	if (md->sha256.curlen >= sizeof(md->sha256.buf))
		return -EINVAL;

	/* increase the length of the message */
	md->sha256.length += md->sha256.curlen * 8;

	/* append the '1' bit */
	md->sha256.buf[md->sha256.curlen++] = (unsigned char)0x80;

	/* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
	if (md->sha256.curlen > 56) {
		while (md->sha256.curlen < 64) {
			md->sha256.buf[md->sha256.curlen++] = (unsigned char)0;
		}
		sha256_compress(md, md->sha256.buf);
		md->sha256.curlen = 0;
	}

	/* pad up to 56 bytes of zeroes */
	while (md->sha256.curlen < 56) {
		md->sha256.buf[md->sha256.curlen++] = (unsigned char)0;
	}

	/* store length */
	STORE64H(md->sha256.length, md->sha256.buf + 56);
	sha256_compress(md, md->sha256.buf);

	/* copy output */
	for (i = 0; i < 8; i++) {
		STORE32H(md->sha256.state[i], out + (4 * i));
	}
	return EOK;
}

#if 0
/**
  Self-test the hash
  @return EOK if successful, CRYPT_NOP if self-tests have been disabled
*/
int sha256_test(void)
{
	static const struct {
		char *msg;
		unsigned char hash[32];
	} tests[] = {
		{ "abc",
			{ 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
				0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
				0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
				0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad } },
		{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			{ 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
				0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
				0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
				0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1 } },
	};

	int i;
	unsigned char tmp[32];
	hash_state md;

	for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
		sha256_init(&md);
		sha256_update(&md, (unsigned char *)tests[i].msg, (unsigned long)strlen(tests[i].msg));
		sha256_final(&md, tmp);
		if (memcmp(tmp, tests[i].hash, sizeof(tests[i].hash)) != 0) {
			return -1;
		}
	}
	return EOK;
}
#endif

void hmac_sha256(const unsigned char *text, int text_len, const unsigned char *key, int key_len, unsigned char *digest)
{
	hash_state context;
	unsigned char k_ipad[64]; /* inner padding - key XORd with ipad */
	unsigned char k_opad[64]; /* outer padding - key XORd with opad */
	unsigned char tk[32];     /* L=32 for MD5 (RFC 2141, 2. Definition of HMAC) */
	int i;

	/* if key is longer than 64 bytes reset it to key=MD5(key) */
	if (key_len > 64) {
		sha256_init(&context);
		sha256_update(&context, key, key_len);
		sha256_final(&context, tk);

		key = tk;
		key_len = sizeof(tk);
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
	sha256_init(&context);                   /* init context for 1st pass */
	sha256_update(&context, k_ipad, 64);     /* start with inner pad */
	sha256_update(&context, text, text_len); /* then text of datagram */
	sha256_final(&context, digest);          /* finish up 1st pass */
	/*
     * perform outer MD5
     */
	sha256_init(&context);               /* init context for 2nd pass */
	sha256_update(&context, k_opad, 64); /* start with outer pad */
	sha256_update(&context, digest, 32); /* then results of 1st pass */
	sha256_final(&context, digest);      /* finish up 2nd pass */
}

#if 0
int hmac_sha256_test(void)
{
	static const struct {
		unsigned char key[32];
		const char *msg;
		unsigned char hash[32];
	} tests[] = {
		{ { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			  0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b },
			"Hi There",
			{ 0x19, 0x8a, 0x60, 0x7e, 0xb4, 0x4b, 0xfb, 0xc6, 0x99, 0x03, 0xa0, 0xf1, 0xcf, 0x2b, 0xbd, 0xc5,
				0xba, 0x0a, 0xa3, 0xf3, 0xd9, 0xae, 0x3c, 0x1c, 0x7a, 0x3b, 0x16, 0x96, 0xa0, 0xb6, 0x8c, 0xf7 } },
		{ { 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
			  0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65 },
			"what do ya want for nothing?",
			{ 0x16, 0x7f, 0x92, 0x85, 0x88, 0xc5, 0xcc, 0x2e, 0xef, 0x8e, 0x30, 0x93, 0xca, 0xa0, 0xe8, 0x7c,
				0x9f, 0xf5, 0x66, 0xa1, 0x47, 0x94, 0xaa, 0x61, 0x64, 0x8d, 0x81, 0x62, 0x1a, 0x2a, 0x40, 0xc6 } },
	};

	int i;
	unsigned char mac[32];

	for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
		hmac_sha256((const uint8_t *)tests[i].msg, strlen(tests[i].msg), tests[i].key, 32, mac);
		if (memcmp(mac, tests[i].hash, sizeof(tests[i].hash)) != 0) {
			return -1;
		}
	}
	return EOK;
}
#endif
