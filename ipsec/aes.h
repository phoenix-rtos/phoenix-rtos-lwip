/* 
 * File:   aes.h
 *
 * AES Cryptographic Algorithm Header File. Include this header file in
 * your source which uses these given APIs. (This source is kept under
 * public domain)
 *
 * from http://embeddedknowledge.blogspot.com/2012/03/optimized-aes-source-code-for-embedded.html
 */

#ifndef _IPSEC_AES_H_
#define _IPSEC_AES_H_

#include <stdint.h>
#include <stddef.h>


typedef struct {
	unsigned int Ek[60];
	unsigned int Dk[60];
	unsigned int Iv[4];
	unsigned char Nr;
	unsigned char Mode;
} AES_ctx_t;


#define AES_128     16
#define AES_192     24
#define AES_256     32
#define AES_BLOCKSZ 16
#define AES_EBC     0
#define AES_CBC     1


extern int AES_init(AES_ctx_t *ctx, unsigned char *pIV, unsigned char *pKey, size_t KeyLen, int Mode);
extern int AES_encrypt(AES_ctx_t *ctx, unsigned char *plain, unsigned char *cipher, size_t len);
extern int AES_decrypt(AES_ctx_t *ctx, unsigned char *cipher, unsigned char *plain, size_t len);
extern void ipsec_cipher_aes(uint8_t *text, const size_t text_len, const uint8_t *key, const size_t key_len,
	const uint8_t *iv, const int mode, uint8_t *output);

#endif /* _IPSEC_AES_H_ */
