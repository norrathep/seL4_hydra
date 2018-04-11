#ifndef __AES_CBC_H
#define __AES_CBC_H

#include <aes/rijndael-alg-fst.h>
#include <stdint.h>

#define AES_BLOCK_SIZE 16

void AES_cbc_encrypt(const uint8_t *in, uint8_t out[16], size_t len, const uint32_t *key, const unsigned int nr,
                       uint8_t *ivec, const int enc);
void cbc_mac_aes(const uint8_t *in, uint8_t *out, size_t len,
	const uint8_t rkey[32], const unsigned int key_size);

#endif /* __AES_CBC_H */
