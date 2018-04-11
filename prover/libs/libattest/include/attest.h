#pragma once
#ifndef __ATTEST_H__
#define __ATTEST_H_

typedef enum {AES_128, AES_192, AES_256, SHA_256, SIMON, SPECK, BLAKE2S} hmac_type;

uint64_t MAC(const uint8_t *block, unsigned int block_size, const uint8_t *key, const unsigned int key_size, hmac_type fn, uint8_t digest[32]);

uint64_t MAC_with_params(const uint32_t* params, const unsigned int num_params,
    const uint8_t* str, const unsigned int str_len, 
    const uint8_t *key, const unsigned int key_size, hmac_type fn, uint8_t digest[32]);


#endif
