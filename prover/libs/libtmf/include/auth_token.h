//
// Created by oak on 11/12/17.
//

#include <stdint.h>
#include <crypto-ed25519/libed25519/ed25519.h>
#include <sha/hmac-sha256.h>

#ifndef _AUTH_TOKEN_H_H
#define _AUTH_TOKEN_H_H



#pragma pack(push, 1)
typedef struct AuthToken {
    uint32_t version;
    uint64_t uuid;
    // TODO: constraint
    uint32_t key_id;
    uint8_t sig_alg;
    uint16_t ts[9];
    uint32_t ls[9];
    uint8_t sig[64];

} AuthToken_t;

typedef struct SecContHeader {
    uint32_t aes_version;
    uint8_t aes_iv[16];
    uint16_t ts[4];
    uint32_t ls[4];
    uint8_t digest[32];
} SecContHeader_t;
#pragma pack(pop)

int verify_authtoken(AuthToken_t token, uint8_t pk[32]);

int verify_seccont(SecContHeader_t header, uint8_t mac_key[32]);

#endif //_AUTH_TOKEN_H_H
