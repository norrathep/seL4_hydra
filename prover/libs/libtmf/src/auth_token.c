//
// Created by oak on 11/12/17.
//

#include <auth_token.h>
#include <memory.h>

int verify_authtoken(AuthToken_t token, uint8_t pk[32]) {
    uint64_t unused;
    return ed25519_verify((const unsigned char *)token.sig, (const unsigned char *)&token.version, sizeof(AuthToken_t)-64, pk, &unused);
}

int verify_seccont(SecContHeader_t header, uint8_t mac_key[32]) {
    uint8_t digest[32] = {0};
    hmac_sha256_get(digest, (const uint8_t*)&header.aes_version, sizeof(SecContHeader_t)-32, mac_key, 32);
    return memcmp(digest, header.digest, 32);


}