#ifndef ED25519_H
#define ED25519_H

#include <stddef.h>
#include <inttypes.h>

#if defined(_WIN32)
    #if defined(ED25519_BUILD_DLL)
        #define ED25519_DECLSPEC __declspec(dllexport)
    #elif defined(ED25519_DLL)
        #define ED25519_DECLSPEC __declspec(dllimport)
    #else
        #define ED25519_DECLSPEC
    #endif
#else
    #define ED25519_DECLSPEC
#endif


#ifdef __cplusplus
extern "C" {
#endif

#ifndef ED25519_NO_SEED
int ED25519_DECLSPEC ed25519_create_seed(unsigned char *seed);
#endif

void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed);
void ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key, uint64_t *runtime);
int ed25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, uint64_t *runtime);
void ed25519_add_scalar(unsigned char *public_key, unsigned char *private_key, const unsigned char *scalar);
void ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key);

void * ed25519_verify_begin(const unsigned char *signature, const unsigned char *public_key);
void ed25519_verify_update(void * hash, const unsigned char *message, size_t message_len);
int ed25519_verify_end(void * hash, const unsigned char *signature);

uint64_t sha512_benchmark(const unsigned char *message, size_t message_len, unsigned char r[64]);

#ifdef __cplusplus
}
#endif

#endif
