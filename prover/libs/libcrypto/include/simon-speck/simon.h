#ifndef SIMON_H
#define SIMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <assert.h>

/*
 * define simon type to use (one of SIMON_32_64, SIMON_64_128, SIMON_128_256)
 */
#define SIMON_64_128
#define TEST_COMBINED

#ifdef SIMON_32_64
#define SIMON_TYPE uint16_t
#define SIMON_ROUNDS 32
#define SIMON_J 0
#define SIMON_KEY_LEN 4
#endif

#ifdef SIMON_64_128
#define SIMON_TYPE uint32_t
#define SIMON_ROUNDS 44
#define SIMON_J 3 
#define SIMON_KEY_LEN 4
#endif

#ifdef SIMON_128
#define SIMON_TYPE uint64_t
#define SIMON_ROUNDS 68
#define SIMON_J 2
#define SIMON_KEY_LEN 2
#endif

#ifdef SIMON_128_256
#define SIMON_TYPE uint64_t
#define SIMON_ROUNDS 72
#define SIMON_J 4
#define SIMON_KEY_LEN 4
#endif

void simon_expand(SIMON_TYPE const K[static SIMON_KEY_LEN], SIMON_TYPE S[static SIMON_ROUNDS]);
void simon_encrypt(SIMON_TYPE const pt[static 2], SIMON_TYPE ct[static 2], SIMON_TYPE const K[static SIMON_ROUNDS]);
void simon_decrypt(SIMON_TYPE const ct[static 2], SIMON_TYPE pt[static 2], SIMON_TYPE const K[static SIMON_ROUNDS]);

void simon_cbc_mac(SIMON_TYPE* pt, int len, SIMON_TYPE ct[static 2], SIMON_TYPE const key[static SIMON_KEY_LEN]);

void testSimon();


#ifdef __cplusplus
}
#endif

#endif
