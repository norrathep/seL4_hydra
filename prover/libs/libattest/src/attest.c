#include <assert.h>

#include <sel4/sel4.h>
#include <sel4bench/sel4bench.h>

#include <sha/hmac-sha256.h>
#include <aes/aes_cbc.h>
#include <simon-speck/speck.h>
#include <simon-speck/simon.h>
#include <blake2/blake2.h>

#include <string.h>
#include <attest.h>


/*void test_enc() {

    int num_runs=10000;
    int i;
    SPECK_TYPE pt[2] = {0}, ct[2] = {0}, K[SPECK_KEY_LEN] = {0};
 
    sel4bench_init();
    uint64_t start_cycle = sel4bench_get_cycle_count();

    for(i=0; i<num_runs; i++) speck_encrypt_combined(pt, ct, K);

    uint64_t end_cycle = sel4bench_get_cycle_count();
    sel4bench_destroy();

    printf("speck-128 enc takes %llu\n", (end_cycle - start_cycle)/num_runs);

    
    SIMON_TYPE pt3[2] = {0}, ct3[2] = {0}, K3[SIMON_KEY_LEN] = {0};
    SIMON_TYPE exp[SIMON_ROUNDS]; 

    sel4bench_init();
    start_cycle = sel4bench_get_cycle_count();

    for(i=0; i<num_runs; i++) { 
        simon_expand(K3, exp); 
        simon_encrypt(pt3, ct3, exp);
    }

    end_cycle = sel4bench_get_cycle_count();
    sel4bench_destroy();

    printf("simon-128 enc takes %llu\n", (end_cycle - start_cycle)/num_runs);

    uint32_t rk[60] = {0};
    uint8_t rkey[32] = {0};
    uint8_t pt2[16] = {0}, ct2[16] = {0};

    sel4bench_init();
    start_cycle = sel4bench_get_cycle_count();

    for(i=0; i<num_runs; i++) {
        int num_rounds = rijndaelKeySetupEnc(rk, rkey, 128);
        rijndaelEncrypt(rk, num_rounds, pt2, ct2);
    }

    end_cycle = sel4bench_get_cycle_count();
    sel4bench_destroy();

    printf("aes-128 enc takes %llu\n", (end_cycle - start_cycle)/num_runs);
}*/

uint64_t attest_string_simon(const uint8_t *block, const unsigned int block_size, 
    const uint8_t *K, const unsigned int K_size, uint8_t digest[8]) {
    
    assert(block_size % sizeof(SIMON_TYPE) == 0);
    assert(sizeof(SIMON_TYPE)*SIMON_KEY_LEN >= K_size);

    int len = block_size/sizeof(SIMON_TYPE);
    /*SIMON_TYPE *pt = malloc(len*sizeof(SIMON_TYPE));
    int i;
    for(i=0; i<len; i++) {
        memcpy(&pt[i], block+i*sizeof(SIMON_TYPE), sizeof(SIMON_TYPE));
    }

    assert(memcmp(pt, block, len*sizeof(SIMON_TYPE)) == 0);*/

    SIMON_TYPE key[SIMON_KEY_LEN] = {0};
    if(K == NULL) {
        key[0] = (SIMON_TYPE)('k');
        key[1] = (SIMON_TYPE)('e');
        //key[2] = (SIMON_TYPE)('y');
    } else {
        memcpy(key, K, K_size);
    }

    SIMON_TYPE ct[2] = {0};

    //sel4bench_init();
    //uint64_t start_cycle = sel4bench_get_cycle_count();
    
    simon_cbc_mac((SIMON_TYPE*)block, len, ct, key);

    //uint64_t end_cycle = sel4bench_get_cycle_count();
    //sel4bench_destroy();

    memcpy(digest, &ct, sizeof(SIMON_TYPE)*2);
    //free(pt);
    //return (end_cycle - start_cycle);
    return 0;	
}
uint64_t attest_string_aes(const uint8_t *block, unsigned int block_size,
    const uint8_t *K, const unsigned int K_size, unsigned int key_size, uint8_t ct[32]) {

    assert(K_size <= 32);

    uint32_t rk[60] = {0};
    uint8_t rkey[32] = {0};
    if(K == NULL) {
        rkey[0] = (uint8_t)('k');
        rkey[1] = (uint8_t)('e');
        rkey[2] = (uint8_t)('y');
    } else {
        memcpy(rkey, K, K_size);
    }

    //sel4bench_init();
    //uint64_t start_cycle = sel4bench_get_cycle_count();

    int num_rounds = rijndaelKeySetupEnc(rk, rkey, key_size);
    assert(num_rounds != 0);

    cbc_mac_aes(block, ct, block_size, rkey, key_size);

    //uint64_t end_cycle = sel4bench_get_cycle_count();
    //sel4bench_destroy();

    //return (end_cycle - start_cycle);
    return 0;
}

uint64_t attest_string_speck(const uint8_t *block, const unsigned int block_size,
    const uint8_t *K, const unsigned int K_size, uint8_t digest[8]) {

    assert(block_size % sizeof(SPECK_TYPE) == 0);
    assert(sizeof(SPECK_TYPE)*SPECK_KEY_LEN >= K_size);

    int len = block_size/sizeof(SPECK_TYPE);

    SPECK_TYPE key[SPECK_KEY_LEN] = {0};
    if(K == NULL) {
        key[0] = (SPECK_TYPE)('k');
        key[1] = (SPECK_TYPE)('e');
        //key[2] = (SPECK_TYPE)('y');
    } else {
        memcpy(key, K, K_size);
    }

    SPECK_TYPE ct[2] = {0};

    //sel4bench_init();
    //uint64_t start_cycle = sel4bench_get_cycle_count();
    
    speck_cbc_mac((SPECK_TYPE*) block, len, ct, key);

    //uint64_t end_cycle = sel4bench_get_cycle_count();
    //sel4bench_destroy();

    memcpy(digest, &ct, sizeof(SPECK_TYPE)*2);
    //return (end_cycle - start_cycle);
    return 0;
}

uint64_t attest_string_blake2(const uint8_t *block, unsigned int block_size,
    const uint8_t *K, const unsigned int K_size, uint8_t digest[BLAKE2S_OUTBYTES]) {
    
    assert(K_size <= BLAKE2S_KEYBYTES);

    uint8_t key[BLAKE2S_KEYBYTES] = {0};
    if(K == NULL) {
        key[0] = (uint8_t)('k');
        key[1] = (uint8_t)('e');
        key[2] = (uint8_t)('y');
    } else {
        memcpy(key, K, K_size);
    }

//    sel4bench_init();
//    uint64_t start_cycle = sel4bench_get_cycle_count();

    blake2s( digest, block, key, BLAKE2S_OUTBYTES, block_size, BLAKE2S_KEYBYTES );

//    uint64_t end_cycle = sel4bench_get_cycle_count();
//    sel4bench_destroy();

//    return (end_cycle - start_cycle);
    return 0;
}

uint64_t attest_string_sha(const uint8_t *block, unsigned int block_size, 
    const uint8_t *K, const unsigned int K_size, uint8_t digest[32]) {

    assert(K_size <= 64);

    uint8_t key[64] = {0};
    if(K == NULL) {
        key[0] = (uint8_t)('k');
        key[1] = (uint8_t)('e');
        key[2] = (uint8_t)('y');
    } else {
        memcpy(key, K, K_size);
    }

//    sel4bench_init();
//    uint64_t start_cycle = sel4bench_get_cycle_count();

    hmac_sha256_get(digest, block, block_size, key, 3);
    
//    uint64_t end_cycle = sel4bench_get_cycle_count();
//    sel4bench_destroy();

//    return (end_cycle - start_cycle);
    return 0;

}

/*
 * return params || str
 */
uint8_t* combine(const uint32_t* params, const unsigned int num_params,
    const uint8_t* str, const unsigned int length) {

    if(num_params == 0) assert(params == NULL);

    unsigned int param_size = num_params*sizeof(num_params); /* param size in byte */
    unsigned int block_size = length + param_size; /* total size in bytes */
    uint8_t *block = malloc(block_size*sizeof(uint8_t));
 
    memcpy(block, params, param_size);
    memcpy(block+param_size, str, length);

    return block;
}

/*
 * compute MAC(params || str)
 */
uint64_t MAC_with_params(const uint32_t* params, const unsigned int num_params,
    const uint8_t* str, const unsigned int str_len, 
    const uint8_t *key, const unsigned int key_size, hmac_type fn, uint8_t digest[32]) {

    assert(str != NULL);
    assert(str_len > 0);

    uint8_t* block = combine(params, num_params, str, str_len);
    unsigned int block_size = str_len+num_params*sizeof(uint32_t);

    uint64_t time = MAC(block, block_size, key, key_size, fn, digest);
    free(block);
    return time;
}

/*
 * compute MAC(block) if K is null, use a default key
 */
uint64_t MAC(const uint8_t* block, const unsigned int block_size, 
    const uint8_t *key, const unsigned int key_size, hmac_type fn, uint8_t digest[32]) {

    assert(block != NULL);
    assert(block_size > 0);

    switch(fn) {
        case SHA_256: return attest_string_sha(block, block_size, key, key_size, digest);
        case AES_128: return attest_string_aes(block, block_size, key, key_size, 128, digest);
        case AES_192: return attest_string_aes(block, block_size, key, key_size, 192, digest);
        case AES_256: return attest_string_aes(block, block_size, key, key_size, 256, digest);
        case SIMON: return attest_string_simon(block, block_size, key, key_size, digest);
        case SPECK: return attest_string_speck(block, block_size, key, key_size, digest);
        case BLAKE2S: return attest_string_blake2(block, block_size, key, key_size, digest);
        default: printf("HMAC FN is undefined\n"); break;
    }
    return 0;
}


