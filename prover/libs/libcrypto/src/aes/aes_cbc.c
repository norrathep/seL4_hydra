#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <aes/aes_cbc.h>
#include <aes/rijndael-alg-fst.h>

typedef void (*block128_f)(const uint32_t rk[], const unsigned int Nr, const uint8_t pt[16], uint8_t ct[16]);

//int BUFFER_SIZE = 10200000; // 2MB
//uint8_t *BUFFER = NULL;

void CRYPTO_cbc128_decrypt(const uint8_t *in, uint8_t *out,
                           size_t len, const uint32_t *key, const unsigned int nr,
                           uint8_t ivec[16], block128_f block)
{
    assert(false && "cbc128_decrypt not implemented");
}

// Oak: Adapt it to support CBC-MAC
void CRYPTO_cbc128_encrypt(const uint8_t *in, uint8_t out[16],
                           size_t len, const uint32_t *key, const unsigned int nr,
                           uint8_t ivec[16], block128_f block)
{
    size_t n;
    const unsigned char *iv = ivec;

    int i=0;
    while (len) {
	    i++;
        for (n = 0; n < 16 && n < len; ++n)
            out[n] = in[n] ^ iv[n];
        for (; n < 16; ++n)
            out[n] = iv[n];
	    (*block) (key, nr, out, out);
        //(*block) (out, out, key);
        iv = out;
        if (len <= 16)
            break;
        len -= 16;
        in += 16;
        //out += 16;
    }
    memcpy(out, iv, 16);
}

/*
 * compute mac based aes-cbc
 * Some assumptions here:
 * block size = 16
 * iv = 0
 * use zero padding, so the result wont match openssl
 */
void cbc_mac_aes(const uint8_t *in, uint8_t out[16], size_t len,
	const uint8_t rkey[32], const unsigned int key_size) {

    // zero padding if needed
    // TODO: use PKCS7 padding
    //size_t padded_len = (len%AES_BLOCK_SIZE == 0) ? len : len + (AES_BLOCK_SIZE - len%AES_BLOCK_SIZE);

    uint32_t rk[60] = {0};

    //uint8_t *encrypt = calloc(padded_len, sizeof(uint8_t));
    //TODO: it is not desirable to have a global array but seL4 does not have a feature 
    // for freeing a large chunk of memory

    /*if(len > BUFFER_SIZE) {
        printf("in AES, len (%d) > BUFFER_SIZE (%d)\n", len, BUFFER_SIZE);
        return;
    }
    if(BUFFER == NULL) {
        BUFFER = malloc(BUFFER_SIZE*sizeof(uint8_t));
    }
    assert(BUFFER != NULL);
    memset(BUFFER, 0, len);*/
    //uint8_t *encrypt = calloc(len, sizeof(uint8_t));

    int num_rounds = rijndaelKeySetupEnc(rk, rkey, key_size);
    assert(num_rounds != 0);
  
    // make iv to be 0 
    uint8_t ivec[16];
    memset(ivec, 0, 16*sizeof(uint8_t));

    AES_cbc_encrypt(in, out, len, rk, num_rounds, ivec, 1);

    //memcpy(out, ivec, 16);
    //free(encrypt);
}

void AES_cbc_encrypt(const uint8_t *in, uint8_t *out,
                     size_t len, const uint32_t *key, const unsigned int nr,
                     uint8_t *ivec, const int enc)
{

    if (enc)
        CRYPTO_cbc128_encrypt(in, out, len, key, nr, ivec,
                              (block128_f) rijndaelEncrypt);
    else
        CRYPTO_cbc128_decrypt(in, out, len, key, nr, ivec,
                              (block128_f) rijndaelDecrypt);
}

