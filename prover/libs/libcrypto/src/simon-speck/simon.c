#include <simon-speck/simon.h>
#include <string.h>
#include <stdio.h>

#define ROR(x, r) ((x >> r) | (x << ((sizeof(SIMON_TYPE) * 8) - r)))
#define ROL(x, r) ((x << r) | (x >> ((sizeof(SIMON_TYPE) * 8) - r)))

SIMON_TYPE z[5][62] = {
	{1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0,1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0},
	{1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0,1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0},
	{1,0,1,0,1,1,1,1,0,1,1,1,0,0,0,0,0,0,1,1,0,1,0,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,1,0,0,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,1,0,0,1,1},
	{1,1,0,1,1,0,1,1,1,0,1,0,1,1,0,0,0,1,1,0,0,1,0,1,1,1,1,0,0,0,0,0,0,1,0,0,1,0,0,0,1,0,1,0,0,1,1,1,0,0,1,1,0,1,0,0,0,0,1,1,1,1},
	{1,1,0,1,0,0,0,1,1,1,1,0,0,1,1,0,1,0,1,1,0,1,1,0,0,0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,0,0,1,1,0,0,1,0,1,0,0,1,0,0,1,1,1,0,1,1,1,1}
};

void simon_cbc_mac(SIMON_TYPE* pt, int len, SIMON_TYPE ct[static 2], SIMON_TYPE const key[static SIMON_KEY_LEN]) {
	SIMON_TYPE plain[2] = {0};
	ct[0] = 0; ct[1] = 0;
	int i;

	//assert(len > 1 && len%2 == 0);
	assert(len > 1);
    SIMON_TYPE exp[SIMON_ROUNDS];
	simon_expand(key, exp);

	for(i=0; i<len; i+=2) {
		plain[0] = pt[i] ^ ct[0];
		plain[1] = pt[i+1] ^ ct[1];
		
	    simon_encrypt(plain, ct, exp);
		
	}
}

void simon_expand(SIMON_TYPE const K[static SIMON_KEY_LEN], SIMON_TYPE S[static SIMON_ROUNDS])
{
    SIMON_TYPE i, tmp;
	for(i = 0;      i<SIMON_KEY_LEN;   i++)
		S[i]=K[i];
	for(i = SIMON_KEY_LEN;     i<SIMON_ROUNDS;    i++)
	{
	    tmp = ROR(S[i-1], 3);
		if (SIMON_KEY_LEN == 4) tmp ^= S[i-3];
		tmp = tmp ^ ROR(tmp,1);
		//is it bitwise negation?
		S[i] = (~(S[i-SIMON_KEY_LEN])) ^ tmp ^ z[SIMON_J][(i-SIMON_KEY_LEN) % 62] ^ 3;
	};

}

void simon_encrypt(SIMON_TYPE const pt[static 2], SIMON_TYPE ct[static 2], SIMON_TYPE const K[static SIMON_ROUNDS])
{
    SIMON_TYPE i, tmp;
    ct[0] = pt[1]; ct[1] = pt[0];
    for(i=0; i<SIMON_ROUNDS; i++) {
        //printf("%x %x\n", ct[0], ct[1]);
        tmp = ct[0];
        ct[0] = ct[1] ^ (ROL(ct[0],1) & ROL(ct[0], 8)) ^ ROL(ct[0], 2) ^ K[i];
        ct[1] = tmp;
    }
    tmp = ct[0];
    ct[0] = ct[1];
    ct[1] = tmp;
}


void testSimon()
{
#ifdef SIMON_32_64
  uint16_t key[4] = {0x0100, 0x0908, 0x1110, 0x1918};
  uint16_t plain[2] = {0x6877, 0x6565};
  uint16_t enc[2] = {0xe9bb, 0xc69b};
#endif

#ifdef SIMON_64_128
  uint32_t key[4] = {0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918};
  uint32_t plain[2] = {0x20646e75, 0x656b696c};
  uint32_t enc[2] = {0xb9dfa07a, 0x44c8fc20};
#endif

#ifdef SIMON_128
    uint64_t key[2] = {0x0706050403020100, 0x0f0e0d0c0b0a0908};
    uint64_t plain[2] = {0x6c6c657661727420, 0x6373656420737265};
    uint64_t enc[2] = {0x65aa832af84e0bbc, 0x49681b1e1e54fe3f};
#endif

#ifdef SIMON_128_256
  uint64_t key[4] = {0x0706050403020100, 0x0f0e0d0c0b0a0908, 0x1716151413121110, 0x1f1e1d1c1b1a1918};
  uint64_t plain[2] = {0x6d69732061207369, 0x74206e69206d6f6f};
  uint64_t enc[2] = {0x3bf72a87efe7b868, 0x8d2b5579afc8a3a0};
#endif

  SIMON_TYPE buffer[2] = {0};
  SIMON_TYPE exp[SIMON_ROUNDS];

  simon_expand(key, exp);
  
//#ifdef TEST_COMBINED
//  simon_encrypt_combined(plain, buffer, key);
//#else
  simon_encrypt(plain, buffer, exp);
  printf("buffer: %llx %llx\n", buffer[0], buffer[1]);
//#endif
  if (memcmp(buffer, enc, sizeof(enc))) {
    printf("encryption failed\n");
    return;
  }
/*#ifdef TEST_COMBINED
  simon_decrypt_combined(enc, buffer, key);
#else
  simon_decrypt(enc, buffer, exp);
#endif
  if (memcmp(buffer, plain, sizeof(enc))) {
    printf("decryption failed\n");
    return;
  }*/
  printf("OK\n");
  return;
}

