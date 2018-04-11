//#include <crypto-ed25519/libed25519/ed25519.h>//"ed25519.h"
#include <malloc.h>
#include <string.h>

#include "sha512.c"
#include "ge.c"
#include "fe.c"
#include "sc.c"

void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed) {
    ge_p3 A;

    sha512(seed, 32, private_key);
    private_key[0] &= 248;
    private_key[31] &= 63;
    private_key[31] |= 64;

    ge_scalarmult_base(&A, private_key);
    ge_p3_tobytes(public_key, &A);
}


/* see http://crypto.stackexchange.com/a/6215/4697 */
void ed25519_add_scalar(unsigned char *public_key, unsigned char *private_key, const unsigned char *scalar) {
    const unsigned char SC_1[32] = {1}; /* scalar with value 1 */
    
    unsigned char n[32]; 
    ge_p3 nB;
    ge_p1p1 A_p1p1;
    ge_p3 A;
    ge_p3 public_key_unpacked;
    ge_cached T;

    sha512_context hash;
    unsigned char hashbuf[64];

    int i;

    /* copy the scalar and clear highest bit */
    for (i = 0; i < 31; ++i) {
        n[i] = scalar[i];
    }
    n[31] = scalar[31] & 127;

    /* private key: a = n + t */
    if (private_key) {
        sc_muladd(private_key, SC_1, n, private_key);

        // https://github.com/orlp/ed25519/issues/3
        sha512_init(&hash);
        sha512_update(&hash, private_key + 32, 32);
        sha512_update(&hash, scalar, 32);
        sha512_final(&hash, hashbuf);
        for (i = 0; i < 32; ++i) {
            private_key[32 + i] = hashbuf[i];
        }
    }

    /* public key: A = nB + T */
    if (public_key) {
        /* if we know the private key we don't need a point addition, which is faster */
        /* using a "timing attack" you could find out wether or not we know the private
           key, but this information seems rather useless - if this is important pass
           public_key and private_key seperately in 2 function calls */
        if (private_key) {
            ge_scalarmult_base(&A, private_key);
        } else {
            /* unpack public key into T */
            ge_frombytes_negate_vartime(&public_key_unpacked, public_key);
            fe_neg(public_key_unpacked.X, public_key_unpacked.X); /* undo negate */
            fe_neg(public_key_unpacked.T, public_key_unpacked.T); /* undo negate */
            ge_p3_to_cached(&T, &public_key_unpacked);

            /* calculate n*B */
            ge_scalarmult_base(&nB, n);

            /* A = n*B + T */
            ge_add(&A_p1p1, &nB, &T);
            ge_p1p1_to_p3(&A, &A_p1p1);
        }
            
        /* pack public key */
        ge_p3_tobytes(public_key, &A);
    }
}

void ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key, uint64_t *runtime) {
    sha512_context hash;
    unsigned char hram[64];
    unsigned char r[64];
    ge_p3 R;

    sha512_init(&hash);
    sha512_update(&hash, private_key + 32, 32);
    sha512_update(&hash, message, message_len);
    sha512_final(&hash, r);

    sc_reduce(r);
    ge_scalarmult_base(&R, r);
    ge_p3_tobytes(signature, &R);

    sha512_init(&hash);
    sha512_update(&hash, signature, 32);
    sha512_update(&hash, public_key, 32);
    sha512_update(&hash, message, message_len);
    sha512_final(&hash, hram);

    sc_reduce(hram);
    sc_muladd(signature + 32, hram, private_key, r);
    *runtime = 0;
}

uint64_t sha512_benchmark(const unsigned char *message, size_t message_len, unsigned char r[64]) {
 
    sha512_context hash;


    sha512_init(&hash);
    sha512_update(&hash, message, message_len);
    sha512_final(&hash, r);

    return 0;

   
}

void ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key) {
    unsigned char e[32];
    unsigned int i;
    
    fe x1;
    fe x2;
    fe z2;
    fe x3;
    fe z3;
    fe tmp0;
    fe tmp1;

    int pos;
    unsigned int swap;
    unsigned int b;

    /* copy the private key and make sure it's valid */
    for (i = 0; i < 32; ++i) {
        e[i] = private_key[i];
    }

    e[0] &= 248;
    e[31] &= 63;
    e[31] |= 64;

    /* unpack the public key and convert edwards to montgomery */
    /* due to CodesInChaos: montgomeryX = (edwardsY + 1)*inverse(1 - edwardsY) mod p */
    fe_frombytes(x1, public_key);
    fe_1(tmp1);
    fe_add(tmp0, x1, tmp1);
    fe_sub(tmp1, tmp1, x1);
    fe_invert(tmp1, tmp1);
    fe_mul(x1, tmp0, tmp1);

    fe_1(x2);
    fe_0(z2);
    fe_copy(x3, x1);
    fe_1(z3);

    swap = 0;
    for (pos = 254; pos >= 0; --pos) {
        b = e[pos / 8] >> (pos & 7);
        b &= 1;
        swap ^= b;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b;

        /* from montgomery.h */
        fe_sub(tmp0, x3, z3);
        fe_sub(tmp1, x2, z2);
        fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);
        fe_mul(z3, tmp0, x2);
        fe_mul(z2, z2, tmp1);
        fe_sq(tmp0, tmp1);
        fe_sq(tmp1, x2);
        fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);
        fe_mul(x2, tmp1, tmp0);
        fe_sub(tmp1, tmp1, tmp0);
        fe_sq(z2, z2);
        fe_mul121666(z3, tmp1);
        fe_sq(x3, x3);
        fe_add(tmp0, tmp0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, tmp1, tmp0);
    }

    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(shared_secret, x2);
}

static int consttime_equal(const unsigned char *x, const unsigned char *y) {
    unsigned char r = 0;

    r = x[0] ^ y[0];
    #define F(i) r |= x[i] ^ y[i]
    F(1);
    F(2);
    F(3);
    F(4);
    F(5);
    F(6);
    F(7);
    F(8);
    F(9);
    F(10);
    F(11);
    F(12);
    F(13);
    F(14);
    F(15);
    F(16);
    F(17);
    F(18);
    F(19);
    F(20);
    F(21);
    F(22);
    F(23);
    F(24);
    F(25);
    F(26);
    F(27);
    F(28);
    F(29);
    F(30);
    F(31);
    #undef F

    return !r;
}

int ed25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, uint64_t *runtime) {
    unsigned char h[64];
    unsigned char checker[32];
    sha512_context hash;
    ge_p3 A;
    ge_p2 R;

    if (signature[63] & 224) {
        return 0;
    }

    if (ge_frombytes_negate_vartime(&A, public_key) != 0) {
        return 0;
    }
	
    sha512_init(&hash);
    sha512_update(&hash, signature, 32);
    sha512_update(&hash, public_key, 32);
    sha512_update(&hash, message, message_len);
    sha512_final(&hash, h);
    
    sc_reduce(h);
    ge_double_scalarmult_vartime(&R, h, &A, signature + 32);
    ge_tobytes(checker, &R);

    *runtime = 0;

    if (!consttime_equal(checker, signature)) {
        return 0;
    }

    return 1;
}

typedef struct context_
{
	sha512_context hash;
	ge_p3 A;
} context;
		   

void * ed25519_verify_begin(const unsigned char *signature, const unsigned char *public_key) {
	ge_p3 A;

	if (signature[63] & 224) {
		return NULL;
	}
	
	if (ge_frombytes_negate_vartime(&A, public_key) != 0) {
		return NULL;
	}

	context * ctx = (context*) malloc(sizeof(context));
	memcpy(&ctx->A, &A, sizeof(A));
	
	sha512_init(&ctx->hash);
	sha512_update(&ctx->hash, signature, 32);
	sha512_update(&ctx->hash, public_key, 32);

	return ctx;
}

void ed25519_verify_update(void * ctx, const unsigned char *message, size_t message_len) {
	sha512_update(&((context*)ctx)->hash, message, message_len);
}

int ed25519_verify_end(void * ctx, const unsigned char *signature) {
	unsigned char h[64];
	unsigned char checker[32];
	ge_p2 R;
	
	sha512_final(&((context*)ctx)->hash, h);
	
   sc_reduce(h);
	ge_double_scalarmult_vartime(&R, h, &((context*)ctx)->A, signature + 32);
	ge_tobytes(checker, &R);
	
	free(ctx);
	
	if (!consttime_equal(checker, signature)) {
		return 0;
	}

   return 1;
}


