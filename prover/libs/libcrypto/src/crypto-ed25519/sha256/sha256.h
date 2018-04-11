/*
 * SHA256 hash implementation and interface functions
 * Copyright (c) 2003-2011, Jouni Malinen <j@w1.fi>
 *  Modified by Sam Lauzon <slauzon@umich.edu> for the Uptane Project
 *
 *
 * This software may be distributed under the terms of the BSD license.
 */

#ifndef SHA256_H
#define SHA256_H

#define SHA256_MAC_LEN 32

#define SHA256_BLOCK_SIZE 64

struct sha256_state {
	uint64_t length;
	uint32_t state[8], curlen;
	uint8_t buf[SHA256_BLOCK_SIZE];
};

void sha256_init(struct sha256_state *md);
int sha256_process(struct sha256_state *md, const unsigned char *in,
		unsigned long inlen);
int sha256_done(struct sha256_state *md, unsigned char *out);

int hmac_sha256_vector(const uint8_t *key, size_t key_len, size_t num_elem,
		const uint8_t *addr[], const size_t *len, uint8_t *mac);
int hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
		size_t data_len, uint8_t *mac);
void sha256_prf(const uint8_t *key, size_t key_len, const char *label,
		const uint8_t *data, size_t data_len, uint8_t *buf, size_t buf_len);
void tls_prf_sha256(const uint8_t *secret, size_t secret_len,
		const char *label, const uint8_t *seed, size_t seed_len,
		uint8_t *out, size_t outlen);

#endif /* SHA256_H */
