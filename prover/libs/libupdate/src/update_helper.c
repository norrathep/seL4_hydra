//
// Created by oak on 10/25/17.
//

#include <metadata.h>
#include <stdio.h>

void print_signature(Signature_t sig) {
    int j;
    printf("ID: %d\nTYPE: %d\n", sig.key_id, sig.type);
    printf("SIG: ");
    for(j=0; j<64; j++) {
        printf("%.2x ", sig.sig[j]);
    }
    printf("\n");
}

void print_hash(Hash_t hash) {
    int j;
    printf("HashTYPE: %d\n", hash.hash_type);
    printf("Hash: ");
    for(j=0; j<64; j++) {
        printf("%.2x ", hash.hash[j]);
    }
    printf("\n");
}
