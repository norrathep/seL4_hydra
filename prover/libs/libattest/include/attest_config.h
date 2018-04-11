#pragma once
#ifndef __ATTEST_CONFIG_H__
#define __ATTEST_CONFIG_H__


#include <string.h>

#define NONCE_LENGTH 8 /* length of nonce in bytes */
#define PARAM_LENGTH NONCE_LENGTH+2 /* one for start idx and the other for length */

#define SAMPLE_STR_SIZE 10100000 //11000000 //110000 //1100000 // 11MB 

//#define ATTEST_IA32
//#define ATTEST_ODROID_XU4
#define ATTEST_SABRE_LITE

#ifdef ATTEST_SABRE_LITE
#define BASE_STR_ADDR 3796 /* TODO: figure this out */
#endif

#ifdef ATTEST_IA32
#define BASE_STR_ADDR 3728
#endif

#ifdef ATTEST_ORDOID_XU4
#define BASE_STR_ADDR 3000 /* TODO: figure this out */
#endif

uint8_t BASE = 'a';
uint8_t LAST = 'Z';
int MOD = 26;
static inline uint8_t* sample_string() {
     uint8_t *buf = malloc(SAMPLE_STR_SIZE);
     int i;
     for(i=0; i<SAMPLE_STR_SIZE; i++) {
         buf[i] = BASE+i%MOD;
     }
     buf[SAMPLE_STR_SIZE-1] = LAST;
     return buf;
}

static inline void sample_string_on_stack(char buf[SAMPLE_STR_SIZE]) {
    int i;
    for(i=0; i<SAMPLE_STR_SIZE; i++) buf[i] = BASE+i%MOD;
    buf[SAMPLE_STR_SIZE-1] = LAST;
}


#endif
