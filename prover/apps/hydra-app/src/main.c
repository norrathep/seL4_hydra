/*
 * Copyright 2015, NICTA
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(NICTA_BSD)
 */

/*
 * seL4 tutorial part 4: application to be run in a process
 */
#include <autoconf.h>

#include <stdio.h>
#include <assert.h>
#include <stdint.h>

#include <sel4/sel4.h>

/* constants */
#define EP_CPTR 0x3 // where the cap for the endpoint was placed.

void fake_sleep(int usec) {
    while(usec-- > 0) {
        volatile int i=1000;
        while(i-- > 0);
    }
}

void simulate_oillevel(int usec) {
    int current_level = 50;
    int dec = 5;
    while(1) {
        printf("\n***************************************************\n");
        printf("[Fuel Guage Process] Current Level of Fuel %d%%", current_level);
        printf("\n***************************************************\n");
        fake_sleep(usec);
        current_level -= dec;
        if(current_level < 0) current_level = 0;
    }   
}

uint32_t version = 0;
int main(int argc, char **argv) {

    printf("[Fuel Gauge Process] Hello from Fuel Gauge Process\n");
    //printf("[Fuel Gauge Process] Version %d\n", version);

    #define STR_SIZE 150000
    volatile char buf[STR_SIZE] = {0};
    int i;
    for(i = 0; i<STR_SIZE; i++) buf[i] = 'a'+i%26;
           
    seL4_MessageInfo_t tag;
    tag = seL4_MessageInfo_new(1, 0, 0, 1);
    seL4_SetMR(0, (seL4_Word) version);
    seL4_Call(EP_CPTR, tag); // TODO: check if its true that seL4_Send causes some junks in memory spaces? and seL4_Call is fine?


    printf("[Fuel Guage Process] Process is active\n");

    int j=0;
    for(j=0;;j++) {
        printf("===========================================================\n");
        for(i=0; i<10000; i+=100) printf("%c ", buf[i]);
        for(i=0; i<STR_SIZE; i+=100) buf[i] = 'a'+j%26; //printf("%c ", buf[i]);
        printf("\n");
        fake_sleep(500000);
        printf("===========================================================\n");
    }   

    simulate_oillevel(60000);

    for(i=0; i<1000; i++) printf("%c", buf[i]);

    return 0;
}


