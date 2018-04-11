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

uint32_t version = 2;

void fake_sleep(int usec) {
    while(usec-- > 0) {
        volatile int i=1000;
        while(i-- > 0);
    }
}

int SPEED_THRESH = 70;
int speed_warning(int speed) {
    return speed > SPEED_THRESH ? 1 : 0;
}

void print_car(int gap, int acc, char token) {
    char car[500] = "\\
%s                     .------. \n\\
%s                     :|||\"\"\"`.`.\n\\
%s                     :|||     7.`.\n\\
%s  .===+===+===+===+===||`----L7'-`7`---.._\n\\
%s  []                  || ==       |       \"\"\"-.\n\\
%s  []...._____.........||........../ _____ ____|\n\\
%s c\\____/,---.\\_       ||_________/ /,---.\\_  _/\n\\
%s   /_,-/ ,-. \\ `._____|__________||/ ,-. \\ \\_[\n\\
%s      /\\ `-' /                    /\\ `-' /\n\\
%s        `---'                       `---'\n";


    char buffer[500+gap*10];
    char g[gap+1];
    int i=0;
    for(i=0; i<gap; i++) g[i] = ' ';
    if(gap > 9) {
        for(i=gap-8; i<gap; i++) g[i] = token;
    }
    g[gap] = '\0';
    sprintf(buffer, car, g, g, g, g, g, g, g, g, g, g);
    printf("%s", buffer);
}

void simulate_speedometer(int usec) {

    int speed = 0, prev_speed = 0;
    int delta = 20;
    int i, max_iter = 15;	
    for(i=0; i<max_iter; i++) {
        printf("\n\n----------------------------------------------------------------------------------\n\n");
        int warn = speed_warning(speed); //v1 and v2
        if(warn) speed = 70; //v2
        print_car(speed/2, speed-prev_speed, warn ? 'X' : '>'); //v1 and v2
        printf("[Speedometer Process] Current Speed %d MPH", speed);
        if(warn) //printf("\n[Speedometer Process] Warning: Exceeding the Speed Limit\n");//v1 
            printf("\n[Speedometer Process] Reached the Speed Limit : It won't go further.\n"); //v2
        printf("\n\n----------------------------------------------------------------------------------\n\n");
        fake_sleep(usec);
        int tmp_prev_speed = prev_speed;
        prev_speed = speed;
        if(speed >= 160) speed -= delta;
        else if(speed >= 60 && speed < tmp_prev_speed) speed -= delta;
        else speed += delta;
    }
    printf("[Speedmeter Process] Simulation Completes\n");
    while(1){}
}
int main(int argc, char **argv) {


    printf("[Speedometer Process] Hello from Speedometer Process\n");
    printf("[Speedometer Process] Version %d\n", version);

           
    seL4_MessageInfo_t tag;
    tag = seL4_MessageInfo_new(1, 0, 0, 1);
    seL4_SetMR(0, (seL4_Word) version);
    seL4_Call(EP_CPTR, tag); // TODO: check if its true that seL4_Send causes some junks in memory spaces? and seL4_Call is fine?

    printf("[Speedometer Process] Process is active\n");

    simulate_speedometer(60000);
    return 0;
}


