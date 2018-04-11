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
 * seL4 tutorial part 4: create a new process and IPC with it
 */


/* Include Kconfig variables. */
#include <autoconf.h>

#include <stdio.h>
#include <assert.h>

#include <sel4/sel4.h>

#include <simple/simple.h>
#include <simple-default/simple-default.h>

#include <vka/object.h>
#include <vka/capops.h>

#include <allocman/allocman.h>
#include <allocman/bootstrap.h>
#include <allocman/vka.h>

#include <vspace/vspace.h>

#include <sel4utils/vspace.h>
#include <sel4utils/mapping.h>
#include <sel4utils/process.h>

#include <unistd.h>

#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>

#include <sel4platsupport/mach/gpt.h>

#include "network.h"
#include "pbuf_helpers.h"



/* global environment variables */
seL4_BootInfo *info;
simple_t simple;
vka_t vka;
allocman_t *allocman;

/* static memory for the allocator to bootstrap with */
#define ALLOCATOR_STATIC_POOL_SIZE ((1 << seL4_PageBits) * 1000)
UNUSED static char allocator_mem_pool[ALLOCATOR_STATIC_POOL_SIZE];

/* dimensions of virtual memory for the allocator to use */
#define ALLOCATOR_VIRTUAL_POOL_SIZE ((1 << seL4_PageBits) * 2000)

/* static memory for virtual memory bootstrapping */
UNUSED static sel4utils_alloc_data_t data;

/* convenience function */
extern void name_thread(seL4_CPtr tcb, char *name);

vspace_t vspace;

void create_process(sel4utils_process_t *process, const uint8_t priority, 
    char *image_name, cspacepath_t *ep_cap_path, const seL4_Uint32 badge) {

    UNUSED int error;

    /* fill the allocator with virtual memory */
    void *vaddr;
    UNUSED reservation_t virtual_reservation;
    virtual_reservation = vspace_reserve_range(&vspace,
        ALLOCATOR_VIRTUAL_POOL_SIZE, seL4_AllRights, 1, &vaddr);
    assert(virtual_reservation.res);
    bootstrap_configure_virtual_pool(allocman, vaddr,
        ALLOCATOR_VIRTUAL_POOL_SIZE, simple_get_pd(&simple));
	
    /* use sel4utils to make a new process */
    error = sel4utils_configure_process(process, &vka, &vspace, priority, image_name);
	

    /* give the new process's thread a name */
    name_thread(process->thread.tcb.cptr, image_name);

    /* create an endpoint */
    vka_object_t ep_object = {0};
    error = vka_alloc_endpoint(&vka, &ep_object);
    assert(error == 0);

    /* make a badged enpoint in the new process's cspace. */
    vka_cspace_make_path(&vka, ep_object.cptr, ep_cap_path);
    seL4_CapData_t capData = seL4_CapData_Badge_new(badge);     
    seL4_CPtr dest_ep_cap = sel4utils_mint_cap_to_process(process, *ep_cap_path, seL4_AllRights, capData);
    assert(dest_ep_cap != 0);

    /* spawn the process */
    error = sel4utils_spawn_process_v(process, &vka, &vspace, 0, NULL, 1);

    printf("spawned a process, waiting for response\n");

    /* make sure the process starts by now */
    seL4_Word sender_badge;
	UNUSED seL4_MessageInfo_t tag = seL4_Wait(ep_cap_path->capPtr, &sender_badge);
    //seL4_Recv(ep_cap_path->capPtr, &sender_badge);
    seL4_Word msg = seL4_GetMR(0);
    printf("main: created a process and got a respond(%#x) from %#x badge\n", msg, sender_badge);

}


int main(void)
{
    UNUSED int error;

    /* give us a name: useful for debugging if the thread faults */
    name_thread(seL4_CapInitThreadTCB, "dhs-demo");

    /* get boot info */
    info = seL4_GetBootInfo();

    /* init simple */
    simple_default_init_bootinfo(&simple, info);

    /* get our cspace root cnode */
    UNUSED seL4_CPtr root_cspace_cap;
    root_cspace_cap = simple_get_cnode(&simple);

    /* print out bootinfo and other info about simple */
    simple_print(&simple);

    /* create an allocator */
    allocman = bootstrap_use_current_simple(&simple, ALLOCATOR_STATIC_POOL_SIZE,
        allocator_mem_pool);
    assert(allocman);

    /* create a vka (interface for interacting with the underlying allocator) */
	allocman_make_vka(&vka, allocman);

    /* create a vspace object to manage our vspace 
     * hint: sel4utils_bootstrap_vspace_with_bootinfo_leaky() */
    error = sel4utils_bootstrap_vspace_with_bootinfo_leaky(&vspace, &data, simple_get_pd(&simple), &vka, info);


	// Perform our own scheduling, using down counter, pause execution every 1ms 
	vka_object_t aep_object = {0};  
    error = vka_alloc_async_endpoint(&vka, &aep_object);
    assert(error == 0);
 
    seL4_timer_t *schedule_timer = sel4platsupport_get_default_timer(&vka, &vspace, &simple, aep_object.cptr);
    assert(schedule_timer != NULL);
    printf("[Attest Process] Init schedule timer\n");

    error = schedule_timer->timer->start(schedule_timer->timer);
    assert(error == 0);

    volatile int i;
    for(i=0; i<10000; i++) {}
    printf("current time: %llu\n", (schedule_timer->timer->get_time(schedule_timer->timer))/100);

    // ======================== Init Network Interface =============================
    struct ip_addr gw;
    lwip_iface_t* lwip_iface = network_init(&simple, &vka, &vspace, &gw);
    assert(lwip_iface != NULL);
    printf("[Attest Process] Network Interface is initialized\n");

    sel4utils_process_t p1, p2;
    cspacepath_t ep_cap_path;
	
	create_process(&p1, seL4_MaxPrio, "hello-4-app", &ep_cap_path, 0x81);
	create_process(&p2, seL4_MaxPrio, "hello-4-pad-app", &ep_cap_path, 0x82);

    sel4utils_destroy_process(&p1, &vka);
    //sel4utils_destroy_process(&p2, &vka);

    create_process(&p1, seL4_MaxPrio, "hello-4-app", &ep_cap_path, 0x81);
	//create_process(&p2, seL4_MaxPrio, "hello-4-pad-app", &ep_cap_path, 0x82);


    return 0;
    



}

