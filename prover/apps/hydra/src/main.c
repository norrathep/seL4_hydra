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

#include <simon-speck/speck.h>
#include <simon-speck/simon.h>
#include <attest.h>
#include <attest_config.h>

#include <sel4utils/irq_server.h>
#include <sel4bench/sel4bench.h>


//#define EXP1
//#define EXP2
//#define EXP3
//#define EXP4

/* constants */

/* global environment variables */
seL4_BootInfo *info;
simple_t simple;
vka_t vka;
allocman_t *allocman;
sel4utils_process_t string_p;
vspace_t vspace;

// ----------------------- Demo Process ------------------
typedef struct demo_process {
    sel4utils_process_t p;
    uint32_t id;
    uint32_t version;
    uint8_t priority;
    char name[20];
    uint32_t badge;
    //unsigned long start_disk_block;
    //uintptr_t start_cpio_addr;
    //unsigned long exec_size; // TODO:
} demo_process_t;

demo_process_t measure_process;

// ------------------------------------------------------

extern char _cpio_archive[];

#define PAGE_SIZE (1 << seL4_PageBits)

/* static memory for the allocator to bootstrap with */
#define ALLOCATOR_STATIC_POOL_SIZE ((1 << seL4_PageBits) * 2000)
UNUSED static char allocator_mem_pool[ALLOCATOR_STATIC_POOL_SIZE];

/* dimensions of virtual memory for the allocator to use */
#define ALLOCATOR_VIRTUAL_POOL_SIZE ((1 << seL4_PageBits) * 2000)

/* static memory for virtual memory bootstrapping */
UNUSED static sel4utils_alloc_data_t data;

/* convenience function */
extern void name_thread(seL4_CPtr tcb, char *name);

int MAX_ATT_MEM_SIZE = 150000; // 11.5 MB
uint8_t *ATTESTED_MEMORY = NULL;

UNUSED void create_process(demo_process_t *dp, cspacepath_t *ep_cap_path) {

    //printf("====================================================================\n");
    //printf("[Attest Process] Creating a process %s\n", dp->name);
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
    error = sel4utils_configure_process(&dp->p, &vka, &vspace, dp->priority, dp->name);

    /* give the new process's thread a name */
    name_thread((dp->p).thread.tcb.cptr, dp->name);

    /* create an endpoint */
    vka_object_t ep_object = {0};
    error = vka_alloc_endpoint(&vka, &ep_object);
    assert(error == 0);

    /* make a badged enpoint in the new process's cspace. */
    vka_cspace_make_path(&vka, ep_object.cptr, ep_cap_path);
    seL4_CapData_t capData = seL4_CapData_Badge_new(dp->badge);     
    seL4_CPtr dest_ep_cap = sel4utils_mint_cap_to_process(&dp->p, *ep_cap_path, seL4_AllRights, capData);
    assert(dest_ep_cap != 0);

    //printf("[Attest Process] Spawning %s process\n\n", dp->name);

    /* spawn the process */
    error = sel4utils_spawn_process_v(&dp->p, &vka, &vspace, 0, NULL, 1);

    //printf("[Attest Process] Waiting\n");
    /* make sure the process starts by now */
    seL4_Word sender_badge;
    UNUSED seL4_MessageInfo_t tag = seL4_Wait(ep_cap_path->capPtr, &sender_badge);

    dp->version = (uint32_t) seL4_GetMR(0);
    //printf("[Attest Process] %s Version %d\n\n", dp->name, dp->version);

    //printf("====================================================================\n");
    // Make it active
    seL4_SetMR(0, 0x19);
    seL4_Reply(tag);
    
}

void create_exp_processes(demo_process_t *dps, int num_p) {

    assert(dps != NULL);
    int i;
    for(i=0; i<num_p; i++) {
        dps[i].id = i+1;
        dps[i].version = 0;
        dps[i].priority = seL4_MaxPrio-200;
        char *m_name = "hydra-app";
        strcpy(dps[i].name, m_name);
        dps[i].badge = 0x81+i;
        cspacepath_t e_path;
        create_process(&dps[i], &e_path);
    }
}

void destroy_processes(demo_process_t *dps, int num_p) {

    int i;
    for(i=0; i<num_p; i++)  sel4utils_destroy_process(&(dps[i].p), &vka);

}

// prevent padding
#pragma pack(1)
typedef struct attest_request {
    uint8_t mac[32];
    uint64_t timestamp;
    uint32_t process_id;
} att_request_t;


int verify_request(uint8_t *cmac, uint8_t* data, int data_size, hmac_type type) {
    assert(cmac != NULL);
    assert(data != NULL);

    // Assume it's blake2s for hash
    
    uint8_t mac[32];
    //printf("data size: %d bytes\n", data_size);
    UNUSED uint64_t auth_time = MAC(data, data_size, NULL, 0, type, mac);

    if(memcmp(mac, cmac, 32) != 0) return 0;   

    return 1;

}

/*UNUSED static void map_mem(demo_process_t *dp, int num_pages) {
    int mem_size = PAGE_SIZE*num_pages;
    assert(ATTESTED_MEMORY != NULL && MAX_ATT_MEM_SIZE > mem_size);
    memset(ATTESTED_MEMORY, 0, mem_size);
    int offset = 0;

    char* elf_vstart = (char*)(dp->p.thread.stack_top);//(char*)(dp->p.entry_point);

    int k;
    for(k=0; k<num_pages; k++) {
        seL4_CPtr frame = vspace_get_cap(&(dp->p.vspace), elf_vstart-PAGE_SIZE*(k+1));

        char *mapping = sel4utils_dup_and_map(&vka, &vspace, frame, seL4_PageBits);
        assert(mapping != NULL);

        memcpy(ATTESTED_MEMORY+offset, mapping, PAGE_SIZE);
        offset += PAGE_SIZE;
        //sel4utils_unmap_dup(&vka, &vspace, mapping, seL4_PageBits);
    }
}*/
static uint64_t attest_process_pages(demo_process_t *dp, void* input, int input_size, uint8_t mac[32], int num_pages, hmac_type type) {
    int mem_size = PAGE_SIZE*num_pages+input_size;
    assert(ATTESTED_MEMORY != NULL && MAX_ATT_MEM_SIZE > mem_size);
    memset(ATTESTED_MEMORY, 0, mem_size);
    int offset = 0;
    memcpy(ATTESTED_MEMORY, input, input_size);
    offset += input_size;

    char* elf_vstart = (char*)(dp->p.thread.stack_top);//(char*)(dp->p.entry_point);

    int k;
    for(k=0; k<num_pages; k++) {
        seL4_CPtr frame = vspace_get_cap(&(dp->p.vspace), elf_vstart-PAGE_SIZE*(k+1));

        char *mapping = sel4utils_dup_and_map(&vka, &vspace, frame, seL4_PageBits);
        assert(mapping != NULL);

        memcpy(ATTESTED_MEMORY+offset, mapping, PAGE_SIZE);
        offset += PAGE_SIZE;
        sel4utils_unmap_dup(&vka, &vspace, mapping, seL4_PageBits);
    }
 
    sel4bench_init();
    uint64_t start = sel4bench_get_cycle_count();
    UNUSED uint64_t auth_time = MAC(ATTESTED_MEMORY, PAGE_SIZE*num_pages+input_size, NULL, 0, type, mac);
    uint64_t end = sel4bench_get_cycle_count();
    sel4bench_destroy();

    return end-start;
}

UNUSED static void attest_process(demo_process_t *dp, void* input, int input_size, uint8_t mac[32]) {
    int num_pages = 8;
    attest_process_pages(dp, input, input_size, mac, num_pages, BLAKE2S);
}

#ifdef CONFIG_PLAT_IMX6
/*
 * network receiver handling
 * first receive the incoming request
 * then attest the process
 * reply with the attestation result
 */
#include <ethdrivers/lwip.h>

#include <lwip/udp.h>
#include <sel4platsupport/mach/gpt.h>
#include "network.h"
#include "pbuf_helpers.h"

seL4_timer_t *timer = NULL;

uint64_t get_time_in_tick(seL4_timer_t *t) {
    return (t->timer->get_time(t->timer))/100;
}
uint64_t base_timestamp = 0;

static int performing_att = 0;

#define PACKET_TIMESTAMP_FIRST_IDX 0
#define PACKET_TIMESTAMP_SECOND_IDX PACKET_TIMESTAMP_SECOND_IDX+1
#define PACKET_NONCE_START_IDX PACKET_TIMESTAMP_SECOND_IDX+1
#define PACKET_NONCE_END_IDX PACKET_NONCE_START_IDX+7
#define PACKET_START_ADDR_IDX PACKET_NONCE_END_IDX+1
#define PACKET_ADDR_LENGTH_IDX PACKET_START_ADDR_IDX+1
#define PACKET_DIGEST_IDX PACKET_ADDR_LENGTH_IDX+1
#define PACKET_DIGEST_LENGTH 32
#define PACKET_NUM_PARAMS 20; //2+8+1+1+8; // timestamp | nonce | start_loc | length | MAC TODO: make it static or create a wrapper class for att request




UNUSED static void
recv_handler(void *arg, struct udp_pcb *upcb, struct pbuf *p,
          struct ip_addr *addr, u16_t port)
{
    performing_att = 1;

    printf("\n\n");
    printf("[Attest Process] Pragma Request arrives from ip: %s @ port %d\n", ipaddr_ntoa(addr), port);
    int pos = 0;


    assert(p->tot_len == sizeof(att_request_t));

    att_request_t att_req;
    pb_read(p, &att_req, sizeof(att_request_t), &pos);
    pbuf_free(p);

    uint8_t request_buffer[sizeof(att_request_t)];
    memcpy(request_buffer, &att_req, sizeof(att_request_t));

    printf("[Attest Process] Verifying Request... ");
    if(verify_request(att_req.mac, request_buffer+32, sizeof(att_request_t)-32, BLAKE2S) == 0) {
        printf("Invalid Mac\n");
        return;
    }

    if(base_timestamp == 0) base_timestamp = att_req.timestamp - get_time_in_tick(timer);

    uint64_t cur_timestamp = base_timestamp + get_time_in_tick(timer);
    uint64_t timestamp_abs_diff = (cur_timestamp > att_req.timestamp) ? cur_timestamp - att_req.timestamp : att_req.timestamp - cur_timestamp;
    #define FRESHNESS_DELTA 15*10000000 // 5 secs
    if(timestamp_abs_diff > FRESHNESS_DELTA) {
        printf("failed!\n");
        performing_att = 0;
        return;
    }

    uint8_t mac[32] = {0};
    demo_process_t target_process = measure_process;

    attest_process(&target_process,request_buffer+32, sizeof(att_request_t)-32, mac);

    struct pbuf *pbuf;
    pbuf = pbuf_alloc(PBUF_TRANSPORT, 32, PBUF_RAM);
    assert(pbuf);
    pos = 0;
    pb_write(pbuf, (void*) mac, 32, &pos);

    int error = udp_send(upcb, pbuf);

    if(error) printf("[Attest Process] fail to send attestation result\n\n");
    pbuf_free(pbuf);

    printf("[Attest Process] Attestation Completes\n");
    performing_att = 0;

}

#include <sel4utils/page_dma.h>
#include <sel4platsupport/io.h>

void init_udp_pcb(struct udp_pcb *pcb, ip_addr_t *self_ip, u16_t self_port,
    ip_addr_t *verifier, u16_t verifier_port, udp_recv_fn recv, void *recv_arg) {

    pcb = udp_new();
    assert(pcb != NULL);

    /* bind netif to local port, connect to GW and register receive handler */
    int error = udp_bind(pcb, self_ip, self_port);
    assert(error == 0);
    error = udp_connect(pcb, verifier, verifier_port);
    assert(error == 0);
    udp_recv(pcb, recv, recv_arg);

}




void
oak_usleep(int usecs, lwip_iface_t* lwip_iface) {
    /* We need to spin because we do not as yet have a timer interrupt */
    while(usecs-- > 0){
        /* Assume 1 GHz clock */
        volatile int i = 1000;
        while(i-- > 0);
        //seL4_Yield();
    }

    /* Handle pending network traffic */
    if(lwip_iface != NULL) ethif_lwip_poll(lwip_iface);
}

#endif
// ===========================================================================================
// ------------------------- Benchmarking Functions -------------------------------------------
/*void verify_request_benchmark(hmac_type ht, int unused) {
    uint8_t request_buffer[sizeof(att_request_t)];
    UNUSED uint8_t mac[64];
    verify_request(mac, request_buffer+32, sizeof(att_request_t)-32, ht);

    uint64_t att_req_ts = 0x1000000;
    uint64_t curr_ts = 0x100000;
    uint64_t base_ts = 0;
    if(base_ts == 0) base_ts = att_req_ts - curr_ts;

    uint64_t cur_timestamp = base_ts + curr_ts;
    uint64_t timestamp_abs_diff = (cur_timestamp > att_req_ts) ? cur_timestamp - att_req_ts : att_req_ts - cur_timestamp;
    #define FRESHNESS_DELTA 15*10000000 // 5 secs
    if(timestamp_abs_diff > FRESHNESS_DELTA) {
        return;
    }
}

void retrieve_mem_benchmark(hmac_type unused, int num_pages) {
    map_mem(&measure_process, num_pages);
}

void mac_mem_benchmark(hmac_type type, int num_pages) {
    UNUSED uint8_t mac[64] = {0};
    UNUSED uint64_t auth_time = MAC(ATTESTED_MEMORY, PAGE_SIZE*num_pages, NULL, 0, type, mac);
}



uint64_t benchmark(void (*benchmark_fn)(hmac_type, int), hmac_type ht, int num_pages, int num_exp) {
    int i;
    uint64_t avg_time = 0;
    // timing each iteration vs timing all? but latter could overflow cycle count
    for(i=0; i<num_exp; i++) {
        sel4bench_init();
        uint64_t start = sel4bench_get_cycle_count();
        (*benchmark_fn)(ht, num_pages);
        uint64_t end = sel4bench_get_cycle_count();
        sel4bench_destroy();
        avg_time += (end-start)/num_exp;
    }
    return avg_time;
}*/

// --------------------------------------------------------------------------------------------

int main(void)
{
    printf("[Attest Process] The attestation process starts\n");
    
    UNUSED int error;

    /* give us a name: useful for debugging if the thread faults */
    name_thread(seL4_CapInitThreadTCB, "hydra");

    /* get boot info */
    info = seL4_GetBootInfo();

    /* init simple */
    simple_default_init_bootinfo(&simple, info);

    /* get our cspace root cnode */
    UNUSED seL4_CPtr root_cspace_cap;
    root_cspace_cap = simple_get_cnode(&simple);

    /* create an allocator */
    allocman = bootstrap_use_current_simple(&simple, ALLOCATOR_STATIC_POOL_SIZE,
        allocator_mem_pool);
    assert(allocman);

	allocman_make_vka(&vka, allocman);

    error = sel4utils_bootstrap_vspace_with_bootinfo_leaky(&vspace, &data, simple_get_pd(&simple), &vka, info);

    // -------------------- malloc main memory ------------------- 

    ATTESTED_MEMORY = malloc(sizeof(uint8_t)*MAX_ATT_MEM_SIZE);
    assert(ATTESTED_MEMORY != NULL);

    // ======================== Init Network Interface =============================
    struct ip_addr gw;
    lwip_iface_t* lwip_iface = network_init(&simple, &vka, &vspace, &gw);
    assert(lwip_iface != NULL);
    printf("[Attest Process] Network Interface is initialized\n");

    /* =============================================================================
       ========================= Setup UDP ======================================== */
    struct udp_pcb *attest_pcb = NULL;
    //struct udp_pcb *update_pcb = NULL;

    //init_udp_pcb(update_pcb, &(lwip_iface->netif->ip_addr), 3000, &(lwip_iface->netif->gw), 11000, recv_update_handler, NULL);
    init_udp_pcb(attest_pcb, &(lwip_iface->netif->ip_addr), 2000, &(lwip_iface->netif->gw), 10000, recv_handler, NULL);


    // ========================= UDP setup complete =============================
    printf("[Attest Process] Attestation and Update Ports are initialized\n");

    
    /*sel4bench_init();
    uint64_t start = sel4bench_get_cycle_count();
    struct pbuf *pbuf;
    pbuf = pbuf_alloc(PBUF_TRANSPORT, 40*N, PBUF_RAM);
    assert(pbuf);
    int pos = 0;
    pb_write(pbuf, (void*) dummy, 40*N, &pos);
    uint64_t end = sel4bench_get_cycle_count();
    sel4bench_destroy();
    printf("Composing a UDP packet takes %llu cycle\n", end-start);

    sel4bench_init();
    start = sel4bench_get_cycle_count();
    error = udp_send(attest_pcb, pbuf);
    end = sel4bench_get_cycle_count();
    sel4bench_destroy();
    printf("Sending a UDP packet takes %llu cycle, error = %d\n", end-start, error);*/

    
    // ======================== Spawn an app ===================================
    /* Now spawn a string process */
    measure_process.id = 1;
    measure_process.version = 0;
    measure_process.priority = seL4_MaxPrio-200;
    char *m_name = "hydra-app";
    strcpy(measure_process.name, m_name);
    measure_process.badge = 0x81;
    cspacepath_t s_path;
    create_process(&measure_process, &s_path);

    // ========================================================================

    /* create an interrupt sync endpoint for timer driver */
    /*vka_object_t timer_object = {0};
    error = vka_alloc_async_endpoint(&vka, &timer_object);
    assert(error == 0);

    // Start the timer - use 512 pre-scaler 
    timer = sel4platsupport_get_gpt(&vspace, &simple, &vka, timer_object.cptr, 512);
    assert(timer != NULL && timer->timer != NULL);
    error = timer->timer->start(timer->timer);
    assert(error == 0);
    printf("[Attest Process] Initialize the timer\n");*/

    UNUSED uint64_t start_cycle, end_cycle;
    UNUSED uint8_t mac[32] = {0};

    UNUSED int i, j, k, mt = 0;
    UNUSED int num_exp = 1000, num_pages = 0;
    UNUSED uint64_t avg_time = 0;

    #ifdef EXP1
    // --------------------------------------------------------------------------------------------------
    // First experiment: Performance Breakdown of Attestation
    // VerifyRequest, RetrieveMem, MacMem
    // Default Page Size is 4096 bytes - 4KB

    // 20KB memory - 20/4 = 5 pages
    num_pages = 5;
    avg_time = benchmark(&verify_request_benchmark, SPECK, num_pages, num_exp);
    printf("20KB: VerifyRequest takes %llu cycles\n", avg_time);

    avg_time = benchmark(&retrieve_mem_benchmark, SPECK, num_pages, num_exp);
    printf("20KB: RetrieveMem takes %llu cycles\n", avg_time);

    avg_time = benchmark(&mac_mem_benchmark, SPECK, num_pages, num_exp);
    printf("20KB: MacMem takes %llu cycles\n", avg_time);

    // 1MB memory - 1024/4 = 256 pages
    num_pages = 256;
    avg_time = benchmark(&verify_request_benchmark, SPECK, num_pages, num_exp);
    printf("1MB: VerifyRequest takes %llu cycles\n", avg_time);

    avg_time = benchmark(&retrieve_mem_benchmark, SPECK, num_pages, num_exp);
    printf("1MB: RetrieveMem takes %llu cycles\n", avg_time);

    avg_time = benchmark(&mac_mem_benchmark, SPECK, num_pages, num_exp);
    printf("1MB: MacMem takes %llu cycles\n", avg_time);

    // Done ------------------------------------------------------------------------------------------------
    #endif

    #ifdef EXP2
    // ===============================================================================================
    // Second Experiment: Different Mac functions on 1MB memory (256 pages)
    // BLAKE2S, HMAC-SHA256, SIMON, SPECK, AES_128, AES_192, AES_256
    #define num_mac_types 8 
    hmac_type hts[num_mac_types] = {BLAKE2S, SHA_256, SIMON, SPECK, AES_128, AES_192, AES_256, BLAKE2S};
    num_pages = 256;

    for(i=0; i<num_mac_types; i++) {
        avg_time = benchmark(&mac_mem_benchmark, hts[i], num_pages, num_exp);
        printf("1MB: MacMem using %d takes %llu cycles\n", hts[i], avg_time);
    }

    // Done ==========================================================================================
    #endif

    #ifdef EXP3
    // -----------------------------------------------------------------------------------------------
    // Third Experiment: MapMem vs MacMem from 1MB (256) - 10MB (2560)
    // MacMem with different mac functions too
    // Change stack size in menuconfig to 13000000
    // NOTE: this experiment could be problematic since map_mem_benchmark does not unmap
    // Might need to rerun multiple times
    #define num_mac_types_exp3 6
    hmac_type hts_exp3[num_mac_types_exp3] = {BLAKE2S, SHA_256, SIMON, SPECK, AES_128, BLAKE2S};
    for(i=1; i<11; i++) {
    //for(i=10; i>0; i--) {
        num_pages = i*256;
        //avg_time = benchmark(&retrieve_mem_benchmark, SPECK, num_pages, num_exp);
        //printf("%dMB: MapMem takes %llu cycles\n", i, avg_time);
        for(j=0; j<num_mac_types_exp3; j++) {
            avg_time = benchmark(&mac_mem_benchmark, hts_exp3[j], num_pages, num_exp);
            printf("%dMB: MacMem using %d takes %llu cycles\n", i, hts_exp3[j], avg_time);
        }
    }
    // Done ------------------------------------------------------------------------------------------
    #endif

    #ifdef EXP4
    // ===============================================================================================
    // Fourth Experiment: This is possibly the trickiest one
    // MacMem (100KB - 25 Pages) vs NumProcess (2-20 additional Processes)
    // Change stack size in menuconfig to 150000

    #define num_mac_types_exp4 2
    hmac_type hts_exp4[num_mac_types_exp4] = {BLAKE2S, SPECK};

    int max_processes = 20;
    demo_process_t *exp_p = malloc(sizeof(demo_process_t)*max_processes);
    // Spawn 2-max_processes processes
    //for(i=2; i<=max_processes; i+=2) {
    for(i=max_processes; i>=2; i-=2) {
        create_exp_processes(exp_p, i);

        // Benchmark for each MAC function
        for(mt = 0; mt<num_mac_types_exp4; mt++) {
            avg_time = 0;
            
            // Compute avg run-time in num_exp experiments
            for(j=0; j<num_exp; j++) {
                // Attest i processes, 25*4096 ~= 100KB each
                for(k=0; k<i; k++) {
                    uint8_t mac[32] = {0};
                    avg_time += attest_process_pages(&exp_p[k], NULL, 0, mac, 25, hts_exp4[mt])/num_exp; 
                }
            }
            printf("MAC type %d, # processes: %d, avg attested time: %llu\n", hts_exp4[mt], i, avg_time);
        }
        destroy_processes(exp_p, i);
    }
    // Done =========================================================================================
    #endif

    //return 0;


    // Perform our own scheduling, using down counter, pause execution every 1ms 
    vka_object_t aep_object = {0};
    error = vka_alloc_async_endpoint(&vka, &aep_object);
    assert(error == 0);
    seL4_timer_t *schedule_timer = sel4platsupport_get_default_timer(&vka, &vspace, &simple, aep_object.cptr);
    assert(schedule_timer != NULL);

    seL4_Word sender = 0;
    //int i = 0;
    while(1) {
        if(performing_att == 0) {
            timer_oneshot_relative(schedule_timer->timer, 1000*1000);
            //i++;
            seL4_Wait(aep_object.cptr, &sender);
            //if(i == 10) produce_measurement();
            sel4_timer_handle_single_irq(schedule_timer);
        }
    	oak_usleep(1000, lwip_iface);
    }

    return 0;
}
