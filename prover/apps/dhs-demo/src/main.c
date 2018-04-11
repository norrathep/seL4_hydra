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

//#include <vka/object.h>
//#include <vka/capops.h>

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

#include <string.h>

#include <attest.h>

#include <ethdrivers/lwip.h>

#include <lwip/udp.h>


#include <sel4bench/sel4bench.h>

#define UPDATE
#ifdef UPDATE
#include <crypto-ed25519/libed25519/ed25519.h>
#include <sdhc/mmc.h>
#include <update.h>
#include <sdhc/sdio.h>
#include <sdhc/plat/sdio.h>
#include <sel4utils/page_dma.h>
#include <sel4platsupport/io.h>
#elif defined(UPDATE_MINIMAL)
#include <crypto-ed25519/libed25519/ed25519.h>
#include <sdhc/mmc.h>
#include <auth_token.h>
#include <sdhc/sdio.h>
#include <sdhc/plat/sdio.h>
#include <sel4utils/page_dma.h>
#include <sel4platsupport/io.h>
#include <aes/aes_cbc.h>
#endif

#include "network.h"
#include "pbuf_helpers.h"


/* constants */

/* global environment variables */
seL4_BootInfo *info;
simple_t simple;
vka_t vka;
allocman_t *allocman;
vspace_t vspace;

#if defined(UPDATE) || defined(UPDATE_MINIMAL)
mmc_card_t *mmc_card;
ps_dma_man_t dma_man = {0};
static void read_from_mmc(uint8_t* mem, uint32_t len, unsigned long start_block);
static void write_to_mmc(uint8_t* mem, uint32_t len, unsigned long start_block);
#endif

// ----------------------- Demo Process ------------------
typedef struct demo_process {
    sel4utils_process_t p;
    uint32_t id;
    uint32_t version;
    uint8_t priority;
    char name[20];
    uint32_t badge;
    unsigned long start_disk_block;
    unsigned long exec_size;
} demo_process_t;

demo_process_t measure_process;
demo_process_t speed_process;

// ------------------------------------------------------

extern char _cpio_archive[];

/* static memory for the allocator to bootstrap with */
#define ALLOCATOR_STATIC_POOL_SIZE ((1 << seL4_PageBits) * 1000)
UNUSED static char allocator_mem_pool[ALLOCATOR_STATIC_POOL_SIZE];

/* dimensions of virtual memory for the allocator to use */
#define ALLOCATOR_VIRTUAL_POOL_SIZE ((1 << seL4_PageBits) * 2000)

/* static memory for virtual memory bootstrapping */
UNUSED static sel4utils_alloc_data_t data;

/* convenience function */
extern void name_thread(seL4_CPtr tcb, char *name);

int MAX_ATT_MEM_SIZE = 500000;// 11500000; // 11.5 MB
uint8_t *ATTESTED_MEMORY = NULL;

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
// More reliable way to malloc
void *large_malloc(size_t len)
{
    if(len <= 0) return NULL;
    int num_pages = 1 + ((len-1)/PAGE_SIZE);

    seL4_CPtr *frames = malloc(sizeof(seL4_CPtr)*num_pages);
    int k=0, error;
    
    // allocate pages
    for(k=0; k<num_pages; k++) {
        vka_object_t frame_obj = {0};
        error = vka_alloc_frame(&vka, seL4_PageBits, &frame_obj);
        //if(error != 0) printf("%d, %d\n", k, num_pages);
        assert(error == 0);
        frames[k] = frame_obj.cptr;
    }

    /* Now map it in */
    void *mapping = vspace_map_pages(&vspace, frames, NULL,  seL4_AllRights, num_pages, seL4_PageBits, 1);
    if (!mapping) {
        //vka_cnode_delete(&copy_path);
        for(k=0; k<num_pages; k++) 
            vka_cspace_free(&vka, frames[k]);
        return NULL;
    }
    return mapping;
}


void
oak_usleep(int usecs) {
    /* We need to spin because we do not as yet have a timer interrupt */
    while(usecs-- > 0){
        /* Assume 1 GHz clock */
        volatile int i = 1000;
        while(i-- > 0);
        //seL4_Yield();
    }

}

void create_process(demo_process_t *dp, cspacepath_t *ep_cap_path) {

    //oak_usleep(1000*1000*2, NULL);
    printf("====================================================================\n");
    printf("[Attest Process] Creating a process: %s\n", dp->name);
    UNUSED int error;

    #if defined(UPDATE)
    // read process's binary from disk
    printf("[Attest Process] Reading %s executable from MMC\n", dp->name);
    read_from_mmc((uint8_t*)_cpio_archive, (uint32_t) dp->exec_size, dp->start_disk_block);
    #endif

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

    printf("[Attest Process] Spawning %s process\n\n", dp->name);

    /* spawn the process */
    error = sel4utils_spawn_process_v(&dp->p, &vka, &vspace, 0, NULL, 1);

    /* make sure the process starts by now */
    seL4_Word sender_badge;
    UNUSED seL4_MessageInfo_t tag = seL4_Wait(ep_cap_path->capPtr, &sender_badge);

    dp->version = (uint32_t) seL4_GetMR(0);
    printf("[Attest Process] %s Version %d\n\n", dp->name, dp->version);

    printf("====================================================================\n");
    // Make it active
    seL4_SetMR(0, 0x19);
    seL4_Reply(tag);
    
}

void reload_process(demo_process_t *dp) {

    // first destroy the process
    sel4utils_destroy_process(&(dp->p), &vka);

    // re-spawn a process
    cspacepath_t s_path;
    create_process(dp, &s_path);

    printf("[Attest Process] created %s process\n", dp->name);

}
#ifdef CONFIG_PLAT_IMX6

#include <sel4platsupport/mach/gpt.h>

/*
 * network receiver handling
 * first receive the incoming request
 * then attest the process
 * reply with the attestation result
 */

seL4_timer_t *timer = NULL;

uint64_t get_time_in_tick(seL4_timer_t *t) {
    return (t->timer->get_time(t->timer))/100;
}
uint64_t base_timestamp = 0;

static int performing_att = 0;

// prevent padding
#pragma pack(push, 1)
typedef struct attest_request {
    uint8_t mac[32];
    uint64_t timestamp;
    uint32_t process_id;
} att_request_t;
#pragma pack(pop)

#if defined(UPDATE) || defined(UPDATE_MINIMAL)
UNUSED static void send_nack(struct udp_pcb *upcb) {
    // send ACK
    struct pbuf *pbuf;
    pbuf = pbuf_alloc(PBUF_TRANSPORT, 32, PBUF_RAM);
    assert(pbuf);
    uint32_t ack[32];
    memset(ack, 0, 32*sizeof(uint32_t));
    
    int unused = 0;
    pb_write_arrl(pbuf, ack, 32, &unused);
    int error = udp_send(upcb, pbuf);
    if(error) printf("Cant send ACK\n");
    pbuf_free(pbuf);
}

UNUSED static void send_ack(struct udp_pcb *upcb) {

    // send ACK
    struct pbuf *pbuf;
    pbuf = pbuf_alloc(PBUF_TRANSPORT, 32, PBUF_RAM);
    assert(pbuf);
    uint32_t ack[32];
    memset(ack, 1, 32*sizeof(uint32_t));
    
    int unused = 0;
    pb_write_arrl(pbuf, ack, 32, &unused);
    int error = udp_send(upcb, pbuf);
    if(error) printf("Cant send ACK\n");
    pbuf_free(pbuf);
}



// read data from MMC
UNUSED static void read_from_mmc(uint8_t* mem, uint32_t len, unsigned long start_block) {
    assert(mem != NULL);

    uint32_t block_size = mmc_block_size(*mmc_card);

    uint32_t num_blocks = len/block_size;
    if(len % block_size != 0) num_blocks++;

    char* vaddr = ps_dma_alloc(&dma_man, block_size, PAGE_SIZE_4K, 0, PS_MEM_NORMAL);
    assert(vaddr != NULL);
    
    uintptr_t paddr = ps_dma_pin(&dma_man, vaddr, block_size);

    uint32_t block_idx = 0, offset = 0;

    for(block_idx=0; block_idx<num_blocks; block_idx++) {
        long read_len = mmc_block_read(*mmc_card, start_block+block_idx, 1, vaddr, paddr, NULL, NULL);
        assert(read_len == block_size);
        memcpy((void*)(mem+offset), (void*) vaddr, block_size);
        offset += block_size;
    }

    ps_dma_unpin(&dma_man, vaddr, block_size);
    ps_dma_free(&dma_man, vaddr, block_size);
}


UNUSED static void write_to_mmc(uint8_t* mem, uint32_t len, unsigned long start_block) {
    assert(mem != NULL);

    uint32_t block_size = mmc_block_size(*mmc_card);

    uint32_t num_blocks = len/block_size;
    if(len % block_size != 0) num_blocks++;

    char* vaddr = ps_dma_alloc(&dma_man, block_size, PAGE_SIZE_4K, 0, PS_MEM_NORMAL);
    assert(vaddr != NULL);
    
    uintptr_t paddr = ps_dma_pin(&dma_man, vaddr, block_size);

    uint32_t block_idx = 0;
    uint32_t offset = 0;

    for(block_idx=0; block_idx<num_blocks; block_idx++) {
        memcpy((void*) vaddr, (void*)(mem+offset), block_size);
        long write_len = mmc_block_write(*mmc_card, start_block+block_idx, 1, vaddr, paddr, NULL, NULL);
        assert(write_len == block_size);
        offset += block_size;
    }

    ps_dma_unpin(&dma_man, vaddr, block_size);
    ps_dma_free(&dma_man, vaddr, block_size);

}

#endif

#ifdef UPDATE_MINIMAL

void key_setup() {
    uint8_t in[16*3] = {0}, out[16] = {0}, rkey[32] = {0};
    cbc_mac_aes(in, out, 16*3, rkey, 256);

    int i;
    uint8_t digest[32] = {0};
    for(i=0; i<3; i++) {
        hmac_sha256_get(digest, in, 32, rkey, 32);
    }
}

// Only work for benchmarking!
UNUSED static void update_handler(void *arg, struct udp_pcb *upcb,
    struct pbuf *p, struct ip_addr *addr, u16_t port)
{
    key_setup();
    AuthToken_t token = {0};
    uint8_t pk[32] = {0};
    int err = verify_authtoken(token, pk);

    SecContHeader_t header = {0};
    err += verify_seccont(header, pk);

}
#endif

#ifdef UPDATE

update_progress_t *progress = NULL;

/*
Overview of the Update Process

The software update system instructs TUF to check for updates.

TUF downloads and verifies timestamp.json.

If timestamp.json indicates that snapshot.json has changed, TUF downloads and verifies snapshot.json.

TUF determines which metadata files listed in snapshot.json differ from those described in the last snapshot.json that TUF has seen. 
If root.json has changed, the update process starts over using the new root.json.

TUF provides the software update system with a list of available files according to targets.json.

The software update system instructs TUF to download a specific target file.

TUF downloads and verifies the file and then makes the file available to the software update system.

If at any point in the above procedure there is a problem (i.e., if unexpired, signed, valid metadata cannot be retrieved from the repository), 
the Root file is downloaded and the process is retried once more (and only once to avoid an infinite loop). 
Optionally, the software update system using the framework can decide how to proceed rather than automatically downloading a new Root file.
*/

TufClient_t saveTuf, tmpTuf;

int MAX_IMAGE_SIZE = 300000;

int expire(uint64_t exp_timestamp)
{
    uint64_t cur_timestamp = base_timestamp + get_time_in_tick(timer);
    return cur_timestamp < exp_timestamp;
}

typedef enum TufState {WaitTimestamp=0, WaitRoot, WaitSnapshot, WaitTargets, WaitImage} TufState_t;
TufState_t tufState = WaitTimestamp;
image_download_t images[NUM_TARGETS] = {{0}};

UNUSED static int install_image(image_download_t *d) {

    // Once complete downloading the new image, perform an update
    assert(mmc_card != NULL);
    printf("\n\n[Attest Process] Received an Image. Verifying the hash.\n");

	int i, j;
    Hash_t cmp_digest[NUM_TARGETS_HASHES] = {{0}};
    if(get_hash(tmpTuf.targets, (const char*)d->img_name, cmp_digest) < 0) {
        printf("[Attest Process] Cannot get hash of image: %s\n", d->img_name);
        return -1;
    }
    for(j=0; j<NUM_TARGETS; j++) {
        uint8_t digest[64] = {0};
        sha256_get(digest, d->img, d->len);
        printf("Len: %d\n", d->len);
        printf("Recomputed hash: ");
        for(i=0; i<64; i++) printf("%02x ", digest[i]);
        printf("\nserver hash: ");
        for(i=0; i<64; i++) printf("%02x ", cmp_digest[j].hash[i]);
        printf("\n");

        if(memcmp(digest, cmp_digest[j].hash, 64) != 0) {
            printf("[Attest Process] Hash does not match. Abort the update\n");
            //return -1; TODO: uncomment
        }    
    }

    demo_process_t *proc;
    if(strcmp(d->img_name, "fuel") == 0) {
        proc = &measure_process;
    } else if(strcmp(d->img_name, "speed") == 0) {
        proc = &speed_process;
    } else return 1;

    printf("[Attest Process] Hash matches. Now updating %s process\n", proc->name);
    write_to_mmc(d->img, d->len, proc->start_disk_block);
    printf("[Attest Process] Restarting %s process\n", proc->name);
    memcpy(_cpio_archive, d->img, d->len);
    reload_process(proc);

    printf("[Attest Process] Update Succeeds\n");
    return 0;
}

UNUSED static int download_image(struct udp_pcb *upcb, struct pbuf *p, image_download_t *d) {
    uint32_t len = 0;
    int pos = 0;
    // Get packet length
    len = p->tot_len;

    printf("Receive %d bytes, ", len);

    int remaining = d->len - d->current_offset;
    if(len > remaining) len = remaining;

    printf("Remaining: %d bytes\n", remaining);
    pb_read(p, d->img+d->current_offset, len, &pos);
    assert(pbuf_free(p) != 0);
    
    d->current_offset += len;
    return 1;
}

// TODO: (1) wait for 10 seconds, if still in the same state, go back to WaitTimestamp
//       (2) download root?
//       (3) keep states -> which images will it download?
UNUSED static void tuf_handler(void *arg, struct udp_pcb *upcb,
    struct pbuf *p, struct ip_addr *addr, u16_t port)
{
    printf("In state: %d\n", tufState);
    int unused = 0;
    char *image_names[NUM_TARGETS] = {"fuel"}; // = {"fuel", "speed"};
    switch(tufState) {

        case WaitRoot:
        {
            // Currently, unsupported
            goto complete;
        }
        case WaitTimestamp:
        {
            // make a copy of saveTuf
            memcpy(&tmpTuf, &saveTuf, sizeof(TufClient_t));

            // Download and verify TimeStampRequest_t
            Timestamp_t ts;
            if(p->tot_len < sizeof(Timestamp_t)) {
                printf("[TUF] packet is smaller than timestamp request [%d vs %d]\n", p->tot_len, sizeof(Timestamp_t));
                goto error;
            }
            pb_read(p, &ts, sizeof(Timestamp_t), &unused);
            if(strcmp(ts.signed_data.meta.name, "snapshot") != 0) {
                printf("[TUF] Invalid meta name: %s\n", ts.signed_data.meta.name);
                goto error;
            }
            printf("Version: %d vs %d\n", saveTuf.timestamp.signed_data.version, ts.signed_data.version);

            // Do not update if the current version is already up-to-date
            if(saveTuf.timestamp.signed_data.version >= ts.signed_data.version) {
                printf("[TUF] Timestamp version is lower [%d vs %d]\n", saveTuf.timestamp.signed_data.version, ts.signed_data.version);
                goto error;
            }

            if(expire(ts.signed_data.timestamp) == 1) {
                printf("[TUF] Timestamp Request is already expired\n");
                goto error;
            }
            if(verify_timestamp(saveTuf, ts) == 0) {
                printf("[TUF] Timestamp signature verification failed\n");
                goto error;
            }
       
            // next state is snapshot 
            tufState = WaitSnapshot;
            memcpy(&tmpTuf.timestamp, &ts, sizeof(Timestamp_t));
            goto success;
        }
        case WaitSnapshot:
        {
            // Now download and verify SnapshotRequest_t
            Snapshot_t snapshot;
            if(p->tot_len < sizeof(Snapshot_t)) {
                printf("[TUF] packet is smaller than snapshot request\n");
                goto error;
            }
            pb_read(p, &snapshot, sizeof(Snapshot_t), &unused);

            printf("[TUF] Snapshot version [%d vs %d]\n", saveTuf.snapshot.signed_data.version, snapshot.signed_data.version);
            if(saveTuf.snapshot.signed_data.version > snapshot.signed_data.version) {
                printf("[TUF] Snapshot version is lower [%d vs %d]\n", saveTuf.snapshot.signed_data.version, snapshot.signed_data.version);
                goto error;
            }
            if(expire(snapshot.signed_data.timestamp) == 1) {
                printf("[TUF] Snapshot Request is already expired\n");
                goto error;
            }

            if(verify_snapshot(saveTuf, snapshot) == 0) {
                printf("[TUF] Snapshot signature verification failed\n");
                goto error;
            }

            if(get_version(snapshot, "root") > saveTuf.root.signed_data.version) {
                // If root has changed, download the new root and abort. TODO: how to verify the new root? skip it for now
            }

            memcpy(&tmpTuf.snapshot, &snapshot, sizeof(Snapshot_t));

            if(get_version(snapshot, "targets") <= saveTuf.root.signed_data.version) {
                // If targets is the same, do nothing.
                printf("[TUF] Snapshot -> Targets does not change\n");
                goto success;
            }

            tufState = WaitTargets;
            goto success;
        }
        case WaitTargets:
        {
            Targets_t targets;
            memset(&targets, 0, sizeof(Targets_t));
            if(p->tot_len < sizeof(Targets_t)) {
                printf("[TUF] packet is smaller than targets request\n");
                goto error;
            }
            pb_read(p, &targets, sizeof(Targets_t), &unused);

            printf("[TUF] Targets version [%d vs %d]\n", saveTuf.targets.signed_data.version, targets.signed_data.version);
            if(saveTuf.targets.signed_data.version > targets.signed_data.version) {
                printf("[TUF] Targets version is lower [%d vs %d]\n", saveTuf.targets.signed_data.version, targets.signed_data.version);
                goto error;
            }
            printf("Version: %d\n", targets.signed_data.version);

            if(expire(targets.signed_data.timestamp) == 1) {
                printf("[TUF] Targets Request is already expired\n");
                goto error;
            }
            if(verify_target(saveTuf, targets) == 0) {
                printf("[TUF] Targets signature verification failed\n");
                goto error;
            }
            memcpy(&tmpTuf.targets, &targets, sizeof(Targets_t));

            // Now storing new image's metadata
            tufState = WaitTimestamp;
            // Clear images' metadata
            int i;
            for(i=0; i<NUM_TARGETS; i++) {
                images[i].len = 0;
                images[i].current_offset = 0;
                images[i].complete = 0;
            }
            for(i=0; i<NUM_TARGETS; i++) {
                if(get_version(tmpTuf.snapshot, image_names[i]) > get_version(saveTuf.snapshot, image_names[i])) {

                    TargetsMeta_t meta = {{0}};
                    if(get_meta(targets, image_names[i], &meta) < 0) {
                        printf("error\n");
                        goto error;
                    } 
                    if(meta.len >= MAX_IMAGE_SIZE) {
                        printf("new image's size [%d] is too big\n", i);
                        goto error;
                    }

                    images[i].current_offset = 0;
                    images[i].len = meta.len;
                    images[i].complete = 0;
                    if(images[i].img == NULL) images[i].img = large_malloc(MAX_IMAGE_SIZE);
                    strcpy(images[i].img_name, meta.name);
                    tufState = WaitImage;

                    printf("[TUF] Updating image: %s from v%d to v%d, new_len: %d\n", image_names[i], 
                        get_version(saveTuf.snapshot, image_names[i]), get_version(tmpTuf.snapshot, image_names[i]), images[i].len);

                } else {
                    images[i].complete = 1;
                } 
            }
            goto success;
        }
        case WaitImage:
        {
            // If not complete, keep downloading.
            int i;
            for(i=0; i<NUM_TARGETS; i++) {
                if(images[i].complete) continue;
                if(images[i].current_offset < images[i].len) {
                    if(download_image(upcb, p, &images[i]) == 0) goto error;
                    if(images[i].current_offset >= images[i].len) images[i].complete = 2;
                    break;
                } 
            }

            int num_completes = 0;
            for(i=0; i<NUM_TARGETS; i++) num_completes += (images[i].complete > 0);

            assert(num_completes <= NUM_TARGETS);
            if(num_completes < NUM_TARGETS) goto success;
            else {
                // Perform an update -> onSuccess move tmpTuf to saveTuf and save it to disk
                for(i=0; i<NUM_TARGETS; i++) {
                    if(images[i].complete == 2 && install_image(&images[i]) != 0) goto error;
                }
                tufState = WaitTimestamp;
                goto complete;
            }

        }
        default:
            tufState = WaitTimestamp;
            return;
    }

    send_ack(upcb);
    tufState = WaitTimestamp;
    return;

complete:
    send_ack(upcb);
    printf("Complete\n");
    memcpy(&saveTuf, &tmpTuf, sizeof(TufClient_t));
    return;


// OnSuccess, save the state
success:
    send_ack(upcb);
    printf("Success\n");
    return;

error:
    // error should handle
    // Ideally, we want to retry...
    printf("Fail\n");
    send_nack(upcb);
    tufState = WaitTimestamp;
    return;
}

#endif

// attest binary in first eight pages...
static void attest_process(demo_process_t *dp, void* input, int input_size, uint8_t mac[32]) {

    int num_pages = 8;
    int mem_size = PAGE_SIZE*num_pages+input_size;
    assert(ATTESTED_MEMORY != NULL && MAX_ATT_MEM_SIZE > mem_size);
    memset(ATTESTED_MEMORY, 0, mem_size);
    int offset = 0;
    memcpy(ATTESTED_MEMORY, input, input_size);
    offset += input_size;

    char* elf_vstart = (char*)(dp->p.entry_point);

    int k;
    for(k=0; k<num_pages; k++) {
        seL4_CPtr frame = vspace_get_cap(&(dp->p.vspace), elf_vstart+PAGE_SIZE*k);

        char *mapping = sel4utils_dup_and_map(&vka, &vspace, frame, seL4_PageBits);
        assert(mapping != NULL);

        memcpy(ATTESTED_MEMORY+offset, mapping, PAGE_SIZE);
        offset += PAGE_SIZE;
        sel4utils_unmap_dup(&vka, &vspace, mapping, seL4_PageBits);
    }
 
    UNUSED uint64_t auth_time = MAC(ATTESTED_MEMORY, PAGE_SIZE*num_pages+input_size, NULL, 0, BLAKE2S, mac);

    /*printf("mac data: ");
    for(k=0; k<mem_size; k++) printf("%02x ", ATTESTED_MEMORY[k]);
    printf("\n");*/

}
int verify_update_request(uint8_t *cmac, uint8_t* data, int data_size) {
    assert(cmac != NULL);
    assert(data != NULL);

    // Assume it's blake2s for hash
    
    uint8_t mac[32];
    //printf("data size: %d bytes\n", data_size);
    UNUSED uint64_t auth_time = MAC(data, data_size, NULL, 0, BLAKE2S, mac);

    if(memcmp(mac, cmac, 32) != 0) return 0;   

    return 1;

}
UNUSED static void
recv_handler(void *arg, struct udp_pcb *upcb, struct pbuf *p,
          struct ip_addr *addr, u16_t port)
{
    performing_att = 1;

    printf("\n\n");
    printf("[Attest Process] Request arrives from ip: %s @ port %d\n", ipaddr_ntoa(addr), port);
    int pos = 0;

    assert(p->tot_len == sizeof(att_request_t));

    att_request_t att_req;
    pb_read(p, &att_req, sizeof(att_request_t), &pos);
    pbuf_free(p);

    uint8_t request_buffer[sizeof(att_request_t)];
    memcpy(request_buffer, &att_req, sizeof(att_request_t));

    printf("[Attest Process] Verifying Request... ");
    if(verify_update_request(att_req.mac, request_buffer+32, sizeof(att_request_t)-32) == 0) {
        printf("Invalid Mac\n");
        return;
    }


    if(base_timestamp == 0) base_timestamp = att_req.timestamp - get_time_in_tick(timer);

    /* check incoming request's timestamp for freshness */
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
    if(att_req.process_id == 2) target_process = speed_process;

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
#endif // CONFIG_IMX6

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

int main(void)
{
    printf("[Attest Process] The attestation process starts\n");
    
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

    /* create an allocator */
    allocman = bootstrap_use_current_simple(&simple, ALLOCATOR_STATIC_POOL_SIZE,
        allocator_mem_pool);
    assert(allocman);

    allocman_make_vka(&vka, allocman);

    error = sel4utils_bootstrap_vspace_with_bootinfo_leaky(&vspace, &data, simple_get_pd(&simple), &vka, info);

    #ifdef UPDATE
    memset(&saveTuf, 0, sizeof(TufClient_t));
    FullKey_t fullKey[NUM_TOTAL_KEYS];
    generate_default_metadata(&saveTuf.root, &saveTuf.timestamp, &saveTuf.snapshot, &saveTuf.targets, fullKey, ED25519);

    printf("Root generated\n");


    printf("Size: %d, %d, %d\n", sizeof(Signature_t), sizeof(Key_t), sizeof(Hash_t));

    printf("Size: %d, %d, %d, %d\n", sizeof(Root_t), sizeof(Timestamp_t), sizeof(Snapshot_t), sizeof(Targets_t));

    
    #endif

    #if defined(UPDATE) || defined(UPDATE_MINIMAL)
    ps_io_mapper_t io_mapper = {0};
    error = sel4platsupport_new_io_mapper(simple, vspace, vka, &io_mapper);
    assert(error == 0);

    error = sel4utils_new_page_dma_alloc(&vka, &vspace, &dma_man);
    assert(error == 0);

    ps_io_ops_t io_ops = {
        .io_mapper = io_mapper,
    };
    #endif

    // -------------------- malloc main memory ------------------- 

    ATTESTED_MEMORY = large_malloc(sizeof(uint8_t)*MAX_ATT_MEM_SIZE);
    assert(ATTESTED_MEMORY != NULL);
    printf("Malloc'ed main memory\n");

        
    lwip_iface_t* lwip_iface = NULL;
    // ================================= Init Micro-SD driver =================================
    #if defined(UPDATE) || defined(UPDATE_MINIMAL)
    
    printf("[Attest Process] Initializing MMC\n");
    sdio_host_dev_t* dev = (sdio_host_dev_t*) malloc(sizeof(*dev));
    assert(dev != NULL);
    memset(dev,0, sizeof(*dev));

    enum sdio_id id = sdio_default_id();
    error = sdio_init(id, &io_ops, dev);
    assert(error == 0);

    mmc_card = (mmc_card_t*) malloc(sizeof(*mmc_card));
    error = mmc_init(dev, &io_ops, mmc_card);
    assert(error == 0 && mmc_card != NULL);
    printf("[Attest Process] MMC is initialized\n");
   
    // ======================== Init Network Interface =============================
    struct ip_addr gw, verifier;
    lwip_iface = network_init(&simple, &vka, &vspace, &gw);
    assert(lwip_iface != NULL);
    printf("[Attest Process] Network Interface is initialized\n");

    /* =============================================================================
       ========================= Setup UDP ======================================== */
    ipaddr_aton("0.0.0.0", &verifier);
    struct udp_pcb *attest_pcb = NULL;
    init_udp_pcb(attest_pcb, &(lwip_iface->netif->ip_addr), 2000, &verifier, 10000, recv_handler, NULL);

    #ifdef UPDATE
    struct udp_pcb *update_pcb = NULL;
    init_udp_pcb(update_pcb, &(lwip_iface->netif->ip_addr), 3000, &verifier, 11000, tuf_handler, NULL);
    #elif defined(UPDATE_MINIMAL)
    struct udp_pcb *update_pcb = NULL;
    init_udp_pcb(update_pcb, &(lwip_iface->netif->ip_addr), 3000, &verifier, 11000, update_handler, NULL);
    #endif

    #endif


    // ========================= UDP setup complete =============================
    printf("[Attest Process] Attestation and Update Ports are initialized\n");

    // ======================== Spawn an app ===================================
    /* Now spawn a string process */
    measure_process.id = 1;
    measure_process.version = 0;
    measure_process.priority = seL4_MaxPrio-200;
    char *m_name = "fuel-level-app";
    strcpy(measure_process.name, m_name);
    measure_process.badge = 0x81;
    measure_process.start_disk_block = 0x100000;
    measure_process.exec_size = 0x40000;

    cspacepath_t s_path;
    create_process(&measure_process, &s_path);


    speed_process.id = 2;
    speed_process.version = 0;
    speed_process.priority = seL4_MaxPrio-200;
    m_name = "speedometer-app";
    strcpy(speed_process.name, m_name);
    speed_process.badge = 0x82;
    speed_process.start_disk_block = 0x200000;
    speed_process.exec_size = 0x40000;
    
    create_process(&speed_process, &s_path);

    // ========================================================================

    /* create an interrupt sync endpoint for timer driver */
    vka_object_t timer_object = {0};
    error = vka_alloc_async_endpoint(&vka, &timer_object);
    assert(error == 0);
    printf("[Attest Process] Alloc async endpoint\n");

    /* Start the timer - use 512 pre-scaler */
    timer = sel4platsupport_get_gpt(&vspace, &simple, &vka, timer_object.cptr, 512);
    error = timer->timer->start(timer->timer);
    assert(error == 0);
    printf("[Attest Process] Initialize the timer\n");

    // Perform our own scheduling, using down counter, pause execution every 1ms 
    vka_object_t aep_object = {0};
    error = vka_alloc_async_endpoint(&vka, &aep_object);
    assert(error == 0);

    seL4_timer_t *schedule_timer = sel4platsupport_get_default_timer(&vka, &vspace, &simple, aep_object.cptr);
    assert(schedule_timer != NULL);
    printf("[Attest Process] Init schedule timer\n");

    seL4_Word sender = 0;
    while(1) {
        if(performing_att == 0) {
            timer_oneshot_relative(schedule_timer->timer, 1000*1000);
            seL4_Wait(aep_object.cptr, &sender);
            sel4_timer_handle_single_irq(schedule_timer);
        }
        oak_usleep(1000);
        /* Handle pending network traffic */
        if(lwip_iface != NULL) ethif_lwip_poll(lwip_iface);

    }
    printf("shouldnt be here...\n");

    return 0;
}


