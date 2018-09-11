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

#include <string.h>

#include <simon-speck/speck.h>
#include <simon-speck/simon.h>

#include <aes/aes_cbc.h>

#include <crypto-ed25519/libed25519/ed25519.h>

#include <sel4bench/sel4bench.h>

#include <update.h>
#include "json.h"

/* constants */

/* global environment variables */
seL4_BootInfo *info;
simple_t simple;
vka_t vka;
allocman_t *allocman;
vspace_t vspace;

/* static memory for the allocator to bootstrap with */
#define ALLOCATOR_STATIC_POOL_SIZE ((1 << seL4_PageBits) * 2000)
UNUSED static char allocator_mem_pool[ALLOCATOR_STATIC_POOL_SIZE];

/* dimensions of virtual memory for the allocator to use */
#define ALLOCATOR_VIRTUAL_POOL_SIZE ((1 << seL4_PageBits) * 3000)

/* static memory for virtual memory bootstrapping */
UNUSED static sel4utils_alloc_data_t data;

/* convenience function */
extern void name_thread(seL4_CPtr tcb, char *name);

int expire(uint64_t exp_timestamp)
{
    //uint64_t cur_timestamp = base_timestamp + get_time_in_tick(timer);
    return 0;
}

/*UNUSED static int install_image(image_download_t *d) {

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
    //write_to_mmc(d->img, d->len, proc->start_disk_block);
    printf("[Attest Process] Restarting %s process\n", proc->name);
    memcpy(_cpio_archive, d->img, d->len);
    reload_process(proc);

    printf("[Attest Process] Update Succeeds\n");
    return 0;
}*/

#define NUM_LA_KEYS 1

UNUSED void key_setup() {
    uint8_t in[16*3] = {0}, out[16] = {0}, rkey[32] = {0};
    cbc_mac_aes(in, out, 16*3, rkey, 256);
    
    int i;
    uint8_t digest[32] = {0};
    for(i=0; i<3; i++) {
        hmac_sha256_get(digest, in, 32, rkey, 32);
    }
}

UNUSED void validate_targets(TufClient_t saveTuf, Targets_t targets) {
    // Targets
    if(saveTuf.targets.signed_data.version > targets.signed_data.version) {
        //printf("[TUF] Targets version is lower [%d vs %d]\n", saveTuf.targets.signed_data.version, targets.signed_data.version);
    }

    if(expire(targets.signed_data.timestamp) == 1) {
        printf("[TUF] Targets Request is already expired\n");
    }
    if(verify_target(saveTuf, targets) == 0) {
        printf("[TUF] Targets signature verification failed\n");
    }

}

UNUSED void our_update(TufClient_t saveTuf, TufClient_t tmpTuf, Signature_t la_sigs[NUM_LA_KEYS], Key_t la_keys[NUM_LA_KEYS]) {

    key_setup();

    Targets_t targets = tmpTuf.targets;
    // Verify Local Adminstrator Signature
    int i;
    for(i=0; i<NUM_LA_KEYS; i++) {
        if(verify_sig(la_sigs[i], la_keys[i], (unsigned char*)&targets, sizeof(Targets_t)) == 0) printf("Verification is invalid\n");
    }
    validate_targets(saveTuf, targets);

}

UNUSED void tuf_update(TufClient_t saveTuf, TufClient_t tmpTuf) {

    // Root
	if(verify_root(saveTuf, tmpTuf.root) == 0) {
	    printf("[TUF] Root signature verification failed\n");
    }

    // Timestamp
    Timestamp_t ts = tmpTuf.timestamp;
    if(strcmp(ts.signed_data.meta.name, "snapshot") != 0) {
	    printf("[TUF] Invalid meta name: %s\n", ts.signed_data.meta.name);
    }

    if(saveTuf.timestamp.signed_data.version > ts.signed_data.version) {
	    printf("[TUF] Timestamp version is lower [%d vs %d]\n", saveTuf.timestamp.signed_data.version, ts.signed_data.version);
    }

    if(expire(ts.signed_data.timestamp) == 1) {
	    printf("[TUF] Timestamp Request is already expired\n");
    }
    if(verify_timestamp(saveTuf, ts) == 0) {
	    printf("[TUF] Timestamp signature verification failed\n");
    }

    // Snapshot
    Snapshot_t snapshot = tmpTuf.snapshot;
    if(saveTuf.snapshot.signed_data.version > snapshot.signed_data.version) {
        printf("[TUF] Snapshot version is lower [%d vs %d]\n", saveTuf.snapshot.signed_data.version, snapshot.signed_data.version);
    }
    if(expire(snapshot.signed_data.timestamp) == 1) {
        printf("[TUF] Snapshot Request is already expired\n");
    }

    if(verify_snapshot(saveTuf, snapshot) == 0) {
        printf("[TUF] Snapshot signature verification failed\n");
    }

    if(get_version(snapshot, "targets") <= saveTuf.root.signed_data.version) {
        printf("[TUF] Snapshot -> Targets does not change\n");
    }

    // Targets
    Targets_t targets = tmpTuf.targets;
    if(saveTuf.targets.signed_data.version > targets.signed_data.version) {
        printf("[TUF] Targets version is lower [%d vs %d]\n", saveTuf.targets.signed_data.version, targets.signed_data.version);
    }

    if(expire(targets.signed_data.timestamp) == 1) {
        printf("[TUF] Targets Request is already expired\n");
    }
    if(verify_target(saveTuf, targets) == 0) {
        printf("[TUF] Targets signature verification failed\n");
    }

}

// ---------------------------------------- Benchmark of JSON vs Binary format parsing ------------------------------

char *test_json = "{\n"
        "  \"Signatures\": [\n"
        "    {\n"
        "      \"ID\": 4,\n"
        "      \"TYPE\": 1,\n"
        "      \"SIG\": \"ebd7b4355f7ff4f8049e2358c5f92e734e2d10b93f449c989116d7433306dab3a34cf503c0bac2e90e39294424a30b6dcc468d8b100a99ae7e99b157e2a3bb01\"\n"
        "    },\n"
        "    {\n"
        "      \"ID\": 5,\n"
        "      \"TYPE\": 1,\n"
        "      \"SIG\": \"ebd7b4355f7ff4f8049e2358c5f92e734e2d10b93f449c989116d7433306dab3a34cf503c0bac2e90e39294424a30b6dcc468d8b100a99ae7e99b157e2a3bb01\"\n"
        "    }\n"
        "  ],\n"
        "  \"RoleType\": 2,\n"
        "  \"Expires\": 123451,\n"
        "  \"targets\": {\n"
        "    \"fuel\": {\n"
        "      \"Len\": 100,\n"
        "      \"HashTYPE\": 0,\n"
        "      \"Hash\": \"cd00e292c5970d3c5e2f0ffa5171e555bc46bfc4faddfb4a418b6840b86e79a3\"\n"
        "    },\n"
        "    \"speed\": {\n"
        "      \"Len\": 100,\n"
        "      \"HashTYPE\": 0,\n"
        "      \"Hash\": \"66fc1f9c1e8a4656fb5699bde4c9640efe859199c835270cd169ada282087b83\"\n"
        "    }\n"
        "  },\n"
        "  \"Version\": 1\n"
        "}";

static void process_json(Targets_t* targets, json_value* value)
{
    assert(value->type == json_object);
    json_value *v1, *v2, *v3;
    int i=0;
    const char* pos;
    // There are five objects
    // 0th is Signatures object -- skip for now
    v1 = value->u.object.values[0].value;
    assert(v1->type == json_array && v1->u.array.length == NUM_TARGETS_KEYS);
    for(i=0; i<NUM_TARGETS_KEYS; i++) {
        v2 = v1->u.array.values[i];
        // Three objects - ID, TYPE, SIG

        // ID
        v3 = v2->u.object.values[0].value;
        targets->signature[i].key_id = (uint32_t) v3->u.integer;

        // TYPE
        v3 = v2->u.object.values[1].value;
        targets->signature[i].type = v3->u.integer;

        // SIG
        v3 = v2->u.object.values[2].value;
        pos = v3->u.string.ptr;
        uint8_t *val = targets->signature[i].sig;
        for (size_t count = 0; count < MAX_SIG_SIZE; count++) {
            sscanf(pos, "%2hhx", &val[count]);
            pos += 2;
        }
    }

    // 1st is RoleType
    v1 = value->u.object.values[1].value;
    assert(v1->type == json_integer);
    targets->signed_data.role_type = (enum RoleType) v1->u.integer;

    // 2nd is Expires
    v1 = value->u.object.values[2].value;
    assert(v1->type == json_integer);
    targets->signed_data.timestamp = (uint32_t) v1->u.integer;

    // 3rd is Target
    v1 = value->u.object.values[3].value;
    // 2 sub-objects - one for each app
    for(i=0; i<NUM_TARGETS; i++) {
        // 3 sub-objects - Len, HashType and Hash
        v2 = v1->u.object.values[i].value;
        strcpy(targets->signed_data.meta[i].name, v1->u.object.values[i].name);

        // Len
        v3 = v2->u.object.values[0].value;
        targets->signed_data.meta[i].len = (uint32_t) v3->u.integer;

        // HashType
        v3 = v2->u.object.values[1].value;
        targets->signed_data.meta[i].hash[0].hash_type = (enum HashType) v3->u.integer;

        // Hash
        v3 = v2->u.object.values[2].value;
        pos = v3->u.string.ptr;
        uint8_t *val = targets->signed_data.meta[i].hash[0].hash;
        for (size_t count = 0; count < MAX_HASH_SIZE; count++) {
            sscanf(pos, "%2hhx", &val[count]);
            pos += 2;
        }
    }

    // 4th is version
    v1 = value->u.object.values[4].value;
    assert(v1->type == json_integer);
    targets->signed_data.version = (uint32_t) v1->u.integer;

}

void parse_json_test(Targets_t *out, char *test) {
    json_value* value = json_parse(test, strlen(test));
    process_json(out, value);

}

void parse_binary_test(Targets_t* out, void* test) {
    memcpy((void*) out, test, sizeof(Targets_t));
}

// -----------------------------------------------------------------------

#include <platsupport/clock.h>
#include <sel4platsupport/io.h>

int main(void)
{
    printf("[Attest Process] The attestation process starts\n");
    
    UNUSED int error;

    /* give us a name: useful for debugging if the thread faults */
    name_thread(seL4_CapInitThreadTCB, "update-benchmark");

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

    /*ps_io_mapper_t io_mapper = {0};
    error = sel4platsupport_new_io_mapper(simple, vspace, vka, &io_mapper);
    assert(error == 0);

    ps_io_ops_t io_ops = {
        .io_mapper = io_mapper,
    };*/

    /*clock_sys_t clock;
    error = clock_sys_init(&io_ops, &clock);
    assert(error == 0);

    clk_t *clk = clk_get_clock(&clock, CLK_ARM);
    assert(error == 0);

    freq_t freq = clk_set_freq(clk, 100*MHZ);
    printf("Set clock to %llu\n", freq);*/


    TufClient_t saveTuf, tmpTuf;
    memset(&saveTuf, 0, sizeof(TufClient_t));
    FullKey_t fullKey[NUM_TOTAL_KEYS] = {{0}};
    generate_default_metadata(&saveTuf.root, &saveTuf.timestamp, &saveTuf.snapshot, &saveTuf.targets, fullKey, ED25519);
    memcpy(&tmpTuf, &saveTuf, sizeof(TufClient_t));


    Targets_t out1, out2;

    int nxps = 1000, iii;

    sel4bench_init();
    uint64_t s = sel4bench_get_cycle_count();
    for(iii=0; iii<nxps; iii++) {
        parse_json_test(&out1, test_json);
    }
    uint64_t e = sel4bench_get_cycle_count();
    sel4bench_destroy();
    printf("Parsing JSON format takes: %llu, %llu\n", (e-s), (e-s)/nxps);

    void* in_bin = (void*)(&out1);
    
    sel4bench_init();
    s = sel4bench_get_cycle_count();
    for(iii=0; iii<nxps; iii++) {
        parse_binary_test(&out2, in_bin);
    }
    e = sel4bench_get_cycle_count();
    sel4bench_destroy();
    printf("Parsing binary format takes: %llu, %llu\n", (e-s), (e-s)/nxps);

    printf("Out1:==\n");
    print_targets_role(out1);
    printf("Out2:==\n");
    print_targets_role(out2);
    
    
    return 0;

    char new_image[100] = {0};
    memset(new_image, 11, 100);
    update_image(saveTuf.targets.signed_data.meta[0].name, new_image, 100, fullKey, &tmpTuf.root, &tmpTuf.timestamp, &tmpTuf.snapshot, &tmpTuf.targets);

    printf("ROOT generated\n");

    printf("Size: %d, %d, %d\n", sizeof(Signature_t), sizeof(Key_t), sizeof(Hash_t));

    printf("Size: %d, %d, %d, %d\n", sizeof(Root_t), sizeof(Timestamp_t), sizeof(Snapshot_t), sizeof(Targets_t));

    // ========================================================================


    int num_exps = 1000, i;
    uint64_t avg_time = 0;
    for(i=0; i<num_exps; i++) {
        sel4bench_init();
        uint64_t start = sel4bench_get_cycle_count();

        tuf_update(saveTuf, tmpTuf);

        uint64_t end = sel4bench_get_cycle_count();
        sel4bench_destroy();

        avg_time += (end-start)/num_exps;
    }
    printf("Verifying TUF metadata takes %llu\n", avg_time);


    enum Keytype kts[2] = {ED25519, HMACSHA256};
    int j;
    for(j=0; j<2; j++) {
        generate_default_metadata(&saveTuf.root, &saveTuf.timestamp, &saveTuf.snapshot, &saveTuf.targets, fullKey, kts[j]);
        saveTuf.root.signed_data.targets_role.threshold = 1;
        tmpTuf.root.signed_data.targets_role.threshold = 1;
        memset(&tmpTuf, 0, sizeof(TufClient_t));
        update_image(saveTuf.targets.signed_data.meta[0].name, new_image, 100, fullKey, &tmpTuf.root, &tmpTuf.timestamp, &tmpTuf.snapshot, &tmpTuf.targets);
        FullKey_t la_keys[NUM_LA_KEYS]; Key_t la_ks[NUM_LA_KEYS];
        Signature_t la_sigs[NUM_LA_KEYS];
        for(i=0; i<NUM_LA_KEYS; i++) {
            memset(la_keys[i].public_key, i+10, 32);
            memset(la_ks[i].public_key, i+10, 32);

            la_keys[i].type = HMACSHA256;
            la_keys[i].key_id = 11;
            la_ks[i].type = HMACSHA256;
            la_ks[i].key_id = 11;

            sign(&la_sigs[i], la_keys[i], (uint8_t*)&tmpTuf.targets, sizeof(Targets_t));
            
        }

        avg_time = 0;
        for(i=0; i<num_exps; i++) {
            sel4bench_init();
            uint64_t start = sel4bench_get_cycle_count();

            our_update(saveTuf, tmpTuf, la_sigs, la_ks);

            uint64_t end = sel4bench_get_cycle_count();
            sel4bench_destroy();

            avg_time += (end-start)/num_exps;
        }
        printf("Verifying our metadata takes %llu (authorization token type: %d)\n", avg_time, kts[j]);
 
        avg_time = 0;
        for(i=0; i<num_exps; i++) {
            sel4bench_init();
            uint64_t start = sel4bench_get_cycle_count();

            key_setup();

            uint64_t end = sel4bench_get_cycle_count();
            sel4bench_destroy();

            avg_time += (end-start)/num_exps;
        }
        printf("Key agreement takes %llu (type :%d)\n", avg_time, kts[j]);
     
        avg_time = 0;
        for(i=0; i<num_exps; i++) {
            sel4bench_init();
            uint64_t start = sel4bench_get_cycle_count();

            validate_targets(saveTuf, tmpTuf.targets);

            uint64_t end = sel4bench_get_cycle_count();
            sel4bench_destroy();

            avg_time += (end-start)/num_exps;
        }
        printf("Verifying our authorization token takes %llu (type :%d)\n", avg_time, kts[j]);
 
    }

    avg_time = 0;
    int len = 250000;
    uint8_t *img = malloc(len);
    uint8_t digest[32];
    for(i=0; i<num_exps; i++) {
        sel4bench_init();
        uint64_t start = sel4bench_get_cycle_count();

        sha256_get(digest, img, len);

        uint64_t end = sel4bench_get_cycle_count();
        sel4bench_destroy();

        avg_time += (end-start)/num_exps;
    }

    printf("Verifying image takes %llu\n", avg_time);

    return 0;
}


