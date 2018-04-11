#include <update.h>
#include <assert.h>

void print_update_request(update_req_t r) {
    int i;
    
    printf("=============================================================\n");
    printf("Size of update request: %d bytes\n", sizeof(update_req_t));
    // print mac
    printf("MAC: ");
    for(i=0; i<32; i++) printf("%02x ", r.mac[i]);
    printf("\n");

    printf("Sig: ");
    for(i=0; i<64; i++) printf("%02x ", r.signature[i]);
    printf("\n");

    printf("Public Key: ");
    for(i=0; i<32; i++) printf("%02x ", r.public_key[i]);
    printf("\n");

    printf("Hash: ");
    for(i=0; i<64; i++) printf("%02x ", r.hash[i]);
    printf("\n");

    printf("Version: %d - File Size: %d bytes - Process ID %d\n", r.version, r.file_size, r.process_id);
    printf("start_disk_addr: %d, start_cpio_addr: %d\n", r.start_disk_addr, r.start_cpio_addr);
    printf("=============================================================\n");
}

void sign(Signature_t *sig, FullKey_t key, const unsigned char* data, size_t len) {
    if(data == NULL && len != 0) return;

    sig->key_id = key.key_id;
    sig->type = key.type;
    uint64_t unused;
    switch(key.type) {
        case ED25519:
            ed25519_sign(sig->sig, data, len, key.public_key, key.private_key, &unused);
            return;
        case HMACSHA256:
            hmac_sha256_get(sig->sig, data, len, key.public_key, 32);
            return;
        default:
            printf("Signature scheme %d is not supported\n", key.type);
            return;
    }

}

void generate_keypair(FullKey_t *key, const unsigned char *seed, enum Keytype type) {
    key->type = type;
    uint8_t pkey[32] = {59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50, 21, 119, 29, 226, 67, 166, 58, 192, 72, 161, 139, 89, 218, 41};
    uint8_t  skey[32] = {80, 70, 173, 193, 219, 168, 56, 134, 123, 43, 187, 253, 208, 195, 66, 62, 88, 181, 121, 112, 181, 38, 122, 144, 245, 121, 96, 146, 74, 135, 241, 86};
    int i;
    switch(type) {
        case ED25519:
            //ed25519_create_keypair(pkey, skey, seed);
            for(i=0; i<32; i++) {
                key->public_key[i] = pkey[i];
                key->private_key[i] = skey[i];
            }
            return;
        case HMACSHA256:
            memset(key->public_key, seed[0], 32);
            memset(key->private_key, seed[0]+1, 32);
            return;
        default:
            printf("Keypair type %d is not supported\n", type);
            return;

    }
}

int verify_sig(Signature_t sig, Key_t key, const unsigned char* data, size_t len) {
    if(sig.key_id != key.key_id || sig.type != key.type) return -1;
    if(data == NULL && len != 0) return -1;

    uint64_t unused;
    uint8_t digest[32] = {0};
    switch(sig.type) {
        case ED25519:
            return ed25519_verify(sig.sig, data, len, key.public_key, &unused);
        case HMACSHA256:
            hmac_sha256_get(digest, data, len, key.public_key, 32);
            return (memcmp(digest, sig.sig, 32)==0);
        default:
            printf("Signature scheme %d is not supported\n", sig.type);
            return 0;   
    }
}

int verify_sig_with_threshold(Root_t root, Signature_t *sigs, int num_sigs, int threshold,
    const unsigned char* data, size_t len) {

    int correct = 0;
    int i;
    for(i=0; i<num_sigs; i++) {
        Key_t key;
        int key_exist = find_key(root, sigs[i].key_id, &key);
        if(key_exist && verify_sig(sigs[i], key, data, len)) correct++;
        if(correct >= threshold) return 1;
    }
    return correct >= threshold;
}

void generate_default_root(Root_t *root, FullKey_t fullKey[NUM_TOTAL_KEYS], enum Keytype kt) {
    root->signed_data.role_type = ROOT;
    root->signed_data.timestamp = 123451;
    root->signed_data.version = 1;
    int i;
    if(kt == ANY) kt = ED25519;
    for(i=0; i<NUM_TOTAL_KEYS; i++) {
        root->signed_data.keys[i].key_id = (uint32_t) i;
        root->signed_data.keys[i].type = kt;

        unsigned char seed[32] = {0};
        memset(seed, i, 32);

        //uint8_t public_key[32] = {0}, private_key[32] = {0};
        FullKey_t k = {0};
        //ed25519_create_keypair(public_key, private_key, seed);
        //memcpy(root->signed_data.keys[i].public_key, public_key, 32);
        generate_keypair(&k, seed, kt);
        memcpy(root->signed_data.keys[i].public_key, k.public_key, 32);

        if (fullKey != NULL) {
            fullKey[i].key_id = i;
            fullKey[i].type = kt;
            memcpy(fullKey[i].public_key, k.public_key, 32);
            memcpy(fullKey[i].private_key, k.private_key, 32);
        }

        //print_key(root->signed_data.keys[i]);
    }

    uint32_t idx=0;
    root->signed_data.root_role.threshold = 2;
    for(i=0; i<NUM_ROOT_KEYS; i++) {
        root->signature[i].key_id = idx;
        root->signed_data.root_role.key_id[i] = idx++;
    }

    root->signed_data.timestamp_role.threshold = 1;
    for(i=0; i<NUM_TIMESTAMP_KEYS; i++)
        root->signed_data.timestamp_role.key_id[i] = (idx++);

    root->signed_data.snapshot_role.threshold = 1;
    for(i=0; i<NUM_SNAPSHOT_KEYS; i++)
        root->signed_data.snapshot_role.key_id[i] = (idx++);

    root->signed_data.targets_role.threshold = 2;
    for(i=0; i<NUM_TARGETS_KEYS; i++)
        root->signed_data.targets_role.key_id[i] = (idx++);

    printf("Signing root role using keys:\n");
    // Sign root
    for(i=0; i<NUM_ROOT_KEYS; i++) {
        int key_idx = find_key_index(*root, root->signed_data.root_role.key_id[i]);
        assert(key_idx >= 0);
        //print_key(root->signed_data.keys[key_idx]);
        sign(&root->signature[i], fullKey[key_idx], (unsigned char*)(&root->signed_data), sizeof(RootSigned_t));
        /*ed25519_sign(root->signature[i].sig,
                     (unsigned char*)(&root->signed_data),
                     sizeof(RootSigned_t), fullKey[key_idx].public_key,
                     fullKey[key_idx].private_key, NULL);
        root->signature[i].key_id = (unsigned) key_idx;
        root->signature[i].type = ED25519;*/

    }
}

void generate_timestamp(const Root_t root, const Snapshot_t snapshot,
                        const FullKey_t fullKey[NUM_TOTAL_KEYS], Timestamp_t *ts) {
    
    ts->signed_data.role_type = TIMESTAMP;
    ts->signed_data.timestamp = 123451;
    ts->signed_data.version++;

    ts->signed_data.meta.version = snapshot.signed_data.version;
    strcpy(ts->signed_data.meta.name, "snapshot");
    ts->signed_data.meta.len = sizeof(Snapshot_t);


    int i;
    for(i=0; i<NUM_TIMESTAMP_HASHES; i++) {
        sha256_get(ts->signed_data.meta.hash[i].hash, (uint8_t *) (&snapshot), sizeof(Snapshot_t));
        ts->signed_data.meta.hash[i].hash_type = SHA256;
    }

    printf("Signing timestamp role using keys:\n");
    // Now sign
    for(i=0; i<NUM_TIMESTAMP_KEYS; i++) {
        int key_idx = find_key_index(root, root.signed_data.timestamp_role.key_id[i]);
        assert(key_idx >= 0);
        //print_key(root.signed_data.keys[key_idx]);
        sign(&ts->signature[i], fullKey[key_idx], (unsigned char*)(&ts->signed_data), sizeof(TimestampSigned_t));
        /*ed25519_sign(ts->signature[i].sig, (unsigned char*)(&ts->signed_data),
                     sizeof(TimestampSigned_t), fullKey[key_idx].public_key,
                     fullKey[key_idx].private_key, NULL);
        ts->signature[i].key_id = (unsigned) key_idx;
        ts->signature[i].type = ED25519;*/

    }
}


void generate_snapshot(const Root_t root, const Targets_t targets,
                        const FullKey_t fullKey[NUM_TOTAL_KEYS], Snapshot_t *snapshot, int app_change[NUM_TARGETS]) {

    snapshot->signed_data.role_type = SNAPSHOT;
    snapshot->signed_data.timestamp = 123451;
    snapshot->signed_data.version++;

    int i, idx=0;
    // Include root
    strcpy(snapshot->signed_data.meta[idx].name, "root");
    snapshot->signed_data.meta[idx].version = root.signed_data.version;
    idx++;

    // Include targets
    strcpy(snapshot->signed_data.meta[idx].name, "targets");
    snapshot->signed_data.meta[idx].version = targets.signed_data.version;
    idx++;

    // TODO: include apps
    for(i=0; i<NUM_TARGETS; i++) {
        strcpy(snapshot->signed_data.meta[idx+i].name, targets.signed_data.meta[i].name);
        if(app_change[i]) snapshot->signed_data.meta[idx+i].version++;
    }

    printf("Signing snapshot role using keys:\n");
    // Now sign
    for(i=0; i<NUM_TIMESTAMP_KEYS; i++) {
        int key_idx = find_key_index(root, root.signed_data.snapshot_role.key_id[i]);
        assert(key_idx >= 0);
        //print_key(root.signed_data.keys[key_idx]);
        sign(&snapshot->signature[i], fullKey[key_idx], (unsigned char*)(&snapshot->signed_data), sizeof(SnapshotSigned_t));
        /*ed25519_sign(snapshot->signature[i].sig, (unsigned char*)(&snapshot->signed_data),
                     sizeof(SnapshotSigned_t), fullKey[key_idx].public_key,
                     fullKey[key_idx].private_key, NULL);
        snapshot->signature[i].key_id = (unsigned) key_idx;
        snapshot->signature[i].type = ED25519;*/
    }
}


void generate_targets(const Root_t root, const TargetsMeta_t meta[NUM_TARGETS],
                       const FullKey_t fullKey[NUM_TOTAL_KEYS], Targets_t *targets) {

    targets->signed_data.role_type = TARGETS;
    targets->signed_data.timestamp = 123451;
    targets->signed_data.version++;
    int i;

    for(i=0; i<NUM_TARGETS; i++) {
        memcpy(&targets->signed_data.meta[i], &meta[i], sizeof(TargetsMeta_t));
    }

    printf("Signing targets role using keys:\n");
    // Now sign
    for(i=0; i<NUM_TARGETS_KEYS; i++) {
        int key_idx = find_key_index(root, root.signed_data.targets_role.key_id[i]);
        assert(key_idx >= 0);
        //print_key(root.signed_data.keys[key_idx]);
        sign(&targets->signature[i], fullKey[key_idx], (unsigned char*)(&targets->signed_data), sizeof(TargetsSigned_t));
        /*ed25519_sign(targets->signature[i].sig, (unsigned char*)(&targets->signed_data),
                     sizeof(TargetsSigned_t), fullKey[key_idx].public_key,
                     fullKey[key_idx].private_key, NULL);
        targets->signature[i].key_id = (unsigned) key_idx;
        targets->signature[i].type = ED25519;*/

    }
    //print_targets_role(*targets);
}

TargetsMeta_t generate_targets_meta(const uint8_t *image, size_t len, const char *name) {
    int i;
    TargetsMeta_t out = {{0}};
    for(i=0; i<NUM_TARGETS_HASHES; i++) {
        sha256_get(out.hash[i].hash, image, len);
        out.hash[i].hash_type = SHA256;
    }
    out.len = len;
    strcpy(out.name, name);
    return out;
}

void generate_random_image(uint8_t *image, size_t len, int seed) {
    assert(image != NULL);
    memset(image, seed, len);
}

void generate_random_targets_meta(const char image_names[NUM_TARGETS][MAX_NAME_SIZE], TargetsMeta_t *targetsMeta) {

    int i;
    size_t img_len;
    for(i=0; i<NUM_TARGETS; i++) {
        img_len = (size_t)(100);
        uint8_t *image = malloc(img_len);
        generate_random_image(image, img_len, i);
        free(image);

//        char image_name[MAX_NAME_SIZE] = {0};
//        sprintf(image_name, "%s_%d", image, i);

        TargetsMeta_t meta = generate_targets_meta(image, img_len, image_names[i]);
        memcpy(&targetsMeta[i], &meta, sizeof(TargetsMeta_t));
    }
}

// TODO: update_root

void update_image(const char *image_name, char *new_image, size_t len,
                  const FullKey_t fullKey[NUM_TOTAL_KEYS],
                  Root_t *root, Timestamp_t *ts, Snapshot_t *snapshot, Targets_t *targets) {
    TargetsMeta_t origMeta[NUM_TARGETS] = {{{0}}};
    memcpy(&origMeta, targets->signed_data.meta, NUM_TARGETS*sizeof(TargetsMeta_t));
    TargetsMeta_t newMeta = {{0}};
    int metaIdx = get_meta(*targets, image_name, &newMeta);

    newMeta = generate_targets_meta((uint8_t*)new_image, len, origMeta[metaIdx].name);
    memcpy(&origMeta[metaIdx], &newMeta, sizeof(TargetsMeta_t));

    generate_targets(*root, origMeta, fullKey, targets);

    int app_change[NUM_TARGETS] = {0};
    app_change[metaIdx] = 1;
    generate_snapshot(*root, *targets, fullKey, snapshot, app_change);

    generate_timestamp(*root, *snapshot, fullKey, ts);

}

void generate_default_metadata(Root_t *root, Timestamp_t *ts, Snapshot_t *snapshot, Targets_t *targets, FullKey_t fullKey[NUM_TOTAL_KEYS], enum Keytype kt) {

    generate_default_root(root, fullKey, kt);
    printf("Root generated\n");

    TargetsMeta_t targetsMeta[NUM_TARGETS];
    const char image_names[NUM_TARGETS][MAX_NAME_SIZE] = {"fuel", "speed"};

    /*int i;
    printf("sprinting\n");
    for(i=0; i<NUM_TARGETS; i++) {
        sprintf(image_names[i], "app_%d", i);
        printf("img: %s\n", image_names[i]);
    }*/

    generate_random_targets_meta(image_names, targetsMeta);
    printf("Targets meta generated\n");

    generate_targets(*root, targetsMeta, fullKey, targets);
    printf("Targets generated\n");

    int app_change[NUM_TARGETS] = {0};
    generate_snapshot(*root, *targets, fullKey, snapshot, app_change);
    printf("Snapshot generated\n");

    generate_timestamp(*root, *snapshot, fullKey, ts);
    printf("Timestamp generated\n");

}

void print_key(Key_t k) {
    printf("Printing key:\n");
    printf("ID: %x\n", k.key_id);
    printf("TYPE: %d\n", k.type);
    printf("PK: ");
    int i;
    for(i=0; i<32; i++) printf("%.2x ", k.public_key[i]);
    printf("\n");
}

void print_fullkey(FullKey_t k) {
    printf("Printing key:\n");
    printf("ID: %x\n", k.key_id);
    printf("TYPE: %d\n", k.type);
    printf("PK: ");
    int i;
    for(i=0; i<32; i++) printf("%d, ", k.public_key[i]);
    printf("\n");
    printf("SK: ");
    for(i=0; i<32; i++) printf("%d, ", k.private_key[i]);
    printf("\n");
}


