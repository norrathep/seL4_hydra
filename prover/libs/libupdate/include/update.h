#ifndef _UPDATE_H_
#define _UPDATE_H_

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <metadata.h> 
#include <stdio.h>
#include <root_role.h>
#include <targets_role.h>
#include <timestamp_role.h>
#include <snapshot_role.h>
#include <sha/hmac-sha256.h>
#include <crypto-ed25519/libed25519/ed25519.h>

#ifdef __cplusplus
extern "C" {
#endif
typedef  struct update_req {
    uint8_t mac[32];
    uint32_t start_disk_addr;
    uint32_t start_cpio_addr;
    uint32_t version;
    uint32_t file_size;
    uint32_t process_id;
    uint8_t hash[64];
    uint8_t signature[64];
    uint8_t public_key[32];

} update_req_t;

typedef struct update_progress {
    uint32_t current_offset;
    uint32_t current_packet;
    update_req_t request;
} update_progress_t;

typedef struct image_download {
    uint32_t current_offset;
    uint32_t len;
    uint8_t complete;
    uint8_t *img;
    char img_name[MAX_NAME_SIZE];
} image_download_t;

typedef struct download_state {
    image_download_t fuel;
    image_download_t speed;
} download_state_t;

void print_update_request(update_req_t r);

void sign(Signature_t *sig, FullKey_t key, const unsigned char* data, size_t len);

int verify_sig(Signature_t sig, Key_t key, const unsigned char* data, size_t len);

int verify_sig_with_threshold(Root_t root, Signature_t *sigs, int num_sigs, int threshold,
    const unsigned char* data, size_t len);

void generate_default_metadata(Root_t *root, Timestamp_t *ts, Snapshot_t *snapshot, Targets_t *targets, FullKey_t fullKey[NUM_TOTAL_KEYS], enum Keytype kt);

void print_key(Key_t k);

void update_image(const char *image_name, char *new_image, size_t len,
                  const FullKey_t fullKey[NUM_TOTAL_KEYS],
                  Root_t *root, Timestamp_t *ts, Snapshot_t *snapshot, Targets_t *targets);


typedef struct TufClient {
    Root_t root;
    Timestamp_t timestamp;
    Snapshot_t snapshot;
    Targets_t targets;
} TufClient_t;


static int inline verify_root(TufClient_t save, Root_t root) {
    return verify_sig_with_threshold(save.root, root.signature,
                                     NUM_ROOT_KEYS, save.root.signed_data.root_role.threshold,
                                     (unsigned char*)(&root.signed_data),
                                     sizeof(RootSigned_t));
}

static int inline verify_target(TufClient_t save, Targets_t targets) {
    return verify_sig_with_threshold(save.root, targets.signature,
                                     NUM_TARGETS_KEYS, save.root.signed_data.targets_role.threshold,
                                     (unsigned char*)(&targets.signed_data),
                                     sizeof(TargetsSigned_t));
}

static int inline verify_snapshot(TufClient_t save, Snapshot_t snapshot) {
    return verify_sig_with_threshold(save.root, snapshot.signature,
                                     NUM_SNAPSHOT_KEYS, save.root.signed_data.snapshot_role.threshold,
                                     (unsigned char*)(&snapshot.signed_data),
                                     sizeof(SnapshotSigned_t));
}

static int inline verify_timestamp(TufClient_t save, Timestamp_t ts) {
    return verify_sig_with_threshold(save.root, ts.signature,
                                     NUM_TIMESTAMP_KEYS, save.root.signed_data.timestamp_role.threshold,
                                     (unsigned char*)(&ts.signed_data),
                                     sizeof(TimestampSigned_t));
}

#ifdef __cplusplus
}
#endif

#endif /* _UPDATE_H_ */
