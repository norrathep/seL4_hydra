#ifndef _ROOT_ROLE_H_
#define _ROOT_ROLE_H_

#include <metadata.h>

#pragma pack(push, 1)
typedef struct RootRole {
    uint32_t key_id[NUM_ROOT_KEYS];
    uint8_t threshold;
} RootRole_t;

typedef struct TimestampRole {
    uint32_t key_id[NUM_TIMESTAMP_KEYS];
    uint8_t threshold;
} TimestampRole_t;

typedef struct SnapshotRole {
    uint32_t key_id[NUM_SNAPSHOT_KEYS];
    uint8_t threshold;
} SnapshotRole_t;

typedef struct TargetsRole {
    uint32_t key_id[NUM_TARGETS_KEYS];
    uint8_t threshold;
} TargetsRole_t;

// https://github.com/theupdateframework/tuf/blob/develop/tests/repository_data/repository/metadata/root.json
typedef struct RootSigned {
    enum RoleType role_type;
    uint64_t timestamp;
    Key_t keys[NUM_TOTAL_KEYS];
    RootRole_t root_role;
    TimestampRole_t timestamp_role;
    SnapshotRole_t snapshot_role;
    TargetsRole_t targets_role;
    uint32_t version;
} RootSigned_t;

typedef struct Root {
    Signature_t signature[NUM_ROOT_KEYS];
    RootSigned_t signed_data;
} Root_t;
#pragma pack(pop)

int find_key(Root_t root, uint32_t key_id, Key_t *k);

int find_key_index(Root_t root, uint32_t key_id);

#endif
