#ifndef _SNAPSHOT_ROLE_H_
#define _SNAPSHOT_ROLE_H_

#include <metadata.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 1)
// https://github.com/theupdateframework/tuf/blob/develop/tests/repository_data/repository/metadata/snapshot.json
typedef struct SnapshotMeta {
    char name[MAX_NAME_SIZE];
    uint32_t version;
} SnapshotMeta_t;

typedef struct SnapshotSigned {
    enum RoleType role_type;
    uint64_t timestamp;
    SnapshotMeta_t meta[NUM_SNAPSHOTS]; // root, targets, app1, app2, ...
    uint32_t version;
} SnapshotSigned_t;


typedef struct Snapshot {
    Signature_t signature[NUM_SNAPSHOT_KEYS];
    SnapshotSigned_t signed_data;
} Snapshot_t;

#pragma pack(pop)

int get_version(Snapshot_t sh, char* meta_name);


#ifdef __cplusplus
}
#endif

#endif
