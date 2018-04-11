#ifndef _TARGETS_ROLE_H_
#define _TARGETS_ROLE_H_

#include <metadata.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 1)
// https://github.com/theupdateframework/tuf/blob/develop/tests/repository_data/repository/metadata/targets.json
typedef struct TargetsMeta {
    char name[MAX_NAME_SIZE];
    Hash_t hash[NUM_TARGETS_HASHES];
    uint32_t len;
} TargetsMeta_t;

typedef struct TargetsSigned {
    enum RoleType role_type;
    uint64_t timestamp; 
    TargetsMeta_t meta[NUM_TARGETS];
    uint32_t version;
} TargetsSigned_t;

typedef struct Targets {
    Signature_t signature[NUM_TARGETS_KEYS];
    TargetsSigned_t signed_data;
} Targets_t;
#pragma pack(pop)

int get_hash(Targets_t targets, const char* filename, Hash_t out[NUM_TARGETS_HASHES]);

int get_meta(Targets_t targets, const char* filename, TargetsMeta_t *meta);

void print_targets_role(Targets_t targets);

#ifdef __cplusplus
}
#endif

#endif
