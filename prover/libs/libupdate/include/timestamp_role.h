#ifndef _TIMESTAMP_ROLE_H_
#define _TIMESTAMP_ROLE_H_

#include <metadata.h>

#pragma pack(push, 1)

// https://github.com/theupdateframework/tuf/blob/develop/tests/repository_data/repository/metadata/timestamp.json
typedef struct TimestampMeta {
    char name[MAX_NAME_SIZE];
    Hash_t hash[NUM_TIMESTAMP_HASHES];
    uint32_t len;
    uint32_t version;
} TimestampMeta_t;

typedef struct TimestampSigned {
    enum RoleType role_type;
    uint64_t timestamp;
    TimestampMeta_t meta; // snapshot
    uint32_t version;
} TimestampSigned_t;

typedef struct Timestamp {
    Signature_t signature[NUM_TIMESTAMP_KEYS];
    TimestampSigned_t signed_data;
} Timestamp_t;
#pragma pack(pop)

#endif
