#ifndef _METADATA_H_
#define _METADATA_H_

#include <update_common.h>

#define NUM_ROOT_KEYS 2
#define NUM_TIMESTAMP_KEYS 1
#define NUM_SNAPSHOT_KEYS 1
#define NUM_TARGETS_KEYS 2
#define NUM_TOTAL_KEYS NUM_ROOT_KEYS+NUM_TIMESTAMP_KEYS+NUM_SNAPSHOT_KEYS+NUM_TARGETS_KEYS

#define MAX_KEY_SIZE 32
#define MAX_SIG_SIZE 64
#define MAX_HASH_SIZE 64


#define MAX_NAME_SIZE 16

#define NUM_TARGETS 1 // number of running apps
#define NUM_SNAPSHOTS (1+1+NUM_TARGETS)

#define NUM_TIMESTAMP_HASHES 1
#define NUM_TARGETS_HASHES 1

enum Keytype {ANY, ED25519, HMACSHA256, Internal_ForceKeytypeIntSize = INT_MAX};

enum RoleType {ROOT, SNAPSHOT, TARGETS, TIMESTAMP, Internal_ForceRoletypeIntSize = INT_MAX};
enum HashType {SHA256, Internal_ForceHashtypeIntSize = INT_MAX};

#pragma pack(push, 1)

typedef struct FullKey {
    uint32_t key_id;
    enum Keytype type;
    uint8_t public_key[MAX_KEY_SIZE];
    uint8_t private_key[MAX_KEY_SIZE];
} FullKey_t;

typedef struct Key {
    uint32_t key_id;
    enum Keytype type;
    uint8_t public_key[MAX_KEY_SIZE];
} Key_t;

// sizeof(Signature) = 4+4+64 = 72
typedef struct Signature {
    uint32_t key_id;
    enum Keytype type;
    uint8_t sig[MAX_SIG_SIZE];
} Signature_t;

typedef struct Hash {
    enum HashType hash_type;
    uint8_t hash[MAX_HASH_SIZE];
} Hash_t;

#pragma pack(pop)


#endif /* _METADATA_H_ */
