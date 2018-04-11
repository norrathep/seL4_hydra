#ifndef _METADATA_H_
#define _METADATA_H_

#define NUM_APPS 2
#define NUM_ROOT_KEYS 4
#define NUM_ROLES 4

enum Keytype {ED25519} Keytype_t;
enum RoleType {ROOT, SNAPSHOT, TARGET, TIMESTAMP} RoleType_t;
enum HashType {SHA256, SHA512} HashType_t;

// TODO: Symmetric Keys - we dont need public_key
// Then Signature will contain MAC instead

typedef struct ServerKey {
	uint32_t key_id;
	enum Keytype type;
	uint8_t public_key[32];
	uint8_t private_key[32];
} ServerKey_t;

#pragma pack(1)
typedef struct Key {
    uint32_t key_id;
    enum Keytype type;
    uint8_t public_key[32];
} Key_t;

// sizeof(Signature) = 4+4+64 = 72
#pragma pack(1)
typedef struct Signature {
    uint32_t key_id;
    enum Keytype type;
    uint8_t sig[64];
} Signature_t;

#pragma pack(1)
typedef struct Role {
    enum RoleType type;
    uint32_t key_id;
    uint8_t threshold;
} Role_t;

// sizeof(FileMeta) = 16+4+64+1+4 = 89
#pragma pack(1)
typedef struct FileMeta {
    char name[16];
    enum HashType hash_type;
    uint8_t hash[64];
    uint32_t len;
} FileMeta_t;

// ---------------------------------------------------------------------------------------
//                  Now defining three metadata/requests: root, snapshot and targets
// ---------------------------------------------------------------------------------------

#pragma pack(1)
typedef struct RootRequest {
    Signature_t signature;
    enum RoleType role_type;
    uint64_t timestamp; // TODO: get no-padding here
    Key_t keys[NUM_ROOT_KEYS];
    Role_t roles[NUM_ROLES]; // root, snapshot, targets, and timestamp - assume each role has 1 key
    uint32_t version;
} RootRequest_t;

#pragma pack(1)
typedef struct SnapshotRequest {
    Signature_t signature;
    enum RoleType role_type;
    uint64_t timestamp; // TODO: get no-padding here
    FileMeta_t meta[2]; // targets and root
    uint32_t version;
} SnapshotRequest_t;

#pragma pack(1)
typedef struct TargetRequest {
    Signature_t signature;
    enum RoleType role_type;
    uint64_t timestamp; // TODO: get no padding here
    FileMeta_t meta[NUM_APPS];
    uint32_t version;
} TargetRequest_t;

// 89+4+16+72+4 = 177
#pragma pack(1)
typedef struct TimestampRequest {
    Signature_t signature; 
    enum RoleType role_type;
    uint64_t timestamp;
    FileMeta_t meta; // snapshot
    uint32_t version;      
} TimeStampRequest_t;

typedef struct AllMeta {
    FileMeta_t root;
    FileMeta_t snapshot;
    FileMeta_t targets;
    FileMeta_t apps[NUM_APPS];
} AllMeta_t;

typedef struct AllKeys {
    Key_t root;//[1];
    Key_t snapshot;//[1];
    Key_t targets;//[1];
    Key_t timestamp;//[1];
} AllKeys_t;

typedef struct TufClient {
    AllMeta_t metadata;
    RootRequest_t root; 
    AllKeys_t keys;
} TufClient_t;

#endif /* _METADATA_H_ */
