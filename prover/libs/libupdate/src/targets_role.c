#include <targets_role.h>
#include <stdio.h>

int get_hash(Targets_t targets, const char* filename, Hash_t out[NUM_TARGETS_HASHES]) {
    int i;
    for(i=0; i<NUM_TARGETS; i++) {
        if(strcmp(targets.signed_data.meta[i].name, filename) == 0) {
            memcpy(out, targets.signed_data.meta[i].hash, sizeof(Hash_t)*NUM_TARGETS_HASHES);
            return i;
        }
    }
    return -1;
}


int get_meta(Targets_t targets, const char* filename, TargetsMeta_t *meta) {
    int i;
    for(i=0; i<NUM_TARGETS; i++) {
        if(strcmp(targets.signed_data.meta[i].name, filename) == 0) {
            memcpy(meta, &targets.signed_data.meta[i], sizeof(TargetsMeta_t));
            return i;
        }
    }
    return -1;
}

void print_targets_meta(TargetsMeta_t meta) {
    printf("{\n");
    printf("MetaName: %s\n", meta.name);
    printf("Len: %lu\n", meta.len);
    int i;
    for(i=0; i<NUM_TARGETS_HASHES; i++) {
        print_hash(meta.hash[i]);
    }
    printf("}\n");

}

void print_targets_role(Targets_t targets) {
    printf("TARGETS:\n{\n");
    printf("Signatures:\n{\n");
    int i;
    for(i=0; i<NUM_TARGETS_KEYS; i++) {
        print_signature(targets.signature[i]);
    }
    printf("}\n");
    printf("RoleType: %d\nExpires: %lu\nVersion: %d\n", targets.signed_data.role_type, targets.signed_data.timestamp, targets.signed_data.version);

    for(i=0; i<NUM_TARGETS; i++) {
        print_targets_meta(targets.signed_data.meta[i]);
    }
    printf("}\n");
}
