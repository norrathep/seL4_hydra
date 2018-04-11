#include <snapshot_role.h>

int get_version(Snapshot_t sh, char* meta_name) {
    SnapshotMeta_t *meta = sh.signed_data.meta;
    
    // Find name in meta
    int i=0;
    for(i=0; i<NUM_TARGETS+2; i++) {
        SnapshotMeta_t current = meta[i];
	if(strcmp(current.name, meta_name) == 0) return current.version;
    }
    // It does not contain name
    return -1;
}
