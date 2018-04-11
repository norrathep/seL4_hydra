#include <root_role.h>

int find_key(Root_t root, uint32_t key_id, Key_t *k) {
    int i;
    for(i=0; i<NUM_TOTAL_KEYS; i++) {
        if(root.signed_data.keys[i].key_id == key_id) {
            *k = root.signed_data.keys[i];
            return 1;
        }
    }
    return 0;
}

int find_key_index(Root_t root, uint32_t key_id) {
    int i;
    for(i=0; i<NUM_TOTAL_KEYS; i++) {
        if(root.signed_data.keys[i].key_id == key_id) {
            return i;
        }
    }
    return -1;
}
