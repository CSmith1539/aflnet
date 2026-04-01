#include "afl-fastdyn.h"

int fastdyn_send(uint8_t *input, size_t size) {
    return 0;
}

int fastdyn_recv(uint8_t *buffer, size_t size, uint32_t timeout) {
    return 0;
}

// returns integer corresponding to a saved snapshot
int fastdyn_snap() {
    printf("---------- Taking Snapshot ---------------\n");
    return 0;
}

// restores process to given snapshot descriptor
int fastdyn_snap_restore(int snapshot) {
    printf("---------- Restoring Snapshot ---------------\n");
    return 0;
}

// frees the memory saved for a snapshot
void fastdyn_snap_free(int snapshot) {
    printf("---------- Freeing Snapshot ---------------\n");
    return 0;
}