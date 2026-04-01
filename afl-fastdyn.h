#ifndef AFL_FASTDYN_H
#define AFL_FASTDYN_H

#include <stddef.h>
#include <stdint.h>

int fastdyn_send(uint8_t *input, size_t size);
int fastdyn_recv(uint8_t *buffer, size_t size, uint32_t timeout);

// returns integer corresponding to a saved snapshot
int fastdyn_snap();

// restores process to given snapshot descriptor
int fastdyn_snap_restore(int snapshot);

// frees the memory saved for a snapshot
void fastdyn_snap_free(int snapshot);

#endif