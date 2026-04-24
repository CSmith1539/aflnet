#ifndef AFL_FASTDYN_H
#define AFL_FASTDYN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdatomic.h>

#define FASTDYN_SYNC_SHM_NAME "/fastdyn_sync_state"

typedef struct {
  _Atomic uint64_t tx_seq;
  _Atomic uint64_t ack_seq;
} fastdyn_sync_state_t;

/* Forward declaration so the extractor signatures compile without pulling in
 * all of aflnet.h (which afl-fuzz.c includes separately before this header). */
#ifndef __AFLNET_H
typedef struct {
  int start_byte;
  int end_byte;
  char modifiable;
  unsigned int *state_sequence;
  unsigned int state_count;
} region_t;
#endif

/* Still used by protocol handlers in lwip_ip.c and fuzz.c. */
uint32_t fuzz_get_register(int reg);
void fuzz_set_register(uint32_t value, int reg);

int fuzz_write_memory(unsigned long long addr, uint8_t *mem_buf, int len);
int fuzz_read_memory(unsigned long long addr, uint8_t *mem_buf, int len);

int fastdyn_send(uint8_t *input, size_t size, uint32_t timeout_ms);
int fastdyn_recv(uint8_t *buffer, size_t size, uint32_t timeout);

/* TCP protocol extractors — plugged into aflnet via -P TCP */
region_t*     extract_requests_tcp(unsigned char* buf, unsigned int buf_size,
                                   unsigned int* region_count_ref);
unsigned int* extract_response_codes_tcp(unsigned char* buf, unsigned int buf_size,
                                         unsigned int* state_count_ref);

// frees the memory saved for a snapshot
void fastdyn_snap_free();

/*
 * Replay one seed file through the tap_fd IPC on a loop until
 * fuzz_trace_compare() (called inside fuzz_snap_handler) detects a divergence.
 * Enable tracing first via fuzz_trace_enable() (FASTDYN_TRACE_SEED env var
 * path in lwip_ip.c handles this automatically).
 */
void fastdyn_trace_replay(const char *seed_path);

/* Exported from fuzz_trace.c — used by -Z dry-run trace mode in afl-fuzz.c */
void fuzz_trace_enable(void);
void fuzz_trace_reset(void);

#endif
