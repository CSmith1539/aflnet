#ifndef AFL_FASTDYN_H
#define AFL_FASTDYN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define FASTDYN_SHM_NAME      "/fastdyn_fuzzer_fd"
#define FASTDYN_MSG_MAGIC     0x4644594eu /* FDYN */
#define FASTDYN_MAX_FRAME     65536u

#define FASTDYN_TRACE_INITIAL_CAP (16384 * 4)   /* Initial PCs per run. */

typedef struct {
    uint32_t count;
    uint32_t capacity;
    uint32_t *entries;
} fastdyn_trace_run_t;

typedef enum {
  FASTDYN_MSG_INPUT = 1,
  FASTDYN_MSG_RESPONSE,
  FASTDYN_MSG_DONE,
  FASTDYN_MSG_RESTORE,
  FASTDYN_MSG_RESTORE_DONE,
} fastdyn_msg_type_t;

typedef struct {
  uint32_t magic;
  uint32_t type;
  uint64_t seq;
  uint32_t len;
} fastdyn_msg_hdr_t;

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

/* Attach the datagram endpoint supplied by the in-process FastDyn bridge. */
int fastdyn_attach_fd(int fd);

int fastdyn_send(uint8_t *input, size_t size, uint32_t timeout_ms);
int fastdyn_recv(uint8_t *buffer, size_t size, uint32_t timeout);
int fastdyn_snap_restore(uint32_t timeout_ms);

/* TCP protocol extractors — plugged into aflnet via -P TCP */
region_t*     extract_requests_tcp(unsigned char* buf, unsigned int buf_size,
                                   unsigned int* region_count_ref);
unsigned int* extract_response_codes_tcp(unsigned char* buf, unsigned int buf_size,
                                         unsigned int* state_count_ref);

// frees the memory saved for a snapshot
void fastdyn_snap_free();

/* Exported from fuzz_trace.c — used by -Z dry-run trace mode in afl-fuzz.c */
void fuzz_trace_enable(int max_entries);
void fuzz_trace_reset(void);

#endif
