#include "types.h"
#include "aflnet.h"
#include "afl-fastdyn.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <fcntl.h>
#include <immintrin.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/eventfd.h>

#define FASTDYN_SHM_NAME      "/fastdyn_fuzzer_fd"
#define FASTDYN_LOOP_SHM_NAME "/fastdyn_loop_fd"

static int get_fd_from_shm(const char *name) {
    int sfd = shm_open(name, O_RDONLY, 0);
    if (sfd < 0) return -1;
    int *p = mmap(NULL, sizeof(int), PROT_READ, MAP_SHARED, sfd, 0);
    close(sfd);
    if (p == MAP_FAILED) return -1;
    int fd = *p;
    munmap(p, sizeof(int));
    return fd;
}

static int get_fuzzer_fd(void) {
    static int cached = -1;
    if (cached >= 0) return cached;
    cached = get_fd_from_shm(FASTDYN_SHM_NAME);
    if (cached < 0) perror("[fastdyn] shm_open failed — model not yet initialised?");
    return cached;
}

/* fd for the eventfd written by fuzz_eth_in on every entry into the firmware
 * input loop.  Cached on first use, same as get_fuzzer_fd(). */
static int get_loop_fd(void) {
    static int cached = -1;
    if (cached >= 0) return cached;
    cached = get_fd_from_shm(FASTDYN_LOOP_SHM_NAME);
    return cached;
}

static fastdyn_sync_state_t *get_sync_state(void) {
    static fastdyn_sync_state_t *cached = NULL;

    if (cached) return cached;

    int sfd = shm_open(FASTDYN_SYNC_SHM_NAME, O_RDWR, 0);
    if (sfd < 0) return NULL;

    cached = mmap(NULL, sizeof(*cached), PROT_READ | PROT_WRITE,
                  MAP_SHARED, sfd, 0);
    close(sfd);

    if (cached == MAP_FAILED) {
        cached = NULL;
        return NULL;
    }

    return cached;
}

static void drain_eventfd(int efd) {
    if (efd < 0) return;

    while (1) {
        uint64_t dummy;
        ssize_t n = read(efd, &dummy, sizeof(dummy));
        if (n == (ssize_t)sizeof(dummy)) continue;
        break;
    }
}

/*
 * fastdyn_send — inject one Ethernet frame into the model's RX path, then
 * wait up to timeout_ms for the firmware to finish processing it.
 *
 * Drains loop_evt_fd before injecting so that any eventfd count left from a
 * previous round is cleared. After write(), poll waits for loop_evt_fd only:
 * response availability on the data socket does not mean the firmware has
 * returned to fuzz_eth_in() and is safe for the next input yet.
 *
 * poll() intentionally does not consume the eventfd; fastdyn_recv() drains
 * the queued response frames first, then consumes the loop signal once the
 * response queue is empty.
 *
 * Returns:
 *   >= 0  bytes written, firmware acknowledged within timeout_ms
 *   -2    write succeeded but firmware did not return within timeout_ms (hang)
 *   -1    write failed
 */
int fastdyn_send(uint8_t *input, size_t size, uint32_t timeout_ms) {
    int fd  = get_fuzzer_fd();
    if (fd < 0) return -1;
    int lfd = get_loop_fd();
    fastdyn_sync_state_t *sync = get_sync_state();
    uint64_t expected = 0;

    /* Drain any stale eventfd count so only signals from this round unblock us. */
    if (sync) {
        expected = atomic_load_explicit(&sync->tx_seq, memory_order_relaxed) + 1;
        atomic_store_explicit(&sync->tx_seq, expected, memory_order_release);
    }
    drain_eventfd(lfd);

    ssize_t n = write(fd, input, size);
    if (n < 0) {
        if (sync)
            atomic_store_explicit(&sync->tx_seq, expected - 1, memory_order_release);
        printf("[fastdyn_send] failed to write - %zd\n", n);
        fprintf(stderr, "errno=%d\n", errno);
        return -1;
    }

    if (!sync || lfd < 0) {
        struct pollfd pfd = { .fd = lfd, .events = POLLIN };
        int rv;

        if (lfd < 0) return (int)n;

        rv = poll(&pfd, 1, (int)timeout_ms);
        if (rv == 0) return -2; /* timeout — firmware still processing */
        if (rv < 0) return -1;

        return (int)n;
    }

    while (atomic_load_explicit(&sync->ack_seq, memory_order_acquire) < expected) {
        struct pollfd pfd = { .fd = lfd, .events = POLLIN };
        int rv = poll(&pfd, 1, (int)timeout_ms);

        if (rv == 0) return -2; /* timeout — firmware still processing */
        if (rv < 0) {
            if (errno == EINTR) continue;
            return -1;
        }

        if (atomic_load_explicit(&sync->ack_seq, memory_order_acquire) >= expected)
            break;

        /* Woken by an older unread signal: drain and keep waiting for the
         * ack_seq that corresponds to this specific packet. */
        drain_eventfd(lfd);
    }

    return (int)n;
}

/*
 * fastdyn_recv — collect one Ethernet frame the firmware transmitted, or
 * detect that the firmware is back in the input loop without sending one.
 *
 * Polls both the data socketpair and loop_evt_fd.  Data takes priority: if
 * the data fd is readable, a response frame is available and is returned.
 * If only loop_evt_fd is readable, the firmware re-entered the input loop
 * without sending a response (frame dropped); the eventfd is consumed and
 * 0 is returned.  This makes every fastdyn_recv call after a send terminate
 * cleanly without timing out, even when aflnet calls recv multiple times.
 *
 * Returns:
 *   >0   response frame read into buffer
 *    0   loop signal received — firmware done, no response frame (drop)
 *   -1   error (fd unavailable, read error)
 *   -2   poll timed out — firmware did not respond within timeout_ms (hang)
 */
int fastdyn_recv(uint8_t *buffer, size_t size, uint32_t timeout_ms) {
    int fd  = get_fuzzer_fd();
    if (fd < 0) return -1;
    int lfd = get_loop_fd();

    struct pollfd pfds[2];
    int nfds = 0;
    pfds[nfds++] = (struct pollfd){ .fd = fd,  .events = POLLIN };
    if (lfd >= 0)
        pfds[nfds++] = (struct pollfd){ .fd = lfd, .events = POLLIN };

    int rv = poll(pfds, nfds, (int)timeout_ms);
    if (rv == 0) return -2; /* poll timed out — hang */
    if (rv < 0)  return -1; /* signal or error */

    /* Prefer a real response frame over the loop signal. */
    if (pfds[0].revents & POLLIN) {
        ssize_t n = read(fd, buffer, size);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return -1;
        return (int)n;
    }

    /* Loop signal: firmware is back in the input loop, no response frame. */
    if (lfd >= 0) {
        uint64_t val;
        read(lfd, &val, sizeof(val)); /* consume so the next round starts clean */
    }
    return 0;
}

/*
 * Restore firmware memory to a previously captured snapshot.
 * Returns 0 on success, -1 on invalid handle or restore failure.
 */
extern int g_snap_done_fd;
int fastdyn_snap_restore() {
    int fd = get_fuzzer_fd();
    if (fd < 0) return -1;

    /* Raw write — don't use fastdyn_send() here.  fastdyn_send() returns as
     * soon as loop_evt_fd fires (firmware entered the input hook), which
     * happens *before* the snapshot message is read and the restore runs.
     * We need to wait until the restore is fully done, not just until the
     * hook fires. */
    uint32_t snapshot_msg = 0x13243546;
    write(fd, &snapshot_msg, sizeof(snapshot_msg));

    /* Block until fuzz_snap_handler() writes g_snap_done_fd after the
     * restore completes.  No poll needed — blocking eventfd sleeps until
     * exactly one write arrives. */
    if (g_snap_done_fd >= 0) {
        uint64_t val;
        read(g_snap_done_fd, &val, sizeof(val));
    }

    return 0;
}


/*
 * fastdyn_trace_replay — replay one aflnet-format seed file on a loop until
 * fuzz_trace_compare() (called inside fuzz_snap_handler) finds a divergence.
 *
 * The seed file is the same raw concatenated Ethernet frame format used by
 * the fuzzer queue: back-to-back frames with boundaries determined by the
 * Ethernet/IP total-length fields (parsed by extract_requests_ethernet).
 * Each frame is injected individually via fastdyn_send/fastdyn_recv, matching
 * the per-message loop in send_over_fastdyn(), so the firmware sees exactly
 * the same packet sequence it would see during normal fuzzing.
 *
 * Usage:
 *   FASTDYN_TRACE_SEED=/path/to/afl-out/queue/id:000042 fastdyn run ...
 */
void fastdyn_trace_replay(const char *seed_path) {
    FILE *f = fopen(seed_path, "rb");
    if (!f) { perror("[trace] fopen seed"); return; }

    fseek(f, 0, SEEK_END);
    long file_sz = ftell(f);
    rewind(f);
    if (file_sz <= 0) { fclose(f); fprintf(stderr, "[trace] empty seed\n"); return; }

    uint8_t *seed = malloc((size_t)file_sz);
    if (!seed) { fclose(f); perror("[trace] malloc"); return; }
    if (fread(seed, 1, (size_t)file_sz, f) != (size_t)file_sz) {
        fclose(f); free(seed);
        fprintf(stderr, "[trace] short read\n"); return;
    }
    fclose(f);

    /* Split the seed into individual Ethernet frames using the same parser
     * that the main fuzzer loop uses. */
    unsigned int region_count = 0;
    region_t *regions = extract_requests_ethernet(seed, (unsigned int)file_sz,
                                                  &region_count);
    if (!regions || region_count == 0) {
        fprintf(stderr, "[trace] extract_requests_ethernet found no frames\n");
        free(seed);
        return;
    }

    printf("[trace] Replaying '%s': %u frame(s), %ld bytes — running until divergence.\n",
           seed_path, region_count, file_sz);

    uint8_t recv_buf[2048];
    uint32_t run = 0;

    while (1) {
        /* Send each frame in order, draining the response after each one —
         * identical to the inner loop of send_over_fastdyn(). */
        for (unsigned int i = 0; i < region_count; i++) {
            uint8_t  *frame     = seed + regions[i].start_byte;
            uint32_t  frame_len = (uint32_t)(regions[i].end_byte
                                             - regions[i].start_byte + 1);
            //printf("Injecting number %d\n", i);

            // printf("[trace] sending frame size %u:");
            // for (uint32_t i = 0; i < frame_len; i++) {
            //     printf(" %02x", frame[i]);
            // }
            // printf("\n");

            int rc = fastdyn_send(frame, frame_len, 5000);
            //printf("[trace] injected frame\n");
            if (rc == -2) {
                fprintf(stderr, "[trace] fastdyn_send timed out on frame %u, run %u\n",
                        i, run);
                goto next_run;
            }
            if (rc < 0) {
                fprintf(stderr, "Skipping this run, len = %u, ret = %d\n", frame_len, rc);
                goto next_run;
            }

            /* Drain any response frame the firmware produced. */
            fastdyn_recv(recv_buf, sizeof(recv_buf), 500);
        }

next_run:
        /* Trigger snapshot restore.  fuzz_snap_handler fires in the plugin
         * thread, calls fuzz_trace_compare(), and exits on divergence. */
        fastdyn_snap_restore();
        run++;
        printf("[trace] Run %u complete — identical so far.\n", run);
    }

    /* Unreachable (exit(0) fires inside fastdyn_trace_compare on divergence),
     * but free cleanly in case the loop is ever broken out of. */
    free(regions);
    free(seed);
}

/* -------------------------------------------------------------------------
 * TCP protocol extractors
 *
 * The request buffer and response buffer both consist of concatenated raw
 * IPv4 packets (no link-layer framing).  Each packet's length is read from
 * the IP total-length field so that packet boundaries can be determined
 * without any delimiter scanning.
 *
 * State representation: the TCP flags byte (offset 13 in the TCP header) is
 * used directly as the state integer.  The meaningful flag combinations are
 * compact (SYN=0x02, SYN-ACK=0x12, ACK=0x10, FIN=0x01, RST=0x04, …) so no
 * mapping step is needed.
 * -------------------------------------------------------------------------*/

#define TCP_IP_PROTO     6
#define TCP_MIN_IP_HDR  20
#define TCP_MIN_TCP_HDR 20

/*
 * Split a buffer of concatenated IPv4 packets into one region per packet.
 * Each region covers exactly one IP packet and is marked modifiable so
 * aflnet can independently mutate each message.
 */
region_t* extract_requests_tcp(unsigned char* buf, unsigned int buf_size,
                                unsigned int* region_count_ref)
{
    unsigned int region_count = 0;
    region_t    *regions      = NULL;
    unsigned int offset       = 0;

    while (offset < buf_size) {
        if (offset + TCP_MIN_IP_HDR > buf_size) break;

        /* IHL is the low nibble of byte 0, counted in 32-bit words. */
        unsigned int ihl = (unsigned int)(buf[offset] & 0x0F) * 4;
        if (ihl < TCP_MIN_IP_HDR) break; /* malformed */

        /* IP total length (bytes 2-3, big-endian) covers header + payload. */
        unsigned int total_len = ((unsigned int)buf[offset + 2] << 8)
                               |  (unsigned int)buf[offset + 3];

        if (total_len < ihl || offset + total_len > buf_size) {
            /* Truncated or malformed — clamp to remaining bytes. */
            total_len = buf_size - offset;
        }

        region_count++;
        regions = (region_t *)realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte     = (int)offset;
        regions[region_count - 1].end_byte       = (int)(offset + total_len - 1);
        regions[region_count - 1].modifiable     = 1;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count    = 0;

        offset += total_len;
    }

    /* Fallback: treat the whole buffer as a single region. */
    if (region_count == 0 && buf_size > 0) {
        regions = (region_t *)realloc(regions, sizeof(region_t));
        regions[0].start_byte     = 0;
        regions[0].end_byte       = (int)(buf_size - 1);
        regions[0].modifiable     = 1;
        regions[0].state_sequence = NULL;
        regions[0].state_count    = 0;
        region_count              = 1;
    }

    *region_count_ref = region_count;
    return regions;
}

/*
 * Walk a buffer of concatenated IPv4 packets and collect the TCP flags byte
 * from each TCP segment as a state code.
 *
 * The state sequence starts with 0 (the conventional "before any response"
 * state used by all aflnet extractors) and appends one entry per TCP packet.
 * Non-TCP packets are skipped silently.
 */
unsigned int* extract_response_codes_tcp(unsigned char* buf, unsigned int buf_size,
                                         unsigned int* state_count_ref)
{
    unsigned int *state_sequence = NULL;
    unsigned int  state_count    = 0;
    unsigned int  offset         = 0;

    /* Initial state 0 — mandatory by aflnet convention. */
    state_count++;
    state_sequence = (unsigned int *)realloc(state_sequence,
                                             state_count * sizeof(unsigned int));
    state_sequence[state_count - 1] = 0;

    while (offset < buf_size) {
        if (offset + TCP_MIN_IP_HDR > buf_size) break;

        unsigned int ihl = (unsigned int)(buf[offset] & 0x0F) * 4;
        if (ihl < TCP_MIN_IP_HDR) break;

        unsigned int total_len = ((unsigned int)buf[offset + 2] << 8)
                               |  (unsigned int)buf[offset + 3];
        if (total_len < ihl || offset + total_len > buf_size)
            total_len = buf_size - offset;

        /* Only TCP packets contribute a state entry. */
        if (buf[offset + 9] == TCP_IP_PROTO) {
            unsigned int tcp_off = offset + ihl;
            if (tcp_off + TCP_MIN_TCP_HDR <= buf_size) {
                /* Flags are at byte 13 of the TCP header. */
                unsigned int flags = (unsigned int)buf[tcp_off + 13];
                state_count++;
                state_sequence = (unsigned int *)realloc(state_sequence,
                                                         state_count * sizeof(unsigned int));
                state_sequence[state_count - 1] = flags;
            }
        }

        offset += total_len;
    }

    *state_count_ref = state_count;
    return state_sequence;
}
