#include <sys/time.h>

#include "types.h"
#include "aflnet.h"
#include "afl-fastdyn.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/shm.h>

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

static int g_attached_fd = -1;

static int get_fuzzer_fd(void) {
    static int cached = -1;
    if (g_attached_fd >= 0) return g_attached_fd;
    if (cached >= 0) return cached;
    cached = get_fd_from_shm(FASTDYN_SHM_NAME);
    if (cached < 0) perror("[fastdyn] shm_open failed - model not yet initialised?");
    return cached;
}

int fastdyn_attach_fd(int fd)
{
    if (fd < 0) {
        errno = EINVAL;
        return -1;
    }

    g_attached_fd = fd;
    return 0;
}

typedef struct pending_frame {
    struct pending_frame *next;
    size_t len;
    uint8_t data[];
} pending_frame_t;

static pending_frame_t *g_pending_head;
static pending_frame_t *g_pending_tail;
static uint64_t g_next_seq;
static uint8_t g_wire_buf[sizeof(fastdyn_msg_hdr_t) + FASTDYN_MAX_FRAME];

static int queue_response(const uint8_t *data, size_t len)
{
    pending_frame_t *node = malloc(sizeof(*node) + len);
    if (!node) return -1;

    node->next = NULL;
    node->len = len;
    if (len != 0) memcpy(node->data, data, len);

    if (g_pending_tail) {
        g_pending_tail->next = node;
    } else {
        g_pending_head = node;
    }
    g_pending_tail = node;
    return 0;
}

static int pop_response(uint8_t *buffer, size_t size)
{
    pending_frame_t *node = g_pending_head;
    if (!node) return 0;

    size_t copy_len = node->len < size ? node->len : size;
    if (copy_len != 0) memcpy(buffer, node->data, copy_len);

    g_pending_head = node->next;
    if (!g_pending_head) g_pending_tail = NULL;
    free(node);
    return (int)copy_len;
}

static void clear_responses(void)
{
    while (g_pending_head) {
        pending_frame_t *node = g_pending_head;
        g_pending_head = node->next;
        free(node);
    }
    g_pending_tail = NULL;
}

static int send_msg(fastdyn_msg_type_t type,
                    uint64_t seq,
                    const uint8_t *data,
                    size_t len)
{
    int fd = get_fuzzer_fd();
    if (fd < 0 || len > FASTDYN_MAX_FRAME) return -1;

    size_t total = sizeof(fastdyn_msg_hdr_t) + len;
    uint8_t *packet = malloc(total);
    if (!packet) return -1;

    fastdyn_msg_hdr_t hdr = {
        .magic = FASTDYN_MSG_MAGIC,
        .type = (uint32_t)type,
        .seq = seq,
        .len = (uint32_t)len,
    };

    memcpy(packet, &hdr, sizeof(hdr));
    if (len != 0) memcpy(packet + sizeof(hdr), data, len);

    ssize_t written = write(fd, packet, total);
    free(packet);

    return written == (ssize_t)total ? (int)len : -1;
}

static int recv_msg(int timeout_ms, fastdyn_msg_hdr_t *hdr, uint8_t **payload)
{
    int fd = get_fuzzer_fd();
    if (fd < 0) return -1;

    while (true) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int rv = poll(&pfd, 1, (int)timeout_ms);

        if (rv == 0) return 0;
        if (rv < 0) {
            if (errno == EINTR) continue;
            return -1;
        }

        ssize_t rd = read(fd, g_wire_buf, sizeof(g_wire_buf));
        if (rd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            if (errno == EINTR) continue;
            return -1;
        }

        if (rd < (ssize_t)sizeof(*hdr)) return -1;

        memcpy(hdr, g_wire_buf, sizeof(*hdr));
        if (hdr->magic != FASTDYN_MSG_MAGIC ||
            hdr->len > FASTDYN_MAX_FRAME ||
            rd != (ssize_t)(sizeof(*hdr) + hdr->len)) {
            return -1;
        }

        *payload = g_wire_buf + sizeof(*hdr);
        return 1;
    }
}

/*
 * fastdyn_send — inject one frame into the model's RX path, then
 * wait up to timeout_ms for the firmware to finish processing it.
 */
int fastdyn_send(uint8_t *input, size_t size, uint32_t timeout_ms) {
    if (input == NULL) return -1;

    if (size > FASTDYN_MAX_FRAME) {
        size = FASTDYN_MAX_FRAME;
    }

    uint64_t seq = ++g_next_seq;
    int n = send_msg(FASTDYN_MSG_INPUT, seq, input, size);
    if (n < 0) {
        return -1;
    }

    while (true) {
        fastdyn_msg_hdr_t hdr;
        uint8_t *payload = NULL;
        int rv = recv_msg((int)timeout_ms, &hdr, &payload);

        if (rv == 0) return -2;
        if (rv < 0) return -1;

        if (hdr.type == FASTDYN_MSG_RESPONSE && hdr.seq == seq) {
            if (queue_response(payload, hdr.len) < 0) return -1;
        } else if (hdr.type == FASTDYN_MSG_DONE && hdr.seq == seq) {
            return n;
        }
    }
}

/*
 * fastdyn_recv — collect one queued firmware response frame.
 */
int fastdyn_recv(uint8_t *buffer, size_t size, uint32_t timeout_ms) {
    if (buffer == NULL || size == 0) return -1;

    int queued = pop_response(buffer, size);
    if (queued > 0) return queued;

    fastdyn_msg_hdr_t hdr;
    uint8_t *payload = NULL;
    int rv = recv_msg((int)timeout_ms, &hdr, &payload);

    if (rv == 0) return -2;
    if (rv < 0) return -1;

    if (hdr.type == FASTDYN_MSG_RESPONSE) {
        size_t copy_len = hdr.len < size ? hdr.len : size;
        if (copy_len != 0) memcpy(buffer, payload, copy_len);
        return (int)copy_len;
    }

    if (hdr.type == FASTDYN_MSG_DONE) return 0;
    return -2;
}

int fastdyn_snap_restore(uint32_t timeout_ms) {
    uint64_t seq = ++g_next_seq;
    if (send_msg(FASTDYN_MSG_RESTORE, seq, NULL, 0) < 0) {
        return -1;
    }

    while (true) {
        fastdyn_msg_hdr_t hdr;
        uint8_t *payload = NULL;
        int rv = recv_msg((int)timeout_ms, &hdr, &payload);

        if (rv < 0) return -1;
        if (rv == 0) return -2;

        if (hdr.type == FASTDYN_MSG_RESPONSE) {
            if (queue_response(payload, hdr.len) < 0) return -1;
        } else if (hdr.type == FASTDYN_MSG_RESTORE_DONE && hdr.seq == seq) {
            clear_responses();
            return 0;
        }
    }
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
