/* icsp_life.c - ICSP Phase 3: lifecycle.
 *
 * HEARTBEAT / HEARTBEAT-ACK: liveness probe — a dead peer is detected
 * after `timeout_s` of silence and the caller can fail over.
 * SHUTDOWN: graceful close (both sides stop sending, association
 * released). STREAM-RESET: renegotiate a stream at runtime (dynamic
 * renegotiation like RFC 6525).
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include "ICSP/icsp.h"

/* send HEARTBEAT; returns 0 on success */
int icsp_heartbeat_send(struct icsp_assoc *a)
{
    uint8_t chunk[ICSP_CHUNK_HDR + 4];      /* timestamp as payload */
    uint8_t *d = icsp_chunk_put(chunk, ICSP_CHUNK_HEARTBEAT, 4);
    uint32_t now = (uint32_t)time(NULL);
    d[0] = (uint8_t)(now >> 24); d[1] = (uint8_t)(now >> 16);
    d[2] = (uint8_t)(now >> 8);  d[3] = (uint8_t)now;
    return icsp_send_pkt(a, chunk, sizeof(chunk));
}

/* answer HEARTBEAT-ACK for an incoming HEARTBEAT */
int icsp_heartbeat_ack(struct icsp_assoc *a)
{
    uint8_t chunk[ICSP_CHUNK_HDR + 4];
    uint8_t *d = icsp_chunk_put(chunk, ICSP_CHUNK_HEARTBEAT_ACK, 4);
    uint32_t now = (uint32_t)time(NULL);
    d[0] = (uint8_t)(now >> 24); d[1] = (uint8_t)(now >> 16);
    d[2] = (uint8_t)(now >> 8);  d[3] = (uint8_t)now;
    return icsp_send_pkt(a, chunk, sizeof(chunk));
}

/* graceful close: send SHUTDOWN, association -> SHUTDOWN state */
int icsp_shutdown_send(struct icsp_assoc *a)
{
    uint8_t chunk[ICSP_CHUNK_HDR];
    icsp_chunk_put(chunk, ICSP_CHUNK_SHUTDOWN, 0);
    int r = icsp_send_pkt(a, chunk, sizeof(chunk));
    if (r == 0)
        a->state = ICSP_ST_SHUTDOWN;
    return r;
}

/* dynamic stream renegotiation: reset a stream's sequence counters */
int icsp_stream_reset(struct icsp_assoc *a, uint16_t stream_id,
                      uint8_t mode)
{
    uint8_t chunk[ICSP_CHUNK_HDR + 3];
    uint8_t *d = icsp_chunk_put(chunk, ICSP_CHUNK_STREAM_RESET, 3);
    d[0] = (uint8_t)(stream_id >> 8);
    d[1] = (uint8_t)stream_id;
    d[2] = mode;                /* 0=reset, 1=add, 2=close */
    return icsp_send_pkt(a, chunk, sizeof(chunk));
}

/* process lifecycle chunks in a received payload; returns 1 if the
 * association should be considered closed, 0 otherwise */
int icsp_life_handle(struct icsp_assoc *a, const uint8_t *payload,
                     size_t plen)
{
    const uint8_t *p = payload;
    size_t left = plen;

    if (left < ICSP_HEADER_LEN)
        return 0;
    p += ICSP_HEADER_LEN;
    left -= ICSP_HEADER_LEN;

    while (left >= ICSP_CHUNK_HDR) {
        uint8_t type = p[0];
        size_t clen = ((size_t)p[2] << 8) | p[3];
        if (ICSP_CHUNK_HDR + clen > left)
            break;
        if (type == ICSP_CHUNK_SHUTDOWN)
            return 1;
        if (type == ICSP_CHUNK_STREAM_RESET && clen >= 3) {
            uint16_t sid = (uint16_t)((p[4] << 8) | p[5]);
            for (int i = 0; i < a->n_streams; i++)
                if (a->streams[i].id == sid) {
                    a->streams[i].next_send_seq = 0;
                    a->streams[i].next_recv_seq = 0;
                }
        }
        p += ICSP_CHUNK_HDR + clen;
        left -= ICSP_CHUNK_HDR + clen;
    }
    return 0;
}
