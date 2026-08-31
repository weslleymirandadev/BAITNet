/* icsp_data.c - ICSP Phase 2: encrypted data path.
 *
 * DATA chunks are AEAD-encrypted with the session key: the clear
 * payload is [tsn 4][stream 2][seq 2][msg], boxed with secretbox and a
 * nonce derived from (assoc_id, tsn) — per-packet authenticated and
 * replay-protected. SACK acknowledges up to cum_tsn; unacked DATA is
 * retransmitted on timeout.
 *
 * Ordered delivery: per-stream next_recv_seq gate — a message is only
 * delivered when its seq is the expected one, so stream A never blocks
 * stream B (the SCTP multi-streaming win).
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include "IPv69/header.h"
#include "IPv69/l2.h"
#include "ed25519.h"
#include "ICSP/icsp.h"

/* nonce = SHA-512(assoc_id_be || tsn_be)[0..23] */
static void data_nonce(const struct icsp_assoc *a, uint32_t tsn,
                       uint8_t nonce[24])
{
    uint8_t buf[8], h[64];
    buf[0] = (uint8_t)(a->assoc_id >> 24);
    buf[1] = (uint8_t)(a->assoc_id >> 16);
    buf[2] = (uint8_t)(a->assoc_id >> 8);
    buf[3] = (uint8_t)a->assoc_id;
    buf[4] = (uint8_t)(tsn >> 24);
    buf[5] = (uint8_t)(tsn >> 16);
    buf[6] = (uint8_t)(tsn >> 8);
    buf[7] = (uint8_t)tsn;
    ed25519_sha512(h, buf, sizeof(buf));
    memcpy(nonce, h, 24);
}

static struct icsp_stream *find_stream(struct icsp_assoc *a, uint16_t id)
{
    for (int i = 0; i < a->n_streams; i++)
        if (a->streams[i].id == id)
            return &a->streams[i];
    return NULL;
}

static struct icsp_stream *get_stream(struct icsp_assoc *a, uint16_t id)
{
    struct icsp_stream *s = find_stream(a, id);
    if (s)
        return s;
    if (a->n_streams >= ICSP_MAX_STREAMS)
        return NULL;
    s = &a->streams[a->n_streams++];
    memset(s, 0, sizeof(*s));
    s->id = id;
    return s;
}

/* ICSP packet builder (same as handshake): header(12) + chunk */
static int send_pkt(struct icsp_assoc *a, int fd, int ifindex,
                    const uint8_t src_mac[6], const uint8_t *dst_mac,
                    uint64_t dst_addr, uint64_t src_addr,
                    const uint8_t *chunk, size_t chunklen)
{
    uint8_t pkt[ICSP_MAX_PAYLOAD];
    size_t off = 0;

    pkt[off++] = (uint8_t)(a->src_port >> 8);
    pkt[off++] = (uint8_t)a->src_port;
    pkt[off++] = (uint8_t)(a->dst_port >> 8);
    pkt[off++] = (uint8_t)a->dst_port;
    pkt[off++] = ICSP_VERSION;
    pkt[off++] = 0;
    pkt[off++] = (uint8_t)(a->assoc_id >> 24);
    pkt[off++] = (uint8_t)(a->assoc_id >> 16);
    pkt[off++] = (uint8_t)(a->assoc_id >> 8);
    pkt[off++] = (uint8_t)a->assoc_id;
    off += 2;                       /* crc placeholder */
    memcpy(pkt + off, chunk, chunklen);
    off += chunklen;
    uint16_t crc = (uint16_t)icsp_crc32c(pkt + 2, off - 2);
    pkt[10] = (uint8_t)(crc >> 8);
    pkt[11] = (uint8_t)crc;

    uint8_t frame[1600];
    size_t len = build_frame(frame, dst_mac, src_mac, src_addr, dst_addr,
                             IPV69_NEXT_STREAM, 64, 0, 0, pkt, off);
    return send_frame(fd, ifindex, dst_mac, frame, len);
}

int icsp_data_send(struct icsp_assoc *a, int fd, int ifindex,
                   const uint8_t src_mac[6], const uint8_t *dst_mac,
                   uint64_t dst_addr, uint64_t src_addr,
                   uint16_t stream_id, const uint8_t *data, size_t len)
{
    struct icsp_stream *s;
    uint8_t clear[4 + 2 + 2 + ICSP_MAX_PAYLOAD];
    uint8_t box[ICSP_MAX_PAYLOAD + 32];
    uint8_t nonce[24];
    uint8_t chunk[ICSP_CHUNK_HDR + 4 + 2 + 2 + ICSP_MAX_PAYLOAD + 32];
    uint32_t tsn;

    if (!a->has_key)
        return -1;
    s = get_stream(a, stream_id);
    if (!s || len > ICSP_MAX_PAYLOAD)
        return -1;
    tsn = a->next_tsn++;
    /* clear = [tsn][stream][seq][msg] */
    clear[0] = (uint8_t)(tsn >> 24); clear[1] = (uint8_t)(tsn >> 16);
    clear[2] = (uint8_t)(tsn >> 8);  clear[3] = (uint8_t)tsn;
    clear[4] = (uint8_t)(stream_id >> 8); clear[5] = (uint8_t)stream_id;
    clear[6] = (uint8_t)(s->next_send_seq >> 8);
    clear[7] = (uint8_t)s->next_send_seq;
    memcpy(clear + 8, data, len);
    data_nonce(a, tsn, nonce);
    ed25519_secretbox(box, clear, 8 + len, nonce, a->session_key);

    /* chunk: [type][flags][len][tsn 4][stream 2][seq 2][box] */
    uint8_t *d = icsp_chunk_put(chunk, ICSP_CHUNK_DATA, 4 + 2 + 2 + 32 + 8 + len);
    d[0] = (uint8_t)(tsn >> 24); d[1] = (uint8_t)(tsn >> 16);
    d[2] = (uint8_t)(tsn >> 8);  d[3] = (uint8_t)tsn;
    d[4] = (uint8_t)(stream_id >> 8); d[5] = (uint8_t)stream_id;
    d[6] = (uint8_t)(s->next_send_seq >> 8);
    d[7] = (uint8_t)s->next_send_seq;
    memcpy(d + 8, box, 32 + 8 + len);

    /* queue for retransmission */
    if (a->n_sendq < ICSP_SENDQ) {
        struct icsp_assoc *q = a;
        int i = q->n_sendq++;
        q->sendq[i].tsn = tsn;
        q->sendq[i].stream_id = stream_id;
        q->sendq[i].seq = s->next_send_seq;
        q->sendq[i].len = len;
        q->sendq[i].acked = 0;
        q->sendq[i].sent_at = time(NULL);
    }
    s->next_send_seq++;

    if (send_pkt(a, fd, ifindex, src_mac, dst_mac, dst_addr, src_addr,
                 chunk, ICSP_CHUNK_HDR + 4 + 2 + 2 + 32 + 8 + len) < 0)
        return -1;
    return (int)tsn;
}

int icsp_sack_send(struct icsp_assoc *a, int fd, int ifindex,
                   const uint8_t src_mac[6], const uint8_t *dst_mac,
                   uint64_t dst_addr, uint64_t src_addr)
{
    uint8_t chunk[ICSP_CHUNK_HDR + 4];
    uint8_t *d = icsp_chunk_put(chunk, ICSP_CHUNK_SACK, 4);
    d[0] = (uint8_t)(a->cum_tsn >> 24);
    d[1] = (uint8_t)(a->cum_tsn >> 16);
    d[2] = (uint8_t)(a->cum_tsn >> 8);
    d[3] = (uint8_t)a->cum_tsn;
    return send_pkt(a, fd, ifindex, src_mac, dst_mac, dst_addr, src_addr,
                    chunk, sizeof(chunk));
}

int icsp_data_retransmit(struct icsp_assoc *a, int fd, int ifindex,
                         const uint8_t src_mac[6], const uint8_t *dst_mac,
                         uint64_t dst_addr, uint64_t src_addr,
                         int timeout_s)
{
    int resent = 0;
    time_t now = time(NULL);

    for (int i = 0; i < a->n_sendq; i++) {
        if (a->sendq[i].acked || now - a->sendq[i].sent_at < timeout_s)
            continue;
        /* re-send the same DATA with the same TSN/seq */
        uint8_t clear[4 + 2 + 2 + ICSP_MAX_PAYLOAD];
        uint8_t box[ICSP_MAX_PAYLOAD + 32];
        uint8_t nonce[24];
        uint8_t chunk[ICSP_CHUNK_HDR + 4 + 2 + 2 + ICSP_MAX_PAYLOAD + 32];
        uint32_t tsn = a->sendq[i].tsn;

        clear[0] = (uint8_t)(tsn >> 24); clear[1] = (uint8_t)(tsn >> 16);
        clear[2] = (uint8_t)(tsn >> 8);  clear[3] = (uint8_t)tsn;
        clear[4] = (uint8_t)(a->sendq[i].stream_id >> 8);
        clear[5] = (uint8_t)a->sendq[i].stream_id;
        clear[6] = (uint8_t)(a->sendq[i].seq >> 8);
        clear[7] = (uint8_t)a->sendq[i].seq;
        memcpy(clear + 8, a->sendq[i].data, a->sendq[i].len);
        data_nonce(a, tsn, nonce);
        ed25519_secretbox(box, clear, 8 + a->sendq[i].len, nonce,
                          a->session_key);
        uint8_t *d = icsp_chunk_put(chunk, ICSP_CHUNK_DATA,
                                    4 + 2 + 2 + 32 + 8 + a->sendq[i].len);
        d[0] = (uint8_t)(tsn >> 24); d[1] = (uint8_t)(tsn >> 16);
        d[2] = (uint8_t)(tsn >> 8);  d[3] = (uint8_t)tsn;
        d[4] = (uint8_t)(a->sendq[i].stream_id >> 8);
        d[5] = (uint8_t)a->sendq[i].stream_id;
        d[6] = (uint8_t)(a->sendq[i].seq >> 8);
        d[7] = (uint8_t)a->sendq[i].seq;
        memcpy(d + 8, box, 32 + 8 + a->sendq[i].len);
        int spr = send_pkt(a, fd, ifindex, src_mac, dst_mac, dst_addr,
                           src_addr, chunk,
                           ICSP_CHUNK_HDR + 4 + 2 + 2 + 32 + 8 +
                                  a->sendq[i].len);
        if (spr >= 0) {
            a->sendq[i].sent_at = now;
            resent++;
        }
    }
    return resent;
}

int icsp_data_handle(struct icsp_assoc *a, const uint8_t *payload,
                     size_t plen, uint8_t *out, size_t *outlen,
                     uint16_t *out_stream)
{
    const uint8_t *p = payload;
    size_t left = plen;

    /* skip the ICSP header */
    if (left < ICSP_HEADER_LEN)
        return -1;
    p += ICSP_HEADER_LEN;
    left -= ICSP_HEADER_LEN;

    while (left >= ICSP_CHUNK_HDR) {
        uint8_t type = p[0];
        size_t clen = ((size_t)p[2] << 8) | p[3];
        const uint8_t *cd = p + ICSP_CHUNK_HDR;
        if (ICSP_CHUNK_HDR + clen > left)
            break;

        if (type == ICSP_CHUNK_DATA && a->has_key) {
            /* DATA: [tsn 4][stream 2][seq 2][box] */
            uint32_t tsn = ((uint32_t)cd[0] << 24) | ((uint32_t)cd[1] << 16) |
                           ((uint32_t)cd[2] << 8) | cd[3];
            uint16_t sid = (uint16_t)((cd[4] << 8) | cd[5]);
            uint16_t seq = (uint16_t)((cd[6] << 8) | cd[7]);
            size_t boxlen = clen - 8;
            uint8_t clear[ICSP_MAX_PAYLOAD + 4 + 4];
            uint8_t nonce[24];

            data_nonce(a, tsn, nonce);
            if (boxlen < 32 || boxlen > ICSP_MAX_PAYLOAD + 32 + 8)
                goto next;
            if (ed25519_secretbox_open(clear, cd + 8, boxlen - 32, nonce,
                                       a->session_key) != 0)
                return -1;          /* bad MAC: drop association */
            /* validate the plaintext matches the header (anti-replay) */
            uint32_t t2 = ((uint32_t)clear[0] << 24) |
                          ((uint32_t)clear[1] << 16) |
                          ((uint32_t)clear[2] << 8) | clear[3];
            uint16_t s2 = (uint16_t)((clear[4] << 8) | clear[5]);
            uint16_t q2 = (uint16_t)((clear[6] << 8) | clear[7]);
            if (t2 != tsn || s2 != sid || q2 != seq)
                return -1;          /* tampered */
            /* ordered delivery gate: deliver only the expected seq */
            struct icsp_stream *s = get_stream(a, sid);
            if (s && seq == s->next_recv_seq) {
                s->next_recv_seq++;
                size_t mlen = boxlen - 32 - 8;  /* strip the clear header */
                if (mlen > *outlen)
                    mlen = *outlen;
                memcpy(out, clear + 8, mlen);
                *outlen = mlen;
                *out_stream = sid;
                if (tsn > a->cum_tsn)
                    a->cum_tsn = tsn;
                return (int)mlen;
            } else {
                /* out of order: buffer it (still acked via cum window) */
                if (a->n_rcvq < ICSP_RCVQ && s) {
                    int i = a->n_rcvq++;
                    a->rcvq[i].tsn = tsn;
                    a->rcvq[i].stream_id = sid;
                    a->rcvq[i].seq = seq;
                    a->rcvq[i].len = boxlen - 32 - 8;
                    memcpy(a->rcvq[i].data, clear + 8, a->rcvq[i].len);
                    a->rcvq[i].valid = 1;
                }
                /* SACK up to the highest in-order tsn we have buffered */
                if (tsn > a->cum_tsn)
                    a->cum_tsn = tsn;
            }
        } else if (type == ICSP_CHUNK_SACK) {
            /* SACK: [cumulative_tsn 4] — mark our sendq acked */
            uint32_t cum = ((uint32_t)cd[0] << 24) | ((uint32_t)cd[1] << 16) |
                           ((uint32_t)cd[2] << 8) | cd[3];
            for (int i = 0; i < a->n_sendq; i++)
                if (!a->sendq[i].acked && a->sendq[i].tsn <= cum)
                    a->sendq[i].acked = 1;
        }
next:
        p += ICSP_CHUNK_HDR + clen;
        left -= ICSP_CHUNK_HDR + clen;
    }
    return 0;
}
