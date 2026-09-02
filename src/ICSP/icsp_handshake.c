/* icsp_handshake.c - ICSP Phase 1: authenticated handshake + rekey.
 *
 * Client:  INIT -> INIT-ACK(cookie) -> COOKIE-ECHO -> COOKIE-ACK
 * Server:  waits INIT, answers INIT-ACK (signed, secret cookie),
 *          validates COOKIE-ECHO (signature + cookie) -> ESTABLISHED.
 *
 * WireGuard-inspired hardening:
 *   - INIT carries mac1 (cheap Poly1305 pre-auth filter) + a timestamp
 *     (anti-replay: the server rejects ts <= last accepted) + an
 *     optional encrypted identity (ICSP_INIT_FLAG_IDBOX, when the
 *     client knows the server's public key — identity hiding).
 *   - the session keys are directional (send/recv, HKDF) and rekeyed
 *     on a timer: the initiator sends a fresh INIT over the established
 *     association; the responder answers through icsp_handle_frame.
 *
 * Security model (spec §5): the Ed25519 identity authenticates the
 * peer (same pubkey allowlist concept as DHCP69); ephemeral X25519
 * provides forward secrecy; cookie = server secret + hash of params,
 * clients cannot forge it.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include "IPv69/header.h"
#include "IPv69/l2.h"
#include "IPv69/mac1.h"
#include "IPv69/ratelimit.h"
#include "ed25519.h"
#include "ICSP/icsp.h"

/* cookie = server-secret MAC over (client_id_pub, client_eph, streams).
 * Secret rotates every 5 min; the cookie embeds a timestamp so a valid
 * cookie stays acceptable for a short window. */
#define COOKIE_LEN 48
#define COOKIE_TTL 300

/* INIT layout (data after the 4-byte chunk header):
 *   [ver 1][streams 4][eph 32][ts 8][id 32 | box 48][sig 64][mac1 16]
 * box = secretbox(X25519(eph_priv, server_pub), id_pub) — identity
 * hiding when the client knows the server pub (ICSP_INIT_FLAG_IDBOX). */
#define INIT_ID_LEN    32
#define INIT_BOX_LEN   48
#define INIT_PRE_SIG(flags)  (1 + 4 + 32 + 8 + \
                              ((flags) & ICSP_INIT_FLAG_IDBOX ? INIT_BOX_LEN : INIT_ID_LEN))
#define INIT_LEN(flags)      (INIT_PRE_SIG(flags) + 64 + MAC1_LEN)

static uint8_t server_secret[32];
static time_t secret_ts;

static void secret_refresh(void)
{
    if (!server_secret[0] || time(NULL) - secret_ts > COOKIE_TTL) {
        randombytes(server_secret, sizeof(server_secret));
        secret_ts = time(NULL);
    }
}

/* build the cookie over the INIT parameters */
static void cookie_make(const struct icsp_assoc *a, uint8_t out[COOKIE_LEN])
{
    uint8_t buf[32 + 32 + 4];
    uint8_t h[64];

    secret_refresh();
    memcpy(buf, a->peer_id, 32);
    memcpy(buf + 32, a->peer_eph, 32);
    buf[64] = (uint8_t)(a->streams_in >> 8);
    buf[65] = (uint8_t)a->streams_in;
    buf[66] = (uint8_t)(a->streams_out >> 8);
    buf[67] = (uint8_t)a->streams_out;
    ed25519_sha512(h, server_secret, sizeof(server_secret));
    ed25519_sha512(h, buf, sizeof(buf));
    memcpy(out, h, COOKIE_LEN);
}

static int cookie_valid(const uint8_t c[COOKIE_LEN], const struct icsp_assoc *a)
{
    uint8_t expect[COOKIE_LEN];
    cookie_make(a, expect);
    return memcmp(c, expect, COOKIE_LEN) == 0;
}

/* fresh association state, keeping the endpoint context (fd, ifindex,
 * src_mac, dst_addr) and the keepalive/rekey config — so a server can
 * accept association after association on the same socket. */
static void assoc_reset(struct icsp_assoc *a)
{
    l2_handle fd = a->fd;
    int ifindex = a->ifindex;
    uint8_t smac[6];
    uint64_t dst_addr = a->dst_addr, src_addr = a->src_addr;
    int hb = a->hb_interval_s, dead = a->dead_timeout_s;
    int rekey = a->rekey_interval_s;
    uint8_t rnd[4];
    /* tunnel endpoint (--remote) is part of the endpoint context too */
    sock_t tfd = a->tfd;
    struct sockaddr_storage gw = a->gw;
    socklen_t gwlen = a->gwlen;
    int tunnel = a->tunnel;

    memcpy(smac, a->src_mac, 6);
    memset(a, 0, sizeof(*a));
    a->fd = fd;
    a->ifindex = ifindex;
    memcpy(a->src_mac, smac, 6);
    a->dst_addr = dst_addr;
    a->src_addr = src_addr;
    a->tfd = tfd;
    a->gw = gw;
    a->gwlen = gwlen;
    a->tunnel = tunnel;
    a->hb_interval_s = hb;
    a->dead_timeout_s = dead;
    a->rekey_interval_s = rekey;
    /* SCTP-style: random initial TSN so the receiver's replay window
       starts clean (a first TSN of 0 would collide with cum_tsn=0) */
    randombytes(rnd, sizeof(rnd));
    a->next_tsn = ((uint32_t)rnd[0] << 24) | ((uint32_t)rnd[1] << 16) |
                  ((uint32_t)rnd[2] << 8) | rnd[3];
}

/* build the INIT chunk into `chunk` (caller owns the buffer, sized
 * ICSP_CHUNK_HDR + INIT_LEN(flags)). server_pub != NULL enables the
 * encrypted identity (identity hiding). Returns the total chunk length. */
static size_t init_build(struct icsp_assoc *a, const uint8_t sk[64],
                         const uint8_t *server_pub, uint8_t *chunk)
{
    uint8_t eph_priv[32];
    uint8_t *d = chunk + ICSP_CHUNK_HDR;
    uint8_t flags = server_pub ? ICSP_INIT_FLAG_IDBOX : 0;
    size_t pre_sig = INIT_PRE_SIG(flags);
    uint64_t ts = (uint64_t)time(NULL);

    randombytes(eph_priv, 32);
    if (ed25519_scalarmult_base(a->eph_pub, eph_priv) != 0)
        return 0;
    memcpy(a->eph_priv, eph_priv, 32);
    memset(eph_priv, 0, sizeof(eph_priv));

    chunk[0] = ICSP_CHUNK_INIT;
    chunk[1] = flags;
    chunk[2] = (uint8_t)((pre_sig + 64 + MAC1_LEN) >> 8);
    chunk[3] = (uint8_t)(pre_sig + 64 + MAC1_LEN);

    d[0] = ICSP_VERSION;
    d[1] = (uint8_t)(a->streams_in >> 8);
    d[2] = (uint8_t)a->streams_in;
    d[3] = (uint8_t)(a->streams_out >> 8);
    d[4] = (uint8_t)a->streams_out;
    memcpy(d + 5, a->eph_pub, 32);
    d[37] = (uint8_t)(ts >> 56); d[38] = (uint8_t)(ts >> 48);
    d[39] = (uint8_t)(ts >> 40); d[40] = (uint8_t)(ts >> 32);
    d[41] = (uint8_t)(ts >> 24); d[42] = (uint8_t)(ts >> 16);
    d[43] = (uint8_t)(ts >> 8);  d[44] = (uint8_t)ts;
    if (server_pub) {
        /* box = secretbox(X25519(eph, server_pub), id_pub) */
        uint8_t shared[32], nonce[24] = { 0 };
        if (ed25519_scalarmult(shared, a->eph_priv, server_pub) != 0)
            return 0;
        ed25519_secretbox(d + 45, a->id_pub, 32, nonce, shared);
        memset(shared, 0, sizeof(shared));
    } else {
        memcpy(d + 45, a->id_pub, 32);
    }
    /* signature over [ver..id], then mac1 over [ver..sig] */
    ed25519_sign(d + pre_sig, d, pre_sig, sk);

    {
        uint8_t mkey[32];
        mac1_key(a->dst_addr, mkey);
        mac1_compute(mkey, d, pre_sig + 64, d + pre_sig + 64);
    }
    return ICSP_CHUNK_HDR + pre_sig + 64 + MAC1_LEN;
}

/* validate an incoming INIT chunk (mac1, rate limit, timestamp,
 * signature, allowlist). On success fills a->assoc_id/peer_id/peer_eph
 * and returns the flags; -1 = reject (caller should drop silently). */
static int init_check(struct icsp_assoc *a, const uint8_t *frame,
                      const uint8_t *payload, size_t plen,
                      const uint8_t (*peers)[32], int n_peers)
{
    const struct ipv69_header *fh =
        (const struct ipv69_header *)(frame + 14);
    const uint8_t *cd = payload + ICSP_HEADER_LEN + ICSP_CHUNK_HDR;
    uint8_t flags = payload[ICSP_HEADER_LEN + 1];
    size_t pre_sig = INIT_PRE_SIG(flags);

    if (cd[0] != ICSP_VERSION || plen < ICSP_HEADER_LEN + ICSP_CHUNK_HDR + INIT_LEN(flags))
        return -1;
    /* cheap pre-auth filter (WireGuard mac1): drop garbage and
       throttled senders silently, BEFORE any signature/ECDH work */
    {
        uint8_t mkey[32];
        mac1_key(get_addr40(fh->dest), mkey);
        if (mac1_verify(mkey, cd, pre_sig + 64, cd + pre_sig + 64) != 0)
            return -1;
    }
    {
        uint8_t rid[8] = { 0 };
        memcpy(rid, frame + 6, 6);  /* sender MAC */
        if (!rate_allow(rid, 10, 20, 1))
            return -1;
    }
    /* anti-replay: INIT timestamps must be strictly increasing */
    {
        uint64_t ts = 0;
        for (int i = 0; i < 8; i++)
            ts = (ts << 8) | cd[37 + i];
        if (ts <= a->last_init_ts)
            return -1;
        a->last_init_ts = ts;
    }
    a->assoc_id = (uint32_t)(((uint32_t)payload[6] << 24) |
                             ((uint32_t)payload[7] << 16) |
                             ((uint32_t)payload[8] << 8) |
                             payload[9]);
    memcpy(a->peer_eph, cd + 5, 32);
    if (flags & ICSP_INIT_FLAG_IDBOX) {
        /* identity hiding: id = secretbox_open(X25519(sk, eph), box) */
        uint8_t shared[32], nonce[24] = { 0 };
        if (ed25519_scalarmult(shared, a->sk, cd + 5) != 0)
            return -1;
        if (ed25519_secretbox_open(a->peer_id, cd + 45, INIT_BOX_LEN - 32,
                                   nonce, shared) != 0) {
            memset(shared, 0, sizeof(shared));
            return -1;
        }
        memset(shared, 0, sizeof(shared));
    } else {
        memcpy(a->peer_id, cd + 45, 32);
    }
    /* verify client signature over [ver..id/box] */
    if (ed25519_verify(cd, pre_sig, cd + pre_sig, a->peer_id) != 0)
        return -1;
    /* allowlist (like DHCP --peer/--peer-file); empty = accept any
       valid signature (like --learn) */
    if (n_peers > 0) {
        int ok = 0;
        for (int i = 0; i < n_peers; i++)
            if (!memcmp(peers[i], a->peer_id, 32)) { ok = 1; break; }
        if (!ok)
            return -1;
    }
    return (int)flags;
}

/* answer a validated INIT: derive + INIT-ACK [ver][streams][eph][id][sig][cookie] */
static int init_ack_send(struct icsp_assoc *a, const uint8_t sk[64])
{
    uint8_t chunk[ICSP_CHUNK_HDR + 1 + 4 + 32 + 32 + 64 + COOKIE_LEN];
    uint8_t *d = icsp_chunk_put(chunk, ICSP_CHUNK_INIT_ACK,
                                1 + 4 + 32 + 32 + 64 + COOKIE_LEN);
    uint8_t eph_priv[32];

    randombytes(eph_priv, 32);
    if (ed25519_scalarmult_base(a->eph_pub, eph_priv) != 0)
        return -1;
    memcpy(a->eph_priv, eph_priv, 32);
    memset(eph_priv, 0, sizeof(eph_priv));
    if (icsp_derive_key(a, a->eph_priv) != 0)
        return -1;

    d[0] = ICSP_VERSION;
    d[1] = (uint8_t)(a->streams_in >> 8);
    d[2] = (uint8_t)a->streams_in;
    d[3] = (uint8_t)(a->streams_out >> 8);
    d[4] = (uint8_t)a->streams_out;
    memcpy(d + 5, a->eph_pub, 32);
    memcpy(d + 37, a->id_pub, 32);
    ed25519_sign(d + 69, d, 5 + 32 + 32, sk);
    cookie_make(a, d + 69 + 64);
    if (icsp_send_pkt(a, chunk, sizeof(chunk)) < 0) {
        perror("icsp: send INIT-ACK");
        return -1;
    }
    printf("icsp: INIT-ACK sent (cookie)\n");
    return 0;
}

/* --- client --- */
int icsp_client_handshake(struct icsp_assoc *a, uint64_t dst_addr,
                          uint16_t dst_port, const uint8_t sk[64],
                          const uint8_t *server_pub)
{
    uint8_t frame[1600];
    const uint8_t *payload;
    size_t plen;
    uint64_t from;

    assoc_reset(a);
    a->is_initiator = 1;
    a->dst_addr = dst_addr;
    a->dst_port = dst_port;
    if (a->src_port == 0)
        a->src_port = 50000 + (uint16_t)getpid() % 1000;
    a->state = ICSP_ST_COOKIE_WAIT;
    a->streams_in = a->streams_out = 4;
    a->rcv_timeout_ms = 3000;
    memcpy(a->id_pub, sk + 32, 32);
    memcpy(a->sk, sk, 64);
    {
        uint8_t rnd[4];
        randombytes(rnd, sizeof(rnd));
        a->assoc_id = ((uint32_t)rnd[0] << 24) | ((uint32_t)rnd[1] << 16) |
                      ((uint32_t)rnd[2] << 8) | rnd[3];
    }
    printf("icsp: client -> %016llx:%u\n",
           (unsigned long long)dst_addr, dst_port);

    /* INIT */
    {
        uint8_t chunk[ICSP_CHUNK_HDR + INIT_LEN(ICSP_INIT_FLAG_IDBOX)];
        size_t clen = init_build(a, sk, server_pub, chunk);
        if (clen == 0)
            return -1;
        if (icsp_send_pkt(a, chunk, clen) < 0) {
            perror("icsp: send INIT");
            return -1;
        }
        printf("icsp: INIT sent (dst=%016llx:%u%s)\n",
               (unsigned long long)dst_addr, dst_port,
               server_pub ? ", id encrypted" : "");
    }

    /* wait INIT-ACK [ver][streams][eph 32][id 32][sig 64][cookie] */
    for (;;) {
        ssize_t n = icsp_recv_frame(a, frame, &payload, &plen, &from);
        if (n < 0) { perror("icsp: INIT-ACK"); return -1; }
        if (n == 0)
            continue;           /* noise frame */
        if (payload[4] != ICSP_VERSION ||
            payload[ICSP_HEADER_LEN] != ICSP_CHUNK_INIT_ACK)
            continue;
        /* the INIT-ACK must come from the port we asked for */
        {
            uint16_t sport = (uint16_t)((payload[0] << 8) | payload[1]);
            if (sport != dst_port)
                continue;       /* wrong server port: not ours */
        }
        const uint8_t *cd = payload + ICSP_HEADER_LEN + ICSP_CHUNK_HDR;
        uint8_t ver = cd[0];
        uint16_t s_in = (uint16_t)((cd[1] << 8) | cd[2]);
        uint16_t s_out = (uint16_t)((cd[3] << 8) | cd[4]);
        (void)ver; (void)s_in; (void)s_out;
        memcpy(a->peer_eph, cd + 5, 32);
        memcpy(a->peer_id, cd + 37, 32);
        /* verify server signature over [ver..id] */
        if (ed25519_verify(cd, 5 + 32 + 32, cd + 69, a->peer_id) != 0) {
            printf("icsp: INIT-ACK invalid signature (rogue server)\n");
            return -1;
        }
        printf("icsp: INIT-ACK ok (peer_id=%02x%02x.., assoc=%u)\n",
               a->peer_id[0], a->peer_id[1], a->assoc_id);
        /* derive the shared session key (peer_eph now known) */
        if (icsp_derive_key(a, a->eph_priv) != 0)
            return -1;
        /* COOKIE-ECHO [cookie 48][sig 64] */
        uint8_t ck[ICSP_CHUNK_HDR + COOKIE_LEN + 64];
        uint8_t *ckd = icsp_chunk_put(ck, ICSP_CHUNK_COOKIE_ECHO,
                                      COOKIE_LEN + 64);
        memcpy(ckd, cd + 69 + 64, COOKIE_LEN);
        ed25519_sign(ckd + COOKIE_LEN, ckd, COOKIE_LEN, sk);
        if (icsp_send_pkt(a, ck, sizeof(ck)) < 0) {
            perror("icsp: send COOKIE-ECHO");
            return -1;
        }
        printf("icsp: COOKIE-ECHO sent\n");
        break;
    }

    /* wait COOKIE-ACK */
    for (;;) {
        ssize_t n = icsp_recv_frame(a, frame, &payload, &plen, &from);
        if (n < 0) { perror("icsp: COOKIE-ACK"); return -1; }
        if (n == 0)
            continue;
        if (payload[ICSP_HEADER_LEN] != ICSP_CHUNK_COOKIE_ACK)
            continue;
        a->state = ICSP_ST_ESTABLISHED;
        printf("icsp: COOKIE-ACK — association established! session_key=");
        for (int i = 0; i < 32; i++) printf("%02x", a->send_key[i]);
        printf("\n");
        return 0;
    }
}

/* --- server --- */
int icsp_server_accept(struct icsp_assoc *a, uint16_t port,
                       const uint8_t sk[64],
                       const uint8_t (*peers)[32], int n_peers,
                       int timeout_s)
{
    uint8_t frame[1600];
    const uint8_t *payload;
    size_t plen;
    uint64_t from;

    assoc_reset(a);
    a->is_initiator = 0;
    a->src_port = port;
    a->dst_port = 0;
    a->state = ICSP_ST_CLOSED;
    a->streams_in = a->streams_out = 4;
    a->rcv_timeout_ms = timeout_s > 0 ? timeout_s * 1000 : 0;
    memcpy(a->id_pub, sk + 32, 32);
    memcpy(a->sk, sk, 64);

    /* wait INIT */
    for (;;) {
        ssize_t n = icsp_recv_frame(a, frame, &payload, &plen, &from);
        if (n < 0) { perror("icsp: INIT"); return -1; }
        if (n == 0)
            continue;
        if (payload[ICSP_HEADER_LEN] != ICSP_CHUNK_INIT)
            continue;
        /* the INIT must be addressed to the port we accept on */
        {
            uint16_t dport = (uint16_t)((payload[2] << 8) | payload[3]);
            if (dport != port)
                continue;       /* silent drop: not for this port */
        }
        if (init_check(a, frame, payload, plen, peers, n_peers) < 0)
            continue;           /* silent drop (mac1/rate/ts/sig) */
        a->dst_addr = from;
        printf("icsp: INIT ok (peer_id=%02x%02x..) -> INIT-ACK\n",
               a->peer_id[0], a->peer_id[1]);
        break;
    }
    if (init_ack_send(a, sk) < 0)
        return -1;

    /* wait COOKIE-ECHO [cookie][sig] */
    for (;;) {
        ssize_t n = icsp_recv_frame(a, frame, &payload, &plen, &from);
        if (n < 0) { perror("icsp: COOKIE-ECHO"); return -1; }
        if (n == 0)
            continue;
        if (payload[ICSP_HEADER_LEN] != ICSP_CHUNK_COOKIE_ECHO)
            continue;
        const uint8_t *cd = payload + ICSP_HEADER_LEN + ICSP_CHUNK_HDR;
        if (!cookie_valid(cd, a)) {
            printf("icsp: COOKIE-ECHO invalid cookie -> rejected\n");
            return -1;
        }
        if (ed25519_verify(cd, COOKIE_LEN, cd + COOKIE_LEN, a->peer_id) != 0) {
            printf("icsp: COOKIE-ECHO invalid signature -> rejected\n");
            return -1;
        }
        printf("icsp: COOKIE-ECHO ok -> COOKIE-ACK\n");
        break;
    }
    /* COOKIE-ACK */
    {
        uint8_t ck[ICSP_CHUNK_HDR];
        icsp_chunk_put(ck, ICSP_CHUNK_COOKIE_ACK, 0);
        if (icsp_send_pkt(a, ck, sizeof(ck)) < 0) {
            perror("icsp: send COOKIE-ACK");
            return -1;
        }
    }
    a->state = ICSP_ST_ESTABLISHED;
    printf("icsp: association established! session_key=");
    for (int i = 0; i < 32; i++) printf("%02x", a->send_key[i]);
    printf("\n");
    return 0;
}

/* --- rekey (in-session handshake, WireGuard REKEY_AFTER_TIME) ------- */

/* initiator side: start a rekey by sending a fresh INIT on the
 * established association (new assoc_id + ephemeral). */
int icsp_rekey_start(struct icsp_assoc *a)
{
    uint8_t chunk[ICSP_CHUNK_HDR + INIT_LEN(ICSP_INIT_FLAG_IDBOX)];
    uint8_t rnd[4];
    size_t clen;

    randombytes(rnd, sizeof(rnd));
    a->assoc_id = ((uint32_t)rnd[0] << 24) | ((uint32_t)rnd[1] << 16) |
                  ((uint32_t)rnd[2] << 8) | rnd[3];
    clen = init_build(a, a->sk, NULL, chunk);
    if (clen == 0)
        return -1;
    if (icsp_send_pkt(a, chunk, clen) < 0)
        return -1;
    a->state = ICSP_ST_REKEY_WAIT_ACK;
    return 0;
}

/* initiator side: process INIT-ACK/COOKIE-ACK while rekeying.
 * Returns 1 when the rekey completed (new keys installed). */
int icsp_rekey_client_step(struct icsp_assoc *a, const uint8_t *payload)
{
    const uint8_t *cd = payload + ICSP_HEADER_LEN + ICSP_CHUNK_HDR;

    if (a->state == ICSP_ST_REKEY_WAIT_ACK &&
        payload[ICSP_HEADER_LEN] == ICSP_CHUNK_INIT_ACK) {
        memcpy(a->peer_eph, cd + 5, 32);
        memcpy(a->peer_id, cd + 37, 32);
        if (ed25519_verify(cd, 5 + 32 + 32, cd + 69, a->peer_id) != 0)
            return -1;
        /* COOKIE-ECHO */
        uint8_t ck[ICSP_CHUNK_HDR + COOKIE_LEN + 64];
        uint8_t *ckd = icsp_chunk_put(ck, ICSP_CHUNK_COOKIE_ECHO,
                                      COOKIE_LEN + 64);
        memcpy(ckd, cd + 69 + 64, COOKIE_LEN);
        ed25519_sign(ckd + COOKIE_LEN, ckd, COOKIE_LEN, a->sk);
        if (icsp_send_pkt(a, ck, sizeof(ck)) < 0)
            return -1;
        a->state = ICSP_ST_REKEY_WAIT_COOKIE_ACK;
        return 0;
    }
    if (a->state == ICSP_ST_REKEY_WAIT_COOKIE_ACK &&
        payload[ICSP_HEADER_LEN] == ICSP_CHUNK_COOKIE_ACK) {
        if (icsp_derive_key(a, a->eph_priv) != 0)
            return -1;
        a->state = ICSP_ST_ESTABLISHED;
        printf("icsp: rekey ok! new session_key=");
        for (int i = 0; i < 32; i++) printf("%02x", a->send_key[i]);
        printf("\n");
        return 1;
    }
    return 0;
}

/* responder side: process INIT (answer INIT-ACK) / COOKIE-ECHO
 * (COOKIE-ACK + install the new keys) while in an established session.
 * Only the same authenticated peer may rekey. Returns 1 on completion,
 * -1 on protocol error (drop), 0 = not ours. */
int icsp_rekey_server_step(struct icsp_assoc *a, const uint8_t *frame,
                           const uint8_t *payload, size_t plen)
{
    const uint8_t *cd = payload + ICSP_HEADER_LEN + ICSP_CHUNK_HDR;

    if (a->state == ICSP_ST_ESTABLISHED &&
        payload[ICSP_HEADER_LEN] == ICSP_CHUNK_INIT) {
        /* rekey INIT: same identity, fresh ephemeral + timestamp */
        uint8_t save_id[32];

        memcpy(save_id, a->peer_id, 32);
        if (init_check(a, frame, payload, plen, NULL, 0) < 0)
            return -1;
        if (memcmp(a->peer_id, save_id, 32) != 0)
            return -1;          /* different peer: not a rekey */
        if (init_ack_send(a, a->sk) < 0)
            return -1;
        a->state = ICSP_ST_REKEY_WAIT_COOKIE;
        return 0;
    }
    if (a->state == ICSP_ST_REKEY_WAIT_COOKIE &&
        payload[ICSP_HEADER_LEN] == ICSP_CHUNK_COOKIE_ECHO) {
        if (!cookie_valid(cd, a))
            return -1;
        if (ed25519_verify(cd, COOKIE_LEN, cd + COOKIE_LEN, a->peer_id) != 0)
            return -1;
        {
            uint8_t ck[ICSP_CHUNK_HDR];
            icsp_chunk_put(ck, ICSP_CHUNK_COOKIE_ACK, 0);
            if (icsp_send_pkt(a, ck, sizeof(ck)) < 0)
                return -1;
        }
        a->state = ICSP_ST_ESTABLISHED;
        printf("icsp: rekey ok! new session_key=");
        for (int i = 0; i < 32; i++) printf("%02x", a->send_key[i]);
        printf("\n");
        return 1;
    }
    return 0;
}
