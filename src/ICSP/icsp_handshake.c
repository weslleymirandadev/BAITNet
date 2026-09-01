/* icsp_handshake.c - ICSP Phase 1: authenticated handshake.
 *
 * Client:  INIT -> INIT-ACK(cookie) -> COOKIE-ECHO -> COOKIE-ACK
 * Server:  waits INIT, answers INIT-ACK (signed, secret cookie),
 *          validates COOKIE-ECHO (signature + cookie) -> ESTABLISHED.
 *
 * Security model (spec §5): the Ed25519 identity authenticates the
 * peer (same pubkey allowlist concept as DHCP69); ephemeral X25519
 * provides forward secrecy; cookie = server secret + hash of params,
 * clients cannot forge it. Session key = SHA-512(X25519 shared ||
 * assoc_id || "icsp-v1").
 *
 * The endpoint context (fd/ifindex/src_mac/dst_addr) lives in the
 * association (icsp_endpoint_open + the caller); frame TX goes through
 * the shared icsp_send_pkt, RX through icsp_recv_frame.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include "IPv69/header.h"
#include "IPv69/l2.h"
#include "ed25519.h"
#include "ICSP/icsp.h"

/* cookie = server-secret MAC over (client_id_pub, client_eph, streams).
 * Secret rotates every 5 min; the cookie embeds a timestamp so a valid
 * cookie stays acceptable for a short window. */
#define COOKIE_LEN 48
#define COOKIE_TTL 300

static uint8_t server_secret[32];
static time_t secret_ts;

static void secret_refresh(void)
{
    if (!server_secret[0] || time(NULL) - secret_ts > COOKIE_TTL) {
        FILE *ur = fopen("/dev/urandom", "r");
        if (ur) {
            size_t n = fread(server_secret, 1, sizeof(server_secret), ur);
            fclose(ur);
            if (n == sizeof(server_secret))
                secret_ts = time(NULL);
        }
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
 * src_mac, dst_addr) and the keepalive config — so a server can accept
 * association after association on the same socket. */
static void assoc_reset(struct icsp_assoc *a)
{
    int fd = a->fd, ifindex = a->ifindex;
    uint8_t smac[6];
    uint64_t dst_addr = a->dst_addr, src_addr = a->src_addr;
    int hb = a->hb_interval_s, dead = a->dead_timeout_s;

    memcpy(smac, a->src_mac, 6);
    memset(a, 0, sizeof(*a));
    a->fd = fd;
    a->ifindex = ifindex;
    memcpy(a->src_mac, smac, 6);
    a->dst_addr = dst_addr;
    a->src_addr = src_addr;
    a->hb_interval_s = hb;
    a->dead_timeout_s = dead;
}

/* --- client --- */
int icsp_client_handshake(struct icsp_assoc *a, uint64_t dst_addr,
                          uint16_t dst_port, const uint8_t sk[64])
{
    uint8_t frame[1600];
    uint8_t eph_priv[32];
    const uint8_t *payload;
    size_t plen;
    uint64_t from;
    struct timeval tv = { 3, 0 };

    assoc_reset(a);
    a->dst_addr = dst_addr;
    a->dst_port = dst_port;
    if (a->src_port == 0)
        a->src_port = 50000 + (uint16_t)getpid() % 1000;
    a->state = ICSP_ST_COOKIE_WAIT;
    a->streams_in = a->streams_out = 4;
    {
        uint8_t rnd[4];
        FILE *ur = fopen("/dev/urandom", "r");
        if (!ur || fread(rnd, 1, 4, ur) != 4)
            return -1;
        fclose(ur);
        a->assoc_id = ((uint32_t)rnd[0] << 24) | ((uint32_t)rnd[1] << 16) |
                      ((uint32_t)rnd[2] << 8) | rnd[3];
    }
    /* identity + ephemeral keypair */
    memcpy(a->id_pub, sk + 32, 32);
    {
        FILE *ur = fopen("/dev/urandom", "r");
        if (!ur || fread(eph_priv, 1, 32, ur) != 32)
            return -1;
        fclose(ur);
    }
    if (ed25519_scalarmult_base(a->eph_pub, eph_priv) != 0)
        return -1;
    setsockopt(a->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* INIT [ver][streams_in 2][streams_out 2][eph 32][id 32][sig 64] */
    uint8_t chunk[ICSP_CHUNK_HDR + 1 + 4 + 32 + 32 + 64];
    uint8_t *d = icsp_chunk_put(chunk, ICSP_CHUNK_INIT,
                                1 + 4 + 32 + 32 + 64);
    d[0] = ICSP_VERSION;
    d[1] = (uint8_t)(a->streams_in >> 8);
    d[2] = (uint8_t)a->streams_in;
    d[3] = (uint8_t)(a->streams_out >> 8);
    d[4] = (uint8_t)a->streams_out;
    memcpy(d + 5, a->eph_pub, 32);
    memcpy(d + 37, a->id_pub, 32);
    ed25519_sign(d + 69, d, 5 + 32 + 32, sk);
    if (icsp_send_pkt(a, chunk, sizeof(chunk)) < 0) {
        perror("icsp: send INIT");
        return -1;
    }
    printf("icsp: INIT enviado (dst=%016llx:%u)\n",
           (unsigned long long)dst_addr, dst_port);

    /* wait INIT-ACK [ver][streams][eph 32][id 32][sig 64][cookie] */
    for (;;) {
        ssize_t n = icsp_recv_frame(a, frame, &payload, &plen, &from);
        if (n < 0) { perror("icsp: INIT-ACK"); return -1; }
        if (n == 0)
            continue;           /* noise frame */
        if (payload[4] != ICSP_VERSION ||
            payload[ICSP_HEADER_LEN] != ICSP_CHUNK_INIT_ACK)
            continue;
        const uint8_t *cd = payload + ICSP_HEADER_LEN + ICSP_CHUNK_HDR;
        uint8_t ver = cd[0];
        uint16_t s_in = (uint16_t)((cd[1] << 8) | cd[2]);
        uint16_t s_out = (uint16_t)((cd[3] << 8) | cd[4]);
        (void)ver; (void)s_in; (void)s_out;
        memcpy(a->peer_eph, cd + 5, 32);
        memcpy(a->peer_id, cd + 37, 32);
        /* verify server signature over [ver..id] */
        if (ed25519_verify(cd, 5 + 32 + 32, cd + 69, a->peer_id) != 0) {
            printf("icsp: INIT-ACK assinatura invalida (servidor falso)\n");
            return -1;
        }
        printf("icsp: INIT-ACK ok (peer_id=%02x%02x.., assoc=%u)\n",
               a->peer_id[0], a->peer_id[1], a->assoc_id);
        /* derive the shared session key (peer_eph now known) */
        if (icsp_derive_key(a, eph_priv) != 0)
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
        printf("icsp: COOKIE-ECHO enviado\n");
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
        printf("icsp: COOKIE-ACK — associação estabelecida! session_key=");
        for (int i = 0; i < 32; i++) printf("%02x", a->session_key[i]);
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
    uint8_t eph_priv[32];
    const uint8_t *payload;
    size_t plen;
    uint64_t from;
    struct timeval tv = { 30, 0 };

    assoc_reset(a);
    a->src_port = port;
    a->dst_port = 0;
    a->state = ICSP_ST_CLOSED;
    a->streams_in = a->streams_out = 4;
    memcpy(a->id_pub, sk + 32, 32);
    {
        FILE *ur = fopen("/dev/urandom", "r");
        if (!ur || fread(eph_priv, 1, 32, ur) != 32)
            return -1;
        fclose(ur);
    }
    if (ed25519_scalarmult_base(a->eph_pub, eph_priv) != 0)
        return -1;
    if (timeout_s > 0) {
        tv.tv_sec = timeout_s;
        tv.tv_usec = 0;
        setsockopt(a->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    } else {
        /* blocking listen: a real server waits forever */
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        setsockopt(a->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    /* wait INIT */
    for (;;) {
        ssize_t n = icsp_recv_frame(a, frame, &payload, &plen, &from);
        if (n < 0) { perror("icsp: INIT"); return -1; }
        if (n == 0)
            continue;
        if (payload[ICSP_HEADER_LEN] != ICSP_CHUNK_INIT)
            continue;
        const uint8_t *cd = payload + ICSP_HEADER_LEN + ICSP_CHUNK_HDR;
        if (cd[0] != ICSP_VERSION)
            continue;
        a->assoc_id = (uint32_t)(((uint32_t)payload[6] << 24) |
                                 ((uint32_t)payload[7] << 16) |
                                 ((uint32_t)payload[8] << 8) |
                                 payload[9]);
        a->dst_addr = from;
        memcpy(a->peer_eph, cd + 5, 32);
        memcpy(a->peer_id, cd + 37, 32);
        /* verify client signature */
        if (ed25519_verify(cd, 5 + 32 + 32, cd + 69, a->peer_id) != 0) {
            printf("icsp: INIT assinatura invalida -> recusado\n");
            return -1;
        }
        /* allowlist (like DHCP --peer/--peer-file); empty = accept any
           valid signature (like --learn) */
        if (n_peers > 0) {
            int ok = 0;
            for (int i = 0; i < n_peers; i++)
                if (!memcmp(peers[i], a->peer_id, 32)) { ok = 1; break; }
            if (!ok) {
                printf("icsp: INIT peer_id nao autorizado (%02x%02x..) "
                       "-> recusado\n", a->peer_id[0], a->peer_id[1]);
                return -1;
            }
        }
        printf("icsp: INIT ok (peer_id=%02x%02x..) -> INIT-ACK\n",
               a->peer_id[0], a->peer_id[1]);
        break;
    }
    /* derive session key and answer INIT-ACK [ver][streams][eph 32][id 32][sig 64][cookie 48] */
    if (icsp_derive_key(a, eph_priv) != 0)
        return -1;
    uint8_t chunk[ICSP_CHUNK_HDR + 1 + 4 + 32 + 32 + 64 + COOKIE_LEN];
    uint8_t *d = icsp_chunk_put(chunk, ICSP_CHUNK_INIT_ACK,
                                1 + 4 + 32 + 32 + 64 + COOKIE_LEN);
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
    printf("icsp: INIT-ACK enviado (cookie)\n");

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
            printf("icsp: COOKIE-ECHO cookie invalido -> recusado\n");
            return -1;
        }
        if (ed25519_verify(cd, COOKIE_LEN, cd + COOKIE_LEN, a->peer_id) != 0) {
            printf("icsp: COOKIE-ECHO assinatura invalida -> recusado\n");
            return -1;
        }
        printf("icsp: COOKIE-ECHO ok -> COOKIE-ACK\n");
        break;
    }
    /* COOKIE-ACK */
    uint8_t ck[ICSP_CHUNK_HDR];
    icsp_chunk_put(ck, ICSP_CHUNK_COOKIE_ACK, 0);
    if (icsp_send_pkt(a, ck, sizeof(ck)) < 0) {
        perror("icsp: send COOKIE-ACK");
        return -1;
    }
    a->state = ICSP_ST_ESTABLISHED;
    printf("icsp: associação estabelecida! session_key=");
    for (int i = 0; i < 32; i++) printf("%02x", a->session_key[i]);
    printf("\n");
    return 0;
}
