/* icsp_session.c - ICSP session layer: endpoint, receive, poll, relay.
 *
 * What the tools used to hand-roll on top of the transport: open the
 * endpoint (identity + raw socket), parse the L2 frame, refresh the
 * peer MAC, answer heartbeats, send SACKs, detect a dead peer and a
 * graceful SHUTDOWN. icsp_poll() wraps all of it in a select loop and
 * icsp_relay() is the netcat primitive (stdin <-> stream). The L2
 * backend is portable: AF_PACKET on POSIX (l2.c), Npcap on Windows
 * (l2_win.c) — everything here goes through l2_recv/l2_send.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#ifdef _WIN32
#include <winsock2.h>   /* must precede windows.h */
#include <windows.h>
#include <io.h>
#else
#include <poll.h>
#include <arpa/inet.h>
#endif
#include "IPv69/header.h"
#include "IPv69/l2.h"
#include "IPv69/keyring.h"
#include "IPv69/parse.h"    /* ipv69_addr_derive for tunnel mode */
#include "ed25519.h"
#include "ICSP/icsp.h"

int icsp_endpoint_open(struct icsp_assoc *a, const char *ifname,
                       uint8_t sk[64])
{
    char key[512], kpub[512], dir[256], comment[128];
    uint8_t pub[32];

    memset(a, 0, sizeof(*a));
    keyring_paths(dir, sizeof(dir), key, sizeof(key), kpub, sizeof(kpub));
    if (keyring_load_or_create(key, kpub, sk, pub, comment,
                               sizeof(comment)) < 0)
        return -1;
    memcpy(a->id_pub, pub, 32);
    memcpy(a->sk, sk, 64);      /* rekey signs with the identity */
    if (l2_open(ifname, &a->fd, &a->ifindex, a->src_mac) < 0)
        return -1;
    return 0;
}

/* open an ICSP endpoint in tunnel mode (--remote gw:port): frames go to
 * the gateway over UDP. The local MAC and address are derived from the
 * identity (the gateway learns us from the signed INIT/announce). */
int icsp_endpoint_open_remote(struct icsp_assoc *a, const char *gwstr,
                              uint8_t sk[64])
{
    char key[512], kpub[512], dir[256], comment[128];
    uint8_t pub[32];

    memset(a, 0, sizeof(*a));
    keyring_paths(dir, sizeof(dir), key, sizeof(key), kpub, sizeof(kpub));
    if (keyring_load_or_create(key, kpub, sk, pub, comment,
                               sizeof(comment)) < 0)
        return -1;
    memcpy(a->id_pub, pub, 32);
    memcpy(a->sk, sk, 64);      /* rekey signs with the identity */

    char hp[256];
    snprintf(hp, sizeof(hp), "%s", gwstr);
    char *colon = strrchr(hp, ':');
    if (!colon)
        return -1;
    *colon = 0;
    int gport = atoi(colon + 1);
    char *host = hp;
    if (host[0] == '[') {       /* [v6]:port */
        host++;
        char *rb = strchr(host, ']');
        if (rb)
            *rb = 0;
    }
    struct sockaddr_in g4;
    struct sockaddr_in6 g6;
    int fam;
    if (inet_pton(AF_INET, host, &g4.sin_addr) == 1) {
        g4.sin_family = AF_INET;
        g4.sin_port = htons(gport);
        memcpy(&a->gw, &g4, sizeof(g4));
        a->gwlen = sizeof(g4);
        fam = AF_INET;
    } else if (inet_pton(AF_INET6, host, &g6.sin6_addr) == 1) {
        g6.sin6_family = AF_INET6;
        g6.sin6_port = htons(gport);
        memcpy(&a->gw, &g6, sizeof(g6));
        a->gwlen = sizeof(g6);
        fam = AF_INET6;
    } else {
        return -1;
    }
    a->tfd = socket(fam, SOCK_DGRAM, 0);
    if (a->tfd == SOCK_INVALID)
        return -1;
    a->tunnel = 1;
    a->ifindex = -1;
    /* locally administered MAC + class-C address from the identity */
    a->src_mac[0] = 0x02;
    memcpy(a->src_mac + 1, pub, 5);
    {
        uint8_t derived[5];
        ipv69_addr_derive(derived, pub, 'C');
        a->src_addr = get_addr40(derived);
    }
    return 0;
}

/* receive one frame on the association transport (tunnel or L2) */
static ssize_t icsp_rx(struct icsp_assoc *a, uint8_t *frame,
                       size_t maxlen, int timeout_ms)
{
    if (a->tunnel) {
        struct timeval tv = { timeout_ms / 1000,
                              (timeout_ms % 1000) * 1000 };
        setsockopt(a->tfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv,
                   sizeof(tv));
        ssize_t n = recvfrom(a->tfd, (char *)frame, maxlen, 0, NULL, NULL);
        return n < 0 ? 0 : n;   /* timeout counts as "nothing" */
    }
    return l2_recv(a->fd, frame, maxlen, timeout_ms);
}

ssize_t icsp_recv_frame(struct icsp_assoc *a, uint8_t *frame,
                        const uint8_t **payload, size_t *plen,
                        uint64_t *src_addr)
{
    ssize_t n = icsp_rx(a, frame, 1600, a->rcv_timeout_ms);
    if (n == 0) {
        errno = ETIMEDOUT;      /* wait expired (handshake fails like
                                   the old SO_RCVTIMEO behavior) */
        return -1;
    }
    if (n < 0)
        return -1;
    if (n < 14 + IPV69_HEADER_LEN + ICSP_HEADER_LEN)
        return 0;               /* noise: not ours */
    /* Npcap (Windows) delivers locally-injected frames back to the
       same handle: a frame we sent ourselves must never be processed
       as received — its DATA is encrypted with our send key and would
       fail the MAC check, killing the association. AF_PACKET (Linux)
       never loops TX back, so this is a no-op there. */
    if (!memcmp(frame + 6, a->src_mac, 6))
        return 0;
    const struct ipv69_header *h =
        (const struct ipv69_header *)(frame + 14);
    if (h->next_header != IPV69_NEXT_STREAM)
        return 0;
    if (payload)
        *payload = frame + 14 + IPV69_HEADER_LEN;
    if (plen)
        *plen = (size_t)(n - 14 - IPV69_HEADER_LEN);
    if (src_addr)
        *src_addr = get_addr40(h->source);
    memcpy(a->peer_mac, frame + 6, 6);   /* reply unicast to the sender */
    a->has_peer_mac = 1;
    a->dst_addr = get_addr40(h->source); /* reply to the sender's addr
                                            (the gateway routes by it) */
    a->last_rx = time(NULL);            /* peer is alive */
    return n;
}

int icsp_handle_frame(struct icsp_assoc *a, const uint8_t *frame, ssize_t n,
                      icsp_data_cb on_data, void *ud)
{
    if (n < 14 + IPV69_HEADER_LEN + ICSP_HEADER_LEN)
        return 0;
    /* Npcap (Windows) loops locally-injected frames back to the same
       handle: a frame we sent ourselves must never be processed as
       received — its DATA is encrypted with our send key and would
       fail the MAC check, killing the association. AF_PACKET (Linux)
       never loops TX back, so this is a no-op there. */
    if (!memcmp(frame + 6, a->src_mac, 6))
        return 0;
    const struct ipv69_header *h =
        (const struct ipv69_header *)(frame + 14);
    if (h->next_header != IPV69_NEXT_STREAM)
        return 0;
    const uint8_t *payload = frame + 14 + IPV69_HEADER_LEN;
    size_t plen = (size_t)(n - 14 - IPV69_HEADER_LEN);

    memcpy(a->peer_mac, frame + 6, 6);
    a->has_peer_mac = 1;
    a->last_rx = time(NULL);

    /* answer HEARTBEAT automatically (keepalive is transport business) */
    if (plen >= ICSP_HEADER_LEN + ICSP_CHUNK_HDR &&
        payload[ICSP_HEADER_LEN] == ICSP_CHUNK_HEARTBEAT)
        icsp_heartbeat_ack(a);

    /* in-session rekey (WireGuard REKEY_AFTER_TIME): the initiator and
       the responder exchange a fresh handshake over the live assoc */
    if (a->state == ICSP_ST_REKEY_WAIT_ACK ||
        a->state == ICSP_ST_REKEY_WAIT_COOKIE_ACK) {
        int r = icsp_rekey_client_step(a, payload);
        if (r < 0)
            return ICSP_POLL_ERR;
        if (r == 1)
            return 0;           /* rekey completed, nothing else to do */
    }
    if (a->state == ICSP_ST_ESTABLISHED ||
        a->state == ICSP_ST_REKEY_WAIT_COOKIE) {
        int r = icsp_rekey_server_step(a, frame, payload, plen);
        if (r < 0)
            return ICSP_POLL_ERR;
        if (r == 1)
            return 0;           /* rekey completed */
    }

    uint32_t cum_before = a->cum_tsn;
    uint8_t out[ICSP_MAX_PAYLOAD];
    size_t olen = sizeof(out);
    uint16_t ostream = 0;
    int m = icsp_data_handle(a, payload, plen, out, &olen, &ostream);
    if (m < 0)
        return ICSP_POLL_ERR;           /* bad MAC: drop the association */
    if (m > 0 && on_data)
        on_data(a, ostream, out, (size_t)m, ud);
    /* SACK when new data arrived (a->sack_loss_pct = test fault injection) */
    if (a->cum_tsn != cum_before &&
        (a->sack_loss_pct <= 0 || rand() % 100 >= a->sack_loss_pct))
        icsp_sack_send(a);
    if (icsp_life_handle(a, payload, plen))
        return ICSP_POLL_CLOSED;
    return m > 0 ? ICSP_POLL_DATA : 0;
}

int icsp_keepalive_tick(struct icsp_assoc *a)
{
    time_t now = time(NULL);
    if (a->dead_timeout_s > 0 && now - a->last_rx >= a->dead_timeout_s)
        return 1;                       /* peer silent too long */
    if (a->hb_interval_s > 0 && now - a->last_hb >= a->hb_interval_s) {
        icsp_heartbeat_send(a);
        a->last_hb = now;
    }
    /* time-based rekey: only the initiator starts it (WG REKEY_AFTER_TIME) */
    if (a->rekey_interval_s > 0 && a->is_initiator &&
        a->state == ICSP_ST_ESTABLISHED &&
        now - a->key_ts >= a->rekey_interval_s) {
        if (icsp_rekey_start(a) == 0)
            printf("icsp: rekey started (new assoc=%u)\n", a->assoc_id);
    }
    return 0;
}

int icsp_poll(struct icsp_assoc *a, int timeout_ms,
              icsp_data_cb on_data, void *ud)
{
    uint8_t frame[1600];

    ssize_t n = icsp_rx(a, frame, sizeof(frame), timeout_ms);
    if (n < 0)
        return ICSP_POLL_ERR;
    if (n == 0)
        return icsp_keepalive_tick(a) ? ICSP_POLL_DEAD : ICSP_POLL_TIMEOUT;
    return icsp_handle_frame(a, frame, n, on_data, ud);
}

/* --- relay: stdin <-> stream (the netcat primitive) ---
 * POSIX watches stdin with poll(); Windows has no pollable console
 * stdin, so a reader thread feeds a small queue. */

static int relay_send_line(struct icsp_assoc *a, uint16_t stream_id,
                           char *line)
{
    size_t len = strlen(line);
    while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = 0;
    if (!len)
        return 1;               /* empty line: skip */
    /* icsp_data_send returns the TSN (uint32 — may be negative as int
       with the random initial TSN); only -1 means failure. */
    return icsp_data_send(a, stream_id, (const uint8_t *)line, len) == -1 ?
           -1 : 1;
}

#ifdef _WIN32
struct stdin_q {
    char buf[64][ICSP_MAX_PAYLOAD];
    int head, tail, count;
    int eof;
    CRITICAL_SECTION cs;
};

static void stdin_q_init(struct stdin_q *q)
{
    memset(q, 0, sizeof(*q));
    InitializeCriticalSection(&q->cs);
}

static void stdin_q_push(struct stdin_q *q, const char *line)
{
    size_t l = strlen(line);
    if (l > ICSP_MAX_PAYLOAD - 1)
        l = ICSP_MAX_PAYLOAD - 1;
    EnterCriticalSection(&q->cs);
    if (q->count < 64) {
        memcpy(q->buf[q->tail], line, l);
        q->buf[q->tail][l] = 0;
        q->tail = (q->tail + 1) % 64;
        q->count++;
    }
    LeaveCriticalSection(&q->cs);
}

static int stdin_q_pop(struct stdin_q *q, char *out)
{
    int got = 0;
    EnterCriticalSection(&q->cs);
    if (q->count > 0) {
        strcpy(out, q->buf[q->head]);
        q->head = (q->head + 1) % 64;
        q->count--;
        got = 1;
    }
    LeaveCriticalSection(&q->cs);
    return got;
}

static int stdin_q_eof(struct stdin_q *q)
{
    int e;
    EnterCriticalSection(&q->cs);
    e = q->eof;
    LeaveCriticalSection(&q->cs);
    return e;
}

static DWORD WINAPI stdin_thread(void *arg)
{
    struct stdin_q *q = (struct stdin_q *)arg;
    char line[ICSP_MAX_PAYLOAD];
    while (fgets(line, sizeof(line), stdin))
        stdin_q_push(q, line);
    EnterCriticalSection(&q->cs);
    q->eof = 1;
    LeaveCriticalSection(&q->cs);
    return 0;
}

static int relay_stdin(struct icsp_assoc *a, uint16_t stream_id,
                       struct stdin_q *q, int *use_stdin)
{
    char line[ICSP_MAX_PAYLOAD];
    while (stdin_q_pop(q, line))
        if (relay_send_line(a, stream_id, line) < 0)
            return -1;
    if (stdin_q_eof(q)) {
        if (_isatty(_fileno(stdin))) {
            icsp_shutdown_send(a);      /* Ctrl-Z: graceful close */
            return 2;                   /* EOF */
        }
        *use_stdin = 0;                 /* pipe EOF: keep receiving */
    }
    return 0;
}
#else
static int relay_stdin(struct icsp_assoc *a, uint16_t stream_id,
                       void *unused, int *use_stdin)
{
    (void)unused;
    struct pollfd pfd = { 0, POLLIN, 0 };
    if (poll(&pfd, 1, 0) <= 0 || !(pfd.revents & POLLIN))
        return 0;
    char line[ICSP_MAX_PAYLOAD];
    if (!fgets(line, sizeof(line), stdin)) {
        if (isatty(0)) {
            icsp_shutdown_send(a);      /* Ctrl-D: graceful close */
            return 2;                   /* EOF */
        }
        *use_stdin = 0;                 /* pipe/daemon EOF: keep receiving */
        return 0;
    }
    return relay_send_line(a, stream_id, line) < 0 ? -1 : 0;
}
#endif

int icsp_relay(struct icsp_assoc *a, uint16_t stream_id, int use_stdin,
               icsp_data_cb on_data, void *ud)
{
    uint8_t frame[1600];
#ifdef _WIN32
    struct stdin_q q;
    stdin_q_init(&q);
    HANDLE thr = CreateThread(NULL, 0, stdin_thread, &q, 0, NULL);
    (void)thr;
#else
    void *q = NULL;
#endif

    for (;;) {
        if (use_stdin) {
#ifdef _WIN32
            int r = relay_stdin(a, stream_id, &q, &use_stdin);
#else
            int r = relay_stdin(a, stream_id, q, &use_stdin);
#endif
            if (r < 0)
                return ICSP_POLL_ERR;
            if (r == 2)                 /* tty EOF: graceful close */
                return ICSP_POLL_EOF;
        }
        ssize_t n = icsp_rx(a, frame, sizeof(frame), 250);
        if (n < 0)
            return ICSP_POLL_ERR;
        if (n == 0) {
            if (icsp_keepalive_tick(a))
                return ICSP_POLL_DEAD;
            continue;
        }
        int pr = icsp_handle_frame(a, frame, n, on_data, ud);
        if (pr == ICSP_POLL_CLOSED || pr == ICSP_POLL_DEAD ||
            pr == ICSP_POLL_ERR)
            return pr;
    }
}
