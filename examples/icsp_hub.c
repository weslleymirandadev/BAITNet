/* icsp_hub.c - EXAMPLE: group chat hub on the ICSP session layer.
 *
 * A small multicast server: one association per L2 interface (each
 * client lives on its own island/interface), all bridged together —
 * every message received from any client is rebroadcast to every other
 * client with a "[name] " prefix, and lines typed on the hub's stdin go
 * to all of them. The hub itself is a participant too.
 *
 * This is NOT part of the ipv69 binary — a standalone example showing
 * the multi-association pattern on top of ICSP: N independent
 * struct icsp_assoc (one per endpoint), one poll() over all their fds
 * + stdin, icsp_server_accept on a slot when its fd turns ready, and
 * icsp_handle_frame on established slots. 1:1 chat stays in
 * examples/icsp_chat.c (make chat).
 *
 * Usage:
 *   ./icsp_hub <iface[:name]> [<iface[:name]> ...] [port|:port]
 *             [--peer HEX]
 *   ./icsp_hub eth0:moto eth1:windows 6969
 *
 * Clients are plain `icsp_chat client` (or any ICSP tool) pointing at
 * this host's identity-derived address and the hub port. Ctrl-D on the
 * hub closes its own stdin (keeps serving); SIGINT stops the hub.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <net/if.h>
#include "IPv69/parse.h"
#include "IPv69/l2.h"
#include "IPv69/plat.h"
#include "ICSP/icsp.h"

#define HUB_MAX_SLOTS 8

struct hub_slot {
    struct icsp_assoc a;
    const char *ifname;
    char name[32];
    int up;                     /* association established */
};

static volatile int g_stop = 0;
static void on_int(int s) { (void)s; g_stop = 1; }

static void hub_usage(void)
{
    fprintf(stderr,
        "icsp_hub - group chat hub: bridge N clients into one chat\n"
        "\n"
        "Usage: icsp_hub <iface[:name]> [<iface[:name]> ...] "
        "[port|:port] [--peer HEX]\n"
        "\n"
        "  Each interface accepts ONE client (own association). Every\n"
        "  message from a client is rebroadcast to all the others with a\n"
        "  '[name] ' prefix; lines typed here go to every client. The\n"
        "  typical setup is one interface per island (e.g. eth0 bridging\n"
        "  to a phone over Wi-Fi, eth1 host-only to a PC).\n"
        "\n"
        "Options:\n"
        "  --peer HEX   allowlist: accept only this identity (repeatable)\n"
        "\n"
        "Clients use the plain chat client: icsp_chat client <ifname>\n"
        "<hub_addr>:<port>. Identity: ~/.hosts69 keyring. Ctrl-D closes\n"
        "the hub's stdin (clients keep chatting); SIGINT stops the hub.\n");
}

/* incoming DATA from a client: print locally and relay to every other
 * established slot, prefixed with the sender's name. */
struct hub_ctx {
    struct hub_slot slots[HUB_MAX_SLOTS];
    int n;
};

/* relay one message from slot `src` to every other up slot */
static void relay_to_others(struct hub_ctx *h, int src, uint16_t stream,
                            const uint8_t *data, size_t len)
{
    for (int j = 0; j < h->n; j++) {
        if (j == src || !h->slots[j].up)
            continue;
        /* prefix with the sender name so receivers know who talked */
        char buf[ICSP_MAX_PAYLOAD];
        int pl = snprintf(buf, sizeof(buf), "[%s] ", h->slots[src].name);
        if (pl < 0 || (size_t)pl >= sizeof(buf))
            continue;
        size_t left = sizeof(buf) - (size_t)pl;
        if (left > len)
            left = len;
        memcpy(buf + pl, data, left);
        icsp_data_send(&h->slots[j].a, stream, (const uint8_t *)buf,
                       (size_t)pl + left);
    }
}

static void hub_on_data(struct icsp_assoc *a, uint16_t stream,
                        const uint8_t *data, size_t len, void *ud)
{
    struct hub_ctx *h = ud;
    for (int i = 0; i < h->n; i++) {
        if (&h->slots[i].a != a)
            continue;
        printf("[%s] %.*s\n", h->slots[i].name, (int)len, (char *)data);
        fflush(stdout);
        relay_to_others(h, i, stream, data, len);
        return;
    }
}

/* broadcast one hub-stdin line to every established slot */
static void hub_broadcast(struct hub_ctx *h, uint16_t stream, char *line)
{
    size_t len = strlen(line);
    while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = 0;
    if (!len)
        return;
    for (int i = 0; i < h->n; i++)
        if (h->slots[i].up)
            icsp_data_send(&h->slots[i].a, stream,
                           (const uint8_t *)line, len);
}

int main(int argc, char **argv)
{
    struct hub_ctx h;
    uint8_t sk[64];
    uint8_t peers[64][32];
    int n_peers = 0;
    uint16_t port = 6969;
    int use_stdin = 1;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (plat_sock_init() < 0) {
        fprintf(stderr, "hub: winsock init failed\n");
        return 1;
    }
    if (argc < 2) {
        hub_usage();
        return 1;
    }
    memset(&h, 0, sizeof(h));
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            hub_usage();
            return 0;
        }
        if (!strcmp(argv[i], "--peer") && i + 1 < argc) {
            if (hex_decode(argv[++i], peers[n_peers], 32) != 32) {
                fprintf(stderr, "hub: invalid --peer\n");
                return 1;
            }
            n_peers++;
            continue;
        }
        if (argv[i][0] == ':' && argv[i][1]) {
            port = (uint16_t)atoi(argv[i] + 1);
            continue;
        }
        if (argv[i][0] != '-' && !strchr(argv[i], ':') &&
            argv[i][0] >= '0' && argv[i][0] <= '9') {
            port = (uint16_t)atoi(argv[i]);
            continue;
        }
        if (h.n >= HUB_MAX_SLOTS) {
            fprintf(stderr, "hub: too many interfaces (max %d)\n",
                    HUB_MAX_SLOTS);
            return 1;
        }
        /* iface or iface:name */
        char *colon = strchr(argv[i], ':');
        struct hub_slot *s = &h.slots[h.n];
        if (colon && colon[1]) {
            size_t nl = (size_t)(colon - argv[i]);
            char ifn[IFNAMSIZ];
            if (nl >= sizeof(ifn)) nl = sizeof(ifn) - 1;
            memcpy(ifn, argv[i], nl);
            ifn[nl] = 0;
            s->ifname = strdup(ifn);
            snprintf(s->name, sizeof(s->name), "%s", colon + 1);
        } else {
            s->ifname = argv[i];
            snprintf(s->name, sizeof(s->name), "%s", argv[i]);
        }
        h.n++;
    }
    if (h.n == 0) {
        fprintf(stderr, "hub: no interfaces given\n");
        return 1;
    }

    /* open one endpoint (own raw socket) per interface, same identity */
    for (int i = 0; i < h.n; i++) {
        if (icsp_endpoint_open(&h.slots[i].a, h.slots[i].ifname, sk) < 0) {
            fprintf(stderr, "hub: cannot open %s (identity? ipv69 keygen)\n",
                    h.slots[i].ifname);
            return 1;
        }
        printf("hub: slot %d = %s (%s), waiting for a client...\n",
               i, h.slots[i].ifname, h.slots[i].name);
    }
    printf("hub: port %u, peers=%d, %d slot(s). Ctrl-D closes stdin, "
           "SIGINT stops.\n", port, n_peers, h.n);
    signal(SIGINT, on_int);
    signal(SIGTERM, on_int);

    struct pollfd *pfd = calloc((size_t)h.n + 1, sizeof(*pfd));
    if (!pfd)
        return 1;
    uint8_t *frame = malloc(1600);
    if (!frame)
        return 1;

    while (!g_stop) {
        /* poll stdin + every slot fd */
        int nfds = 0;
        pfd[nfds].fd = 0;                 /* stdin */
        pfd[nfds].events = POLLIN;
        pfd[nfds].revents = 0;
        nfds++;
        for (int i = 0; i < h.n; i++) {
            pfd[nfds].fd = (int)h.slots[i].a.fd;
            pfd[nfds].events = POLLIN;
            pfd[nfds].revents = 0;
            nfds++;
        }
        int pr = poll(pfd, (nfds_t)nfds, 200);
        if (pr < 0) {
            if (errno == EINTR && g_stop)
                break;
            if (errno == EINTR)
                continue;
            perror("hub: poll");
            break;
        }

        /* stdin: broadcast each line to every client */
        if (use_stdin && (pfd[0].revents & POLLIN)) {
            char line[ICSP_MAX_PAYLOAD];
            if (!fgets(line, sizeof(line), stdin)) {
                if (isatty(0)) {
                    printf("hub: stdin closed (Ctrl-D) — clients keep "
                           "chatting\n");
                    fflush(stdout);
                    use_stdin = 0;
                } else {
                    use_stdin = 0;   /* pipe EOF: keep serving */
                }
            } else {
                hub_broadcast(&h, 1, line);
            }
        }

        /* each slot: accept when idle+ready, otherwise handle frames */
        for (int i = 0; i < h.n; i++) {
            if (!(pfd[1 + i].revents & POLLIN))
                continue;
            struct hub_slot *s = &h.slots[i];
            if (!s->up) {
                /* an INIT arrived: run the accept handshake (finishes in
                   ms on a live client; 5s bound if the peer vanished) */
                if (icsp_server_accept(&s->a, port, sk, peers, n_peers,
                                       5) == 0) {
                    s->up = 1;
                    s->a.hb_interval_s = 6;
                    s->a.dead_timeout_s = 18;
                    /* the accept left a 5s recv timeout; the hub polls
                       the fd itself, so make recv non-blocking */
                    s->a.rcv_timeout_ms = 0;
                    printf("hub: [%s] client connected (session_key "
                           "%02x%02x..%02x%02x)\n",
                           s->name, s->a.send_key[0], s->a.send_key[1],
                           s->a.send_key[30], s->a.send_key[31]);
                    fflush(stdout);
                }
                /* accept failed (noise/timeout): slot stays open */
                continue;
            }
            /* established slot with data: receive + dispatch one frame
               (the fd is ready, so the recv does not block); DATA goes
               to hub_on_data -> rebroadcast */
            {
                const uint8_t *payload;
                size_t plen;
                uint64_t from;
                ssize_t n = icsp_recv_frame(&s->a, frame, &payload, &plen,
                                            &from);
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        continue;
                    printf("hub: [%s] recv error, dropping slot\n",
                           s->name);
                    s->up = 0;
                    fflush(stdout);
                    continue;
                }
                if (n == 0)
                    continue;       /* noise frame */
                int r = icsp_handle_frame(&s->a, frame, n, hub_on_data,
                                          &h);
                if (r == ICSP_POLL_CLOSED) {
                    printf("hub: [%s] client left (SHUTDOWN) — waiting "
                           "for the next one...\n", s->name);
                    s->up = 0;
                    fflush(stdout);
                } else if (r == ICSP_POLL_ERR) {
                    printf("hub: [%s] association error, dropping slot\n",
                           s->name);
                    s->up = 0;
                    fflush(stdout);
                }
            }
        }

        /* keepalive: dead peers free their slot (accept again) */
        for (int i = 0; i < h.n; i++) {
            struct hub_slot *s = &h.slots[i];
            if (s->up && icsp_keepalive_tick(&s->a)) {
                printf("hub: [%s] peer silent %ds — dropping, waiting for "
                       "the next one...\n", s->name, s->a.dead_timeout_s);
                s->up = 0;
                fflush(stdout);
            }
        }
    }

    /* graceful: tell every client we are leaving */
    for (int i = 0; i < h.n; i++)
        if (h.slots[i].up)
            icsp_shutdown_send(&h.slots[i].a);
    free(pfd);
    free(frame);
    printf("hub: stopped\n");
    return 0;
}
