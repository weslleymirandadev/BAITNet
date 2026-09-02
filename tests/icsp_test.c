/* icsp_test.c - ICSP test: handshake + data + lifecycle.
 *
 *   ipv69 icsp server <ifname> [port|:port] [--peer HEX] [--peer-file F]
 *          [--echo] [--loss N]
 *   ipv69 icsp client <ifname> <dst:porta> [msg] [--echo] [--reset] [--hb]
 *
 * Handshake (Phase 1), then optionally exchanges data (Phase 2):
 *   server --echo answers back on the same stream;
 *   client sends the msg (or "hello icsp") and, with --echo, waits for
 *   the echo. --reset tests STREAM-RESET; --hb sends a heartbeat.
 *   --loss N% skips SACKs on the server (retransmission test).
 * Identity = the ~/.hosts69 keyring (same as DHCP).
 * Built on the session layer: icsp_endpoint_open + icsp_poll.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#ifdef _WIN32
#include "IPv69/plat.h"
#else
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#endif
#include "IPv69/parse.h"
#include "IPv69/l2.h"
#include "IPv69/af69.h"    /* IPV69_CTRL_ND_REQUEST (tunnel announce) */
#include "ed25519.h"
#include "ICSP/icsp.h"

/* tunnel mode: signed ND announce of our address to the gateway */
static void server_announce(const struct icsp_assoc *a,
                            const uint8_t sk[64])
{
    const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t ann[1 + 5 + 32 + 64] = { IPV69_CTRL_ND_REQUEST };
    uint8_t frame[512];
    put_addr40(ann + 1, a->src_addr);
    memcpy(ann + 6, sk + 32, 32);
    ed25519_sign(ann + 38, ann, 6, sk);
    size_t l = build_frame(frame, bcast, a->src_mac, a->src_addr,
                           0xFFFFFFFFFFULL, IPV69_NEXT_CONTROL,
                           64, 0, 0, ann, sizeof(ann));
    sendto(a->tfd, (const char *)frame, l, 0,
           (struct sockaddr *)&a->gw, a->gwlen);
}

/* client-side DATA callback: print + remember the echo */
struct client_ctx {
    int echo_mode;
    int got_echo;
};

static void client_on_data(struct icsp_assoc *a, uint16_t stream,
                           const uint8_t *data, size_t len, void *ud)
{
    struct client_ctx *c = ud;
    printf("icsp: recebido %zu bytes (stream %u): \"%.*s\"\n",
           len, stream, (int)len, (char *)data);
    if (c->echo_mode)
        c->got_echo = 1;
    (void)a;
}

/* server-side DATA callback: echo when --echo */
struct server_ctx {
    int echo_mode;
};

static void server_on_data(struct icsp_assoc *a, uint16_t stream,
                           const uint8_t *data, size_t len, void *ud)
{
    struct server_ctx *c = ud;
    printf("icsp: recebido %zu bytes (stream %u): \"%.*s\"\n",
           len, stream, (int)len, (char *)data);
    if (c->echo_mode)
        icsp_data_send(a, stream, data, len);
}

/* client: handshake + optional data exchange */
static int run_client(int argc, char **argv, struct icsp_assoc *a,
                      uint8_t sk[64])
{
    uint64_t dst;
    uint16_t port;
    struct client_ctx ctx = { 0, 0 };
    int hb_mode = 0, reset_mode = 0, rekey_s = 0;
    const char *msg = "hello icsp";

    for (int i = 4; i < argc; i++) {
        if (!strcmp(argv[i], "--echo")) ctx.echo_mode = 1;
        else if (!strcmp(argv[i], "--hb")) hb_mode = 1;
        else if (!strcmp(argv[i], "--reset")) reset_mode = 1;
        else if (!strcmp(argv[i], "--rekey") && i + 1 < argc)
            rekey_s = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--remote") && i + 1 < argc)
            i++;                /* handled by cmd_icsp (tunnel mode) */
        else msg = argv[i];
    }
    if (argc < 4 || parse_ipv69_addr_port(argv[3], &dst, &port) < 0) {
        fprintf(stderr, "icsp client: precisa <dst:porta> [msg] "
                        "[--echo|--hb|--reset]\n");
        return 1;
    }
    if (port == 0)
        port = 6969;
    printf("icsp: cliente -> %016llx:%u\n", (unsigned long long)dst, port);

    if (icsp_client_handshake(a, dst, port, sk, NULL) < 0)
        return 1;
    printf("icsp: session_key == %02x%02x..%02x%02x\n",
           a->send_key[0], a->send_key[1],
           a->send_key[30], a->send_key[31]);
    if (rekey_s > 0)
        a->rekey_interval_s = rekey_s;   /* WG-style time-based rekey */

    if (hb_mode) {
        printf("icsp: HEARTBEAT ->\n");
        if (icsp_heartbeat_send(a) < 0)
            return 1;
    }
    if (reset_mode) {
        printf("icsp: STREAM-RESET stream 3 ->\n");
        icsp_stream_reset(a, 3, 0);
    }

    /* send the message on stream 1 (and a second on stream 2).
       data_send returns the TSN (uint32 — may be negative as int with
       the random initial TSN); only -1 means failure. */
    int tsn = icsp_data_send(a, 1, (const uint8_t *)msg, strlen(msg));
    if (tsn == -1) {
        fprintf(stderr, "icsp: data_send falhou\n");
        return 1;
    }
    printf("icsp: DATA enviado (tsn=%d, stream 1)\n", tsn);
    icsp_data_send(a, 2, (const uint8_t *)"msg na stream 2", 17);

    /* wait for SACK (and echo when --echo); retransmit on idle.
       With --rekey keep polling past the echo so the timer fires. */
    time_t deadline = time(NULL) + 3 + (rekey_s > 0 ? rekey_s : 0);
    while (time(NULL) < deadline) {
        int r = icsp_poll(a, 200, client_on_data, &ctx);
        if (r == ICSP_POLL_CLOSED)
            break;
        if (r == ICSP_POLL_ERR) {
            fprintf(stderr, "icsp: erro na associação\n");
            return 1;
        }
        if (r == ICSP_POLL_TIMEOUT) {
            int rt = icsp_data_retransmit(a, 1);
            if (rt > 0)
                printf("icsp: retransmitiu DATA (%d)\n", rt);
        }
        if (rekey_s == 0 &&
            (ctx.got_echo || !ctx.echo_mode) && icsp_all_acked(a))
            break;
    }
    printf("icsp: sack=%d echo=%d\n", icsp_all_acked(a), ctx.got_echo);

    /* graceful close */
    icsp_shutdown_send(a);
    printf("icsp: SHUTDOWN enviado\n");
    return 0;
}

/* server: handshake + echo data when --echo */
static int run_server(int argc, char **argv, struct icsp_assoc *a,
                      uint8_t sk[64])
{
    uint8_t peers[64][32];
    int n_peers = 0;
    struct server_ctx ctx = { 0 };
    int loss_pct = 0;
    uint16_t port = 6969;

    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--echo")) ctx.echo_mode = 1;
        else if (!strcmp(argv[i], "--loss") && i + 1 < argc)
            loss_pct = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--peer") && i + 1 < argc) {
            if (hex_decode(argv[++i], peers[n_peers], 32) != 32) {
                fprintf(stderr, "icsp: --peer invalido\n");
                return 1;
            }
            n_peers++;
        } else if (!strcmp(argv[i], "--peer-file") && i + 1 < argc) {
            FILE *f = fopen(argv[++i], "r");
            char line[128];
            if (!f) { perror("icsp: peer-file"); return 1; }
            while (fgets(line, sizeof(line), f)) {
                line[strcspn(line, "\r\n")] = 0;
                if (line[0] && n_peers < 64 &&
                    hex_decode(line, peers[n_peers], 32) == 32)
                    n_peers++;
            }
            fclose(f);
        } else if (!strcmp(argv[i], "--remote") && i + 1 < argc) {
            i++;                /* handled by cmd_icsp (tunnel mode) */
        } else if (argv[i][0] == ':' && argv[i][1]) {
            port = (uint16_t)atoi(argv[i] + 1);
        } else if (argv[i][0] != '-') {
            port = (uint16_t)atoi(argv[i]);
        }
    }
    printf("icsp: servidor em porta %u (peers=%d, echo=%d, loss=%d%%)\n",
           port, n_peers, ctx.echo_mode, loss_pct);

    /* tunnel mode: announce ourselves to the gateway (signed ND
     * request) so it learns our address and can route the INIT to us */
    if (a->tunnel)
        server_announce(a, sk);

    if (icsp_server_accept(a, port, sk, peers, n_peers, 30) < 0)
        return 1;
    printf("icsp: session_key == %02x%02x..%02x%02x\n",
           a->send_key[0], a->send_key[1],
           a->send_key[30], a->send_key[31]);
    a->sack_loss_pct = loss_pct;        /* fault injection (auto-SACK) */
    printf("icsp: servidor escutando (ctrl-C para sair)\n");

    /* serve this association, then accept the next one */
    time_t last_ann = 0;
    for (;;) {
        if (a->tunnel && time(NULL) - last_ann >= 2) {
            server_announce(a, sk);
            last_ann = time(NULL);
        }
        int r = icsp_poll(a, 200, server_on_data, &ctx);
        if (r == ICSP_POLL_ERR) {
            perror("icsp: poll");
            return 1;
        }
        if (r == ICSP_POLL_CLOSED) {
            printf("icsp: SHUTDOWN recebido — associação fechada, "
                   "aguardando proxima...\n");
            if (icsp_server_accept(a, port, sk, peers, n_peers, 30) < 0)
                return 1;
            a->sack_loss_pct = loss_pct;
            printf("icsp: nova associação aceita — session_key == "
                   "%02x%02x..%02x%02x\n",
                   a->send_key[0], a->send_key[1],
                   a->send_key[30], a->send_key[31]);
        }
    }
}

int cmd_icsp(int argc, char **argv)
{
    uint8_t sk[64];
    struct icsp_assoc a;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc < 3) {
        fprintf(stderr, "icsp: precisa <server|client> <ifname> [args]\n");
        return 1;
    }
    const char *remote = NULL;
    for (int i = 3; i < argc; i++)
        if (!strcmp(argv[i], "--remote") && i + 1 < argc)
            remote = argv[++i];
    if (remote) {
        /* tunnel mode: ICSP over the gateway (--remote gw:port) */
        if (icsp_endpoint_open_remote(&a, remote, sk) < 0) {
            fprintf(stderr, "icsp: --remote invalido (%s)\n", remote);
            return 1;
        }
    } else if (icsp_endpoint_open(&a, argv[2], sk) < 0) {
        fprintf(stderr, "icsp: sem identidade (crie com ipv69 keygen)\n");
        return 1;
    }

    if (!strcmp(argv[1], "server"))
        return run_server(argc, argv, &a, sk);
    if (!strcmp(argv[1], "client"))
        return run_client(argc, argv, &a, sk);

    fprintf(stderr, "icsp: modo desconhecido '%s' (server|client)\n", argv[1]);
    return 1;
}
