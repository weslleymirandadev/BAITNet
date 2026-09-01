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
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include "IPv69/parse.h"
#include "IPv69/l2.h"
#include "ICSP/icsp.h"

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
    int hb_mode = 0, reset_mode = 0;
    const char *msg = "hello icsp";

    for (int i = 4; i < argc; i++) {
        if (!strcmp(argv[i], "--echo")) ctx.echo_mode = 1;
        else if (!strcmp(argv[i], "--hb")) hb_mode = 1;
        else if (!strcmp(argv[i], "--reset")) reset_mode = 1;
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

    if (icsp_client_handshake(a, dst, port, sk) < 0)
        return 1;
    printf("icsp: session_key == %02x%02x..%02x%02x\n",
           a->session_key[0], a->session_key[1],
           a->session_key[30], a->session_key[31]);

    if (hb_mode) {
        printf("icsp: HEARTBEAT ->\n");
        if (icsp_heartbeat_send(a) < 0)
            return 1;
    }
    if (reset_mode) {
        printf("icsp: STREAM-RESET stream 3 ->\n");
        icsp_stream_reset(a, 3, 0);
    }

    /* send the message on stream 1 (and a second on stream 2) */
    int tsn = icsp_data_send(a, 1, (const uint8_t *)msg, strlen(msg));
    if (tsn < 0) {
        fprintf(stderr, "icsp: data_send falhou\n");
        return 1;
    }
    printf("icsp: DATA enviado (tsn=%d, stream 1)\n", tsn);
    icsp_data_send(a, 2, (const uint8_t *)"msg na stream 2", 17);

    /* wait for SACK (and echo when --echo); retransmit on idle */
    time_t deadline = time(NULL) + 3;
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
        if ((ctx.got_echo || !ctx.echo_mode) && icsp_all_acked(a))
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
        } else if (argv[i][0] == ':' && argv[i][1]) {
            port = (uint16_t)atoi(argv[i] + 1);
        } else if (argv[i][0] != '-') {
            port = (uint16_t)atoi(argv[i]);
        }
    }
    printf("icsp: servidor em porta %u (peers=%d, echo=%d, loss=%d%%)\n",
           port, n_peers, ctx.echo_mode, loss_pct);

    if (icsp_server_accept(a, port, sk, peers, n_peers, 30) < 0)
        return 1;
    printf("icsp: session_key == %02x%02x..%02x%02x\n",
           a->session_key[0], a->session_key[1],
           a->session_key[30], a->session_key[31]);
    a->sack_loss_pct = loss_pct;        /* fault injection (auto-SACK) */
    printf("icsp: servidor escutando (ctrl-C para sair)\n");

    /* serve this association, then accept the next one */
    for (;;) {
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
                   a->session_key[0], a->session_key[1],
                   a->session_key[30], a->session_key[31]);
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
    if (icsp_endpoint_open(&a, argv[2], sk) < 0) {
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
