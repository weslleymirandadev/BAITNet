/* icsp_test.c - ICSP test: handshake + data + lifecycle.
 *
 *   ipv69 icsp server <ifname> [port|:port] [--peer HEX] [--peer-file F]
 *          [--loss N]
 *   ipv69 icsp client <ifname> <dst:port> [msg] [--reset] [--hb]
 *
 * Handshake (Phase 1), then optionally exchanges data (Phase 2):
 *   client sends the msg (or "hello icsp") on streams 1+2 and waits
 *   for the SACK (all_acked); --reset tests STREAM-RESET; --hb sends
 *   a heartbeat. --loss N% skips SACKs on the server (retransmission
 *   test). Identity = the ~/.hosts69 keyring (same as DHCP).
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

/* client-side DATA callback: print what came back */
static void client_on_data(struct icsp_assoc *a, uint16_t stream,
                           const uint8_t *data, size_t len, void *ud)
{
    (void)a; (void)ud;
    printf("icsp: received %zu bytes (stream %u): \"%.*s\"\n",
           len, stream, (int)len, (char *)data);
}

/* server-side DATA callback: log what arrived */
static void server_on_data(struct icsp_assoc *a, uint16_t stream,
                           const uint8_t *data, size_t len, void *ud)
{
    (void)a; (void)ud;
    printf("icsp: received %zu bytes (stream %u): \"%.*s\"\n",
           len, stream, (int)len, (char *)data);
}

/* client: handshake + optional data exchange */
static int run_client(int argc, char **argv, struct icsp_assoc *a,
                      uint8_t sk[64])
{
    uint64_t dst;
    uint16_t port;
    int hb_mode = 0, reset_mode = 0, rekey_s = 0;
    const char *msg = "hello icsp";

    for (int i = 4; i < argc; i++) {
        if (!strcmp(argv[i], "--hb")) hb_mode = 1;
        else if (!strcmp(argv[i], "--reset")) reset_mode = 1;
        else if (!strcmp(argv[i], "--rekey") && i + 1 < argc)
            rekey_s = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--remote") && i + 1 < argc)
            i++;                /* handled by cmd_icsp (tunnel mode) */
        else msg = argv[i];
    }
    if (argc < 4 || parse_ipv69_addr_port(argv[3], &dst, &port) < 0) {
        fprintf(stderr, "icsp client: requires <dst:port> [msg] "
                        "[--hb|--reset]\n");
        return 1;
    }
    if (port == 0)
        port = 6969;
    printf("icsp: client -> %016llx:%u\n", (unsigned long long)dst, port);

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
        fprintf(stderr, "icsp: data_send failed\n");
        return 1;
    }
    printf("icsp: DATA sent (tsn=%d, stream 1)\n", tsn);
    icsp_data_send(a, 2, (const uint8_t *)"msg on stream 2", 17);

    /* wait for the SACKs; retransmit on idle. With --rekey keep
       polling past the ack so the rekey timer fires. */
    time_t deadline = time(NULL) + 3 + (rekey_s > 0 ? rekey_s : 0);
    while (time(NULL) < deadline) {
        int r = icsp_poll(a, 200, client_on_data, NULL);
        if (r == ICSP_POLL_CLOSED)
            break;
        if (r == ICSP_POLL_ERR) {
            fprintf(stderr, "icsp: error in the association\n");
            return 1;
        }
        if (r == ICSP_POLL_TIMEOUT) {
            int rt = icsp_data_retransmit(a, 1);
            if (rt > 0)
                printf("icsp: retransmitted DATA (%d)\n", rt);
        }
        if (rekey_s == 0 && icsp_all_acked(a))
            break;
    }
    printf("icsp: sack=%d\n", icsp_all_acked(a));

    /* graceful close */
    icsp_shutdown_send(a);
    printf("icsp: SHUTDOWN sent\n");
    return 0;
}

/* server: handshake + log data, accept the next association */
static int run_server(int argc, char **argv, struct icsp_assoc *a,
                      uint8_t sk[64])
{
    uint8_t peers[64][32];
    int n_peers = 0;
    int loss_pct = 0;
    uint16_t port = 6969;

    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--loss") && i + 1 < argc)
            loss_pct = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--peer") && i + 1 < argc) {
            if (hex_decode(argv[++i], peers[n_peers], 32) != 32) {
                fprintf(stderr, "icsp: invalid --peer\n");
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
    printf("icsp: server on port %u (peers=%d, loss=%d%%)\n",
           port, n_peers, loss_pct);

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
    printf("icsp: server listening (ctrl-C to quit)\n");

    /* serve this association, then accept the next one */
    time_t last_ann = 0;
    for (;;) {
        if (a->tunnel && time(NULL) - last_ann >= 2) {
            server_announce(a, sk);
            last_ann = time(NULL);
        }
        int r = icsp_poll(a, 200, server_on_data, NULL);
        if (r == ICSP_POLL_ERR) {
            perror("icsp: poll");
            return 1;
        }
        if (r == ICSP_POLL_CLOSED) {
            printf("icsp: SHUTDOWN received — association closed, "
                   "waiting for the next one...\n");
            if (icsp_server_accept(a, port, sk, peers, n_peers, 30) < 0)
                return 1;
            a->sack_loss_pct = loss_pct;
            printf("icsp: new association accepted — session_key == "
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
        fprintf(stderr, "icsp: requires <server|client> <ifname> [args]\n");
        return 1;
    }
    const char *remote = NULL;
    for (int i = 3; i < argc; i++)
        if (!strcmp(argv[i], "--remote") && i + 1 < argc)
            remote = argv[++i];
    if (remote) {
        /* tunnel mode: ICSP over the gateway (--remote gw:port) */
        if (icsp_endpoint_open_remote(&a, remote, sk) < 0) {
            fprintf(stderr, "icsp: invalid --remote (%s)\n", remote);
            return 1;
        }
    } else if (icsp_endpoint_open(&a, argv[2], sk) < 0) {
        fprintf(stderr, "icsp: no identity (create one with ipv69 keygen)\n");
        return 1;
    }

    if (!strcmp(argv[1], "server"))
        return run_server(argc, argv, &a, sk);
    if (!strcmp(argv[1], "client"))
        return run_client(argc, argv, &a, sk);

    fprintf(stderr, "icsp: unknown mode '%s' (server|client)\n", argv[1]);
    return 1;
}
