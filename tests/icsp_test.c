/* icsp_test.c - ICSP test: handshake + data + lifecycle.
 *
 *   ipv69 icsp server <ifname> [port] [--peer HEX] [--peer-file F] [--echo]
 *   ipv69 icsp client <ifname> <dst> <port> [msg] [--echo] [--reset] [--hb]
 *
 * Handshake (Phase 1), then optionally exchanges data (Phase 2):
 *   server --echo answers back on the same stream;
 *   client sends the msg (or "hello icsp") and, with --echo, waits for
 *   the echo. --reset tests STREAM-RESET; --hb sends a heartbeat.
 * Identity = the ~/.hosts69 keyring (same as DHCP).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include "IPv69/header.h"
#include "IPv69/parse.h"
#include "IPv69/l2.h"
#include "IPv69/keyring.h"
#include "ed25519.h"
#include "ICSP/icsp.h"

static int load_identity(uint8_t sk[64], uint8_t pub[32])
{
    char key[512], kpub[512], dir[256], comment[128];
    keyring_paths(dir, sizeof(dir), key, sizeof(key), kpub, sizeof(kpub));
    return keyring_load_or_create(key, kpub, sk, pub, comment,
                                  sizeof(comment));
}

static int open_raw(const char *ifname, int *ifindex, uint8_t src_mac[6])
{
    int fd = raw_socket(ifname, ifindex, src_mac);
    if (fd < 0)
        perror("icsp: raw_socket");
    return fd;
}

/* client: handshake + optional data exchange */
static int run_client(int argc, char **argv, uint8_t sk[64],
                      uint8_t src_mac[6], int fd, int ifindex)
{
    uint64_t dst;
    uint16_t port;
    const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    struct icsp_assoc a;
    uint8_t buf[ICSP_MAX_PAYLOAD];
    struct timeval tv = { 1, 0 };
    int echo_mode = 0, hb_mode = 0, reset_mode = 0;
    const char *msg = "hello icsp";

    for (int i = 5; i < argc; i++) {
        if (!strcmp(argv[i], "--echo")) echo_mode = 1;
        else if (!strcmp(argv[i], "--hb")) hb_mode = 1;
        else if (!strcmp(argv[i], "--reset")) reset_mode = 1;
        else msg = argv[i];
    }
    if (argc < 5 || parse_ipv69_addr(argv[3], &dst) < 0) {
        fprintf(stderr, "icsp client: precisa <dst> <port> [msg] [--echo|--hb|--reset]\n");
        return 1;
    }
    port = (uint16_t)atoi(argv[4]);
    printf("icsp: cliente -> %016llx:%u\n", (unsigned long long)dst, port);

    if (icsp_client_handshake(fd, ifindex, src_mac, dst,
                              40000 + (uint16_t)getpid() % 1000,
                              port, sk, &a) < 0)
        return 1;
    printf("icsp: session_key == %02x%02x..%02x%02x\n",
           a.session_key[0], a.session_key[1],
           a.session_key[30], a.session_key[31]);

    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (hb_mode) {
        printf("icsp: HEARTBEAT ->\n");
        if (icsp_heartbeat_send(&a, fd, ifindex, src_mac, bcast, dst,
                                0) < 0)
            return 1;
    }
    if (reset_mode) {
        printf("icsp: STREAM-RESET stream 3 ->\n");
        icsp_stream_reset(&a, fd, ifindex, src_mac, bcast, dst, 0, 3, 0);
    }

    /* send the message on stream 1 (and a second on stream 2) */
    int tsn = icsp_data_send(&a, fd, ifindex, src_mac, bcast, dst, 0,
                             1, (const uint8_t *)msg, strlen(msg));
    if (tsn < 0) {
        fprintf(stderr, "icsp: data_send falhou\n");
        return 1;
    }
    printf("icsp: DATA enviado (tsn=%d, stream 1)\n", tsn);
    icsp_data_send(&a, fd, ifindex, src_mac, bcast, dst, 0,
                   2, (const uint8_t *)"msg na stream 2", 17);

    /* wait for SACK (and echo when --echo) */
    time_t deadline = time(NULL) + 3;
    int got_sack = 0, got_echo = 0;
    while (time(NULL) < deadline) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* retransmit unacked after 1s */
                int r = icsp_data_retransmit(&a, fd, ifindex, src_mac, bcast,
                                             dst, 0, 1);
                if (r > 0)
                    printf("icsp: retransmitiu DATA (%d)\n", r);
                continue;
            }
            perror("icsp: recv");
            break;
        }
        if (n < 14 + IPV69_HEADER_LEN + ICSP_HEADER_LEN)
            continue;
        const struct ipv69_header *h =
            (const struct ipv69_header *)(buf + 14);
        if (h->next_header != IPV69_NEXT_STREAM)
            continue;
        const uint8_t *payload = buf + 14 + IPV69_HEADER_LEN;
        if (payload[ICSP_HEADER_LEN] == ICSP_CHUNK_SACK)
            got_sack = 1;
        size_t olen = sizeof(buf);
        uint16_t ostream;
        int m = icsp_data_handle(&a, payload, (size_t)(n - 14 - IPV69_HEADER_LEN),
                                 buf, &olen, &ostream);
        if (m > 0) {
            printf("icsp: recebido %d bytes (stream %u): \"%.*s\"\n",
                   m, ostream, m, (char *)buf);
            if (echo_mode) got_echo = 1;
        }
        if (icsp_life_handle(&a, payload, (size_t)(n - 14 - IPV69_HEADER_LEN)))
            break;
    }
    printf("icsp: sack=%d echo=%d\n", got_sack, got_echo);

    /* graceful close */
    icsp_shutdown_send(&a, fd, ifindex, src_mac, bcast, dst, 0);
    printf("icsp: SHUTDOWN enviado\n");
    return 0;
}

/* server: handshake + echo data when --echo */
static int run_server(int argc, char **argv, uint8_t sk[64],
                      uint8_t src_mac[6], int fd, int ifindex)
{
    uint8_t peers[64][32];
    int n_peers = 0;
    struct icsp_assoc a;
    const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t buf[ICSP_MAX_PAYLOAD];
    struct timeval tv = { 2, 0 };
    int echo_mode = 0, loss_pct = 0;
    uint16_t port = 6969;

    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--echo")) echo_mode = 1;
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
        } else if (argv[i][0] != '-') {
            port = (uint16_t)atoi(argv[i]);
        }
    }
    printf("icsp: servidor em porta %u (peers=%d, echo=%d, loss=%d%%)\n",
           port, n_peers, echo_mode, loss_pct);

    if (icsp_server_accept(fd, ifindex, src_mac, 0, port, sk,
                           peers, n_peers, &a) < 0)
        return 1;
    printf("icsp: session_key == %02x%02x..%02x%02x\n",
           a.session_key[0], a.session_key[1],
           a.session_key[30], a.session_key[31]);

    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    printf("icsp: servidor escutando (ctrl-C para sair)\n");

    /* serve this association, then accept the next one */
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            perror("icsp: recv");
            return 1;
        }
        if (n < 14 + IPV69_HEADER_LEN + ICSP_HEADER_LEN)
            continue;
        const struct ipv69_header *h =
            (const struct ipv69_header *)(buf + 14);
        if (h->next_header != IPV69_NEXT_STREAM)
            continue;
        const uint8_t *payload = buf + 14 + IPV69_HEADER_LEN;
        uint8_t ctype = payload[ICSP_HEADER_LEN];

        if (ctype == ICSP_CHUNK_HEARTBEAT) {
            printf("icsp: HEARTBEAT -> ACK\n");
            icsp_heartbeat_ack(&a, fd, ifindex, src_mac, bcast, 0, 0);
            continue;
        }
        size_t olen = sizeof(buf);
        uint16_t ostream = 0;
        int m = icsp_data_handle(&a, payload,
                                 (size_t)(n - 14 - IPV69_HEADER_LEN),
                                 buf, &olen, &ostream);
        if (m > 0) {
            printf("icsp: recebido %d bytes (stream %u): \"%.*s\"\n",
                   m, ostream, m, (char *)buf);
            /* synthetic loss: --loss N% of DATA packets get no SACK */
            if (loss_pct > 0 && rand() % 100 < loss_pct) {
                printf("icsp: perda sintetica (%d%%) - sem SACK\n", loss_pct);
                continue;
            }
            icsp_sack_send(&a, fd, ifindex, src_mac, bcast, 0, 0);
            if (echo_mode)
                icsp_data_send(&a, fd, ifindex, src_mac, bcast, 0, 0,
                               ostream, buf, (size_t)m);
        }
        if (icsp_life_handle(&a, payload,
                             (size_t)(n - 14 - IPV69_HEADER_LEN))) {
            printf("icsp: SHUTDOWN recebido — associação fechada, "
                   "aguardando proxima...\n");
            /* accept a fresh association on the same port */
            if (icsp_server_accept(fd, ifindex, src_mac, 0, port, sk,
                                   peers, n_peers, &a) < 0)
                return 1;
            printf("icsp: nova associação aceita — session_key == "
                   "%02x%02x..%02x%02x\n",
                   a.session_key[0], a.session_key[1],
                   a.session_key[30], a.session_key[31]);
            continue;
        }
    }
}

int cmd_icsp(int argc, char **argv)
{
    uint8_t sk[64], pub[32], src_mac[6];
    int ifindex;
    int fd;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc < 3) {
        fprintf(stderr, "icsp: precisa <server|client> <ifname> [args]\n");
        return 1;
    }
    if (load_identity(sk, pub) < 0) {
        fprintf(stderr, "icsp: sem identidade (crie com ipv69 keygen)\n");
        return 1;
    }
    fd = open_raw(argv[2], &ifindex, src_mac);
    if (fd < 0)
        return 1;

    if (!strcmp(argv[1], "server"))
        return run_server(argc, argv, sk, src_mac, fd, ifindex);
    if (!strcmp(argv[1], "client"))
        return run_client(argc, argv, sk, src_mac, fd, ifindex);

    fprintf(stderr, "icsp: modo desconhecido '%s' (server|client)\n", argv[1]);
    return 1;
}
