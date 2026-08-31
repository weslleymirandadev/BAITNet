/* icsp_chat.c - example tool built on the ICSP API.
 *
 * A real terminal chat over ICSP: two hosts exchange messages over the
 * encrypted association (session key from the authenticated handshake).
 * Demonstrates the full ICSP API in a usable tool:
 *
 *   ipv69 chat server <ifname> [port] [--peer HEX]
 *   ipv69 chat client <ifname> <dst> <port>
 *
 * stdin = send (stream 1), socket = receive. Ctrl-D ends the chat
 * (graceful SHUTDOWN).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
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

/* one chat loop: stdin -> send(stream 1); socket -> recv + print.
 * use_stdin=0 (server): the socket is the only input — stdin may be
 * EOF (daemonized) and must not close the chat. */
static int chat_loop(struct icsp_assoc *a, int fd, int ifindex,
                     const uint8_t src_mac[6], const uint8_t *dst_mac,
                     uint64_t dst_addr, int echo_mode, int use_stdin)
{
    const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t buf[ICSP_MAX_PAYLOAD];
    char line[ICSP_MAX_PAYLOAD];
    int last_heartbeat = 0;

    if (!dst_mac)
        dst_mac = bcast;

    printf("chat: conectado! digite mensagens (Ctrl-D sai)\n");
    fflush(stdout);

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        if (use_stdin)
            FD_SET(0, &rfds);       /* stdin */
        FD_SET(fd, &rfds);          /* the L2 socket */
        struct timeval tv = { 2, 0 };

        int r = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            perror("chat: select");
            return 1;
        }

        /* heartbeat every ~6s so a dead peer is detected */
        if (r == 0 && time(NULL) - last_heartbeat >= 6) {
            icsp_heartbeat_send(a, fd, ifindex, src_mac, dst_mac,
                                dst_addr, 0);
            last_heartbeat = (int)time(NULL);
            continue;
        }

        if (use_stdin && FD_ISSET(0, &rfds)) {
            if (!fgets(line, sizeof(line), stdin))
                break;              /* Ctrl-D: graceful close */
            size_t n = strlen(line);
            while (n && (line[n - 1] == '\n' || line[n - 1] == '\r'))
                line[--n] = 0;
            if (!n)
                continue;
            if (icsp_data_send(a, fd, ifindex, src_mac, dst_mac,
                               dst_addr, 0, 1,
                               (const uint8_t *)line, n) < 0) {
                fprintf(stderr, "chat: falha ao enviar\n");
                return 1;
            }
            printf("voce: %s\n", line);
        }

        if (FD_ISSET(fd, &rfds)) {
            ssize_t n = recv(fd, buf, sizeof(buf), 0);
            if (n < 0)
                continue;
            if (n < 14 + IPV69_HEADER_LEN + ICSP_HEADER_LEN)
                continue;
            const struct ipv69_header *h =
                (const struct ipv69_header *)(buf + 14);
            if (h->next_header != IPV69_NEXT_STREAM)
                continue;
            const uint8_t *payload = buf + 14 + IPV69_HEADER_LEN;
            uint8_t ctype = payload[ICSP_HEADER_LEN];

            if (ctype == ICSP_CHUNK_HEARTBEAT) {
                icsp_heartbeat_ack(a, fd, ifindex, src_mac, dst_mac,
                                   dst_addr, 0);
                continue;
            }
            size_t olen = sizeof(buf);
            uint16_t ostream;
            int m = icsp_data_handle(a, payload,
                                     (size_t)(n - 14 - IPV69_HEADER_LEN),
                                     buf, &olen, &ostream);
            if (m > 0) {
                printf("eles (%u): %.*s\n", ostream, m, (char *)buf);
                if (echo_mode)
                    icsp_data_send(a, fd, ifindex, src_mac, dst_mac,
                                   dst_addr, 0, ostream, buf, (size_t)m);
            }
            if (icsp_life_handle(a, payload,
                                 (size_t)(n - 14 - IPV69_HEADER_LEN))) {
                printf("chat: o outro lado fechou\n");
                break;
            }
        }
    }
    icsp_shutdown_send(a, fd, ifindex, src_mac, dst_mac, dst_addr, 0);
    printf("chat: encerrado\n");
    return 0;
}

int cmd_chat(int argc, char **argv)
{
    uint8_t sk[64], pub[32], src_mac[6];
    uint8_t peers[64][32];
    int n_peers = 0, echo_mode = 0;
    struct icsp_assoc a;
    int ifindex, fd;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc < 3) {
        fprintf(stderr, "chat: precisa <server|client> <ifname> [dst] [port] "
                "[--peer HEX] [--echo]\n");
        return 1;
    }
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--peer") && i + 1 < argc) {
            if (hex_decode(argv[++i], peers[n_peers], 32) != 32) {
                fprintf(stderr, "chat: --peer invalido\n");
                return 1;
            }
            n_peers++;
        } else if (!strcmp(argv[i], "--echo")) {
            echo_mode = 1;
        }
    }
    if (load_identity(sk, pub) < 0) {
        fprintf(stderr, "chat: sem identidade (ipv69 keygen)\n");
        return 1;
    }
    fd = raw_socket(argv[2], &ifindex, src_mac);
    if (fd < 0) {
        perror("chat: raw_socket");
        return 1;
    }

    if (!strcmp(argv[1], "server")) {
        uint16_t port = 6969;
        for (int i = 3; i < argc; i++)
            if (argv[i][0] != '-') {
                port = (uint16_t)atoi(argv[i]);
                break;
            }
        printf("chat: servidor em %s:%u (peers=%d)\n", argv[2], port, n_peers);
        if (icsp_server_accept(fd, ifindex, src_mac, 0, port, sk,
                               peers, n_peers, &a) < 0)
            return 1;
        printf("chat: session_key == %02x%02x..%02x%02x\n",
               a.session_key[0], a.session_key[1],
               a.session_key[30], a.session_key[31]);
        return chat_loop(&a, fd, ifindex, src_mac, NULL, 0, echo_mode, 0);
    }

    if (!strcmp(argv[1], "client")) {
        uint64_t dst;
        uint16_t port;
        if (argc < 5 || parse_ipv69_addr(argv[3], &dst) < 0) {
            fprintf(stderr, "chat client: precisa <dst> <port>\n");
            return 1;
        }
        port = (uint16_t)atoi(argv[4]);
        printf("chat: cliente -> %016llx:%u\n", (unsigned long long)dst, port);
        if (icsp_client_handshake(fd, ifindex, src_mac, dst,
                                  50000 + (uint16_t)getpid() % 1000,
                                  port, sk, &a) < 0)
            return 1;
        printf("chat: session_key == %02x%02x..%02x%02x\n",
               a.session_key[0], a.session_key[1],
               a.session_key[30], a.session_key[31]);
        return chat_loop(&a, fd, ifindex, src_mac, NULL, dst, 0, 1);
    }

    fprintf(stderr, "chat: modo desconhecido '%s'\n", argv[1]);
    return 1;
}
