/* icsp_chat.c - EXAMPLE: a terminal chat built on the ICSP session layer.
 *
 * This is NOT part of the ipv69 binary — it is a standalone example
 * showing how little code a tool needs on top of ICSP: open the
 * endpoint, handshake, then icsp_relay() — the netcat primitive that
 * multiplexes stdin + the socket internally (poll), forwards stdin
 * lines to stream 1, prints incoming DATA via a callback, and runs
 * heartbeat + dead-peer detection on its own.
 *
 * Usage:
 *   ./icsp_chat server <ifname> [port|:port] [--peer HEX] [--echo]
 *   ./icsp_chat client <ifname> <dst:porta> [--peer HEX] [--echo]
 *
 * stdin = send (stream 1), socket = receive. Ctrl-D ends the chat
 * with a graceful SHUTDOWN. The session key (printed on both sides)
 * proves the authenticated ECDH handshake.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "IPv69/parse.h"
#include "IPv69/l2.h"
#include "ICSP/icsp.h"

static void chat_usage(void)
{
    fprintf(stderr,
        "icsp_chat - example chat built on the ICSP API\n"
        "\n"
        "Usage: icsp_chat <server|client> <ifname> [port|:port] "
        "[--peer HEX] [--echo]\n"
        "       icsp_chat client <ifname> <dst:porta> [--peer HEX] [--echo]\n"
        "\n"
        "  server  wait for a connection (persistent; replies unicast to\n"
        "          the peer MAC, so it works across Wi-Fi APs)\n"
        "  client  connect to <dst:porta> (address-less port form ok)\n"
        "\n"
        "Options:\n"
        "  --peer HEX   allowlist: accept only this identity (repeatable)\n"
        "  --echo       echo received messages back (test mode)\n"
        "\n"
        "Identity: ~/.hosts69 keyring (ipv69 keygen). Both sides print\n"
        "the session key — identical = authenticated ECDH handshake.\n"
        "Ctrl-D closes gracefully (SHUTDOWN).\n");
}

/* incoming DATA: print, and echo back when --echo */
static void on_data(struct icsp_assoc *a, uint16_t stream,
                    const uint8_t *data, size_t len, void *ud)
{
    int echo_mode = *(int *)ud;
    fwrite(data, 1, len, stdout);
    fputc('\n', stdout);
    fflush(stdout);
    if (echo_mode)
        icsp_data_send(a, stream, data, len);
}

/* the whole chat: relay stdin <-> stream 1 until close/dead/EOF */
static int chat_run(struct icsp_assoc *a, int echo_mode)
{
    printf("chat: conectado! digite e Enter envia (Ctrl-D fecha)\n");
    fflush(stdout);
    int r = icsp_relay(a, 1, 1, on_data, &echo_mode);
    if (r == ICSP_POLL_DEAD)
        printf("chat: sem resposta do peer ha %ds — encerrando\n",
               a->dead_timeout_s);
    else if (r == ICSP_POLL_CLOSED)
        printf("chat: o outro lado fechou\n");
    else if (r == ICSP_POLL_ERR)
        return 1;
    icsp_shutdown_send(a);
    printf("chat: encerrado\n");
    return 0;
}

int main(int argc, char **argv)
{
    uint8_t sk[64];
    uint8_t peers[64][32];
    int n_peers = 0, echo_mode = 0;
    struct icsp_assoc a;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc < 3) {
        chat_usage();
        return 1;
    }
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            chat_usage();
            return 0;
        }
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
    if (icsp_endpoint_open(&a, argv[2], sk) < 0) {
        fprintf(stderr, "chat: sem identidade (ipv69 keygen)\n");
        return 1;
    }

    if (!strcmp(argv[1], "server")) {
        uint16_t port = 6969;
        for (int i = 3; i < argc; i++) {
            if (argv[i][0] == '-' || strchr(argv[i], ':'))
                continue;
            port = (uint16_t)atoi(argv[i]);
            break;
        }
        /* also accept `:porta` (address-less form) */
        for (int i = 3; i < argc; i++)
            if (argv[i][0] == ':' && argv[i][1]) {
                port = (uint16_t)atoi(argv[i] + 1);
                break;
            }
        printf("chat: servidor em %s:%u (peers=%d)\n", argv[2], port,
               n_peers);
        /* serve associations forever: accept, chat, then accept again */
        for (;;) {
            if (icsp_server_accept(&a, port, sk, peers, n_peers, 0) < 0)
                return 1;
            a.hb_interval_s = 6;
            a.dead_timeout_s = 18;
            printf("chat: session_key == %02x%02x..%02x%02x\n",
                   a.session_key[0], a.session_key[1],
                   a.session_key[30], a.session_key[31]);
            chat_run(&a, echo_mode);
            printf("chat: aguardando proxima associacao...\n");
        }
    }

    if (!strcmp(argv[1], "client")) {
        uint64_t dst;
        uint16_t port;
        if (argc < 4 || parse_ipv69_addr_port(argv[3], &dst, &port) < 0) {
            fprintf(stderr, "chat client: precisa <dst:porta>\n");
            return 1;
        }
        printf("chat: cliente -> %016llx:%u\n",
               (unsigned long long)dst, port);
        if (icsp_client_handshake(&a, dst, port, sk) < 0)
            return 1;
        a.hb_interval_s = 6;
        a.dead_timeout_s = 18;
        printf("chat: session_key == %02x%02x..%02x%02x\n",
               a.session_key[0], a.session_key[1],
               a.session_key[30], a.session_key[31]);
        return chat_run(&a, echo_mode);
    }

    fprintf(stderr, "chat: modo desconhecido '%s'\n", argv[1]);
    return 1;
}
