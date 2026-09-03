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
 *   ./icsp_chat server [ifname] [port|:port] [--peer HEX]
 *   ./icsp_chat client [ifname] <dst:port> [--peer HEX]
 *
 * The ifname is optional: omit it (or write 'auto') to use the
 * default-route interface — the one that reaches the internet.
 * In tunnel mode (--remote or a ~/.hosts69/gateways file) the ifname
 * is ignored anyway.
 *
 * stdin = send (stream 1), socket = receive. Ctrl-D ends the chat
 * with a graceful SHUTDOWN. The session key (printed on both sides)
 * proves the authenticated ECDH handshake.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "IPv69/plat.h"
#include "IPv69/l2.h"
#include "IPv69/gwfile.h"
#include "IPv69/parse.h"
#include "ICSP/icsp.h"

static void chat_usage(void)
{
    fprintf(stderr,
        "icsp_chat - example chat built on the ICSP API\n"
        "\n"
        "      Usage: icsp_chat <server|client> [ifname] [port|:port] "
            "[--peer HEX] [--remote gw:port]\n"
            "       icsp_chat client [ifname] <dst:port> [--peer HEX]\n"
            "                              [--remote gw:port]\n"
            "\n"
            "  server  wait for a connection (persistent; replies unicast to\n"
            "          the peer MAC, so it works across Wi-Fi APs)\n"
            "  client  connect to <dst:port> (address-less port form ok)\n"
            "\n"
            "The ifname is OPTIONAL: omit it (or write 'auto') to use the\n"
            "default-route interface. In tunnel mode (--remote or a\n"
            "~/.hosts69/gateways file) the ifname is ignored anyway.\n"
            "\n"
            "Options:\n"
            "  --peer HEX   allowlist: accept only this identity (repeatable)\n"
            "  --remote gw  tunnel through this gateway (overrides the\n"
            "               ~/.hosts69/gateways file; host or IP:port, the\n"
            "               built-in DNS resolves domains; default port 6969)\n"
            "\n"
            "Identity: ~/.hosts69 keyring (ipv69 keygen). Both sides print\n"
            "the session key — identical = authenticated ECDH handshake.\n"
            "Ctrl-D closes gracefully (SHUTDOWN).\n");
}

/* incoming DATA: print it */
static void on_data(struct icsp_assoc *a, uint16_t stream,
                    const uint8_t *data, size_t len, void *ud)
{
    (void)a; (void)stream; (void)ud;
    fwrite(data, 1, len, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

/* the whole chat: relay stdin <-> stream 1 until close/dead/EOF */
static int chat_run(struct icsp_assoc *a)
{
    printf("chat: connected! type and press Enter to send (Ctrl-D closes)\n");
    fflush(stdout);
    int r = icsp_relay(a, 1, 1, on_data, NULL);
    if (r == ICSP_POLL_DEAD)
        printf("chat: no response from the peer for %ds — shutting down\n",
               a->dead_timeout_s);
    else if (r == ICSP_POLL_CLOSED)
        printf("chat: the other side closed\n");
    else if (r == ICSP_POLL_ERR)
        return 1;
    icsp_shutdown_send(a);
    printf("chat: closed\n");
    return 0;
}

int main(int argc, char **argv)
{
    uint8_t sk[64];
    uint8_t peers[64][32];
    int n_peers = 0;
    struct icsp_assoc a;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (plat_sock_init() < 0) {
        fprintf(stderr, "chat: winsock init failed\n");
        return 1;
    }

    if (argc < 3) {
        chat_usage();
        return 1;
    }
    /* ifname omitted (`client <dst:port>` / `server :port`): insert
       "auto" so the endpoint resolves the default-route iface */
    if (argc < 30 && parse_looks_like_addr(argv[2])) {
        char *na[32];
        int nargc = parse_insert_auto_ifname(argc, argv, na);
        return main(nargc, na);         /* re-dispatch normalized */
    }
    const char *remote = NULL;
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            chat_usage();
            return 0;
        }
        if (!strcmp(argv[i], "--remote") && i + 1 < argc) {
            remote = argv[++i];
            continue;
        }
        if (!strcmp(argv[i], "--peer") && i + 1 < argc) {
            if (hex_decode(argv[++i], peers[n_peers], 32) != 32) {
                fprintf(stderr, "chat: invalid --peer\n");
                return 1;
            }
            n_peers++;
        }
    }
    /* endpoint: --remote wins; otherwise the ~/.hosts69/gateways file
       (any gateway = tunnel); without either, plain local L2. */
    int n_gw = 0;
    struct sockaddr_storage gws[GWFILE_MAX];
    socklen_t gwlen[GWFILE_MAX];
    if (!remote)
        n_gw = gwfile_load(gws, gwlen, GWFILE_MAX);
    if (remote) {
        if (icsp_endpoint_open_remote(&a, remote, sk) < 0) {
            fprintf(stderr, "chat: invalid --remote (%s)\n", remote);
            return 1;
        }
        printf("chat: tunnel via --remote %s\n", remote);
    } else if (n_gw > 0) {
        if (icsp_endpoint_open_gw(&a, &gws[0], gwlen[0], sk) < 0) {
            fprintf(stderr, "chat: cannot open the gateway tunnel\n");
            return 1;
        }
        printf("chat: tunnel via ~/.hosts69/gateways (%d gateway(s))\n",
               n_gw);
    } else if (icsp_endpoint_open(&a, argv[2], sk) < 0) {
        fprintf(stderr, "chat: no identity (ipv69 keygen)\n");
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
        /* also accept `:port` (address-less form) */
        for (int i = 3; i < argc; i++)
            if (argv[i][0] == ':' && argv[i][1]) {
                port = (uint16_t)atoi(argv[i] + 1);
                break;
            }
        printf("chat: server on %s:%u (peers=%d)\n", argv[2], port,
               n_peers);
        /* tunnel server: keep our route alive at the gateway (the
           accept wait + session re-announce every announce_s) */
        if (a.tunnel) {
            a.announce_s = 2;
            icsp_announce_send(&a);
        }
        /* serve associations forever: accept, chat, then accept again */
        for (;;) {
            if (icsp_server_accept(&a, port, sk, peers, n_peers, 0) < 0)
                return 1;
            a.hb_interval_s = 6;
            a.dead_timeout_s = 18;
            printf("chat: session_key == %02x%02x..%02x%02x\n",
                   a.send_key[0], a.send_key[1],
                   a.send_key[30], a.send_key[31]);
            chat_run(&a);
            printf("chat: waiting for the next association...\n");
        }
    }

    if (!strcmp(argv[1], "client")) {
        uint64_t dst;
        uint16_t port;
        if (argc < 4 || parse_ipv69_addr_port(argv[3], &dst, &port) < 0) {
            fprintf(stderr, "chat client: requires <dst:port>\n");
            return 1;
        }
        printf("chat: client -> %016llx:%u\n",
               (unsigned long long)dst, port);
        if (icsp_client_handshake(&a, dst, port, sk, NULL) < 0)
            return 1;
        a.hb_interval_s = 6;
        a.dead_timeout_s = 18;
        printf("chat: session_key == %02x%02x..%02x%02x\n",
               a.send_key[0], a.send_key[1],
               a.send_key[30], a.send_key[31]);
        return chat_run(&a);
    }

    fprintf(stderr, "chat: unknown mode '%s'\n", argv[1]);
    return 1;
}
