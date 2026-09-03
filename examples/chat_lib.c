/* chat_lib.c - minimal chat built ONLY on libipv69.a (no ipv69 binary,
 * no source-list linking). The point: a developer links the library and
 * gets identity + L2/tunnel + ICSP session in a few calls.
 *
 * Build:  make lib && make libdemo
 *         (libdemo: cc examples/chat_lib.c build/libipv69.a -Iinclude
 *                   -Ilib/ed25519/include)
 *
 * Usage:
 *   ./chat_lib server :6969              # tunnel if ~/.hosts69/gateways
 *   ./chat_lib client <addr>:6969        # or addr:port
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ipv69.h"

static void on_msg(struct icsp_assoc *a, uint16_t stream,
                   const uint8_t *data, size_t len, void *ud)
{
    (void)a; (void)stream; (void)ud;
    fwrite(data, 1, len, stdout);
    fputc('\n', stdout);
}

static int open_endpoint(struct icsp_assoc *a, uint8_t sk[64])
{
    struct sockaddr_storage gws[GWFILE_MAX];
    socklen_t gwlen[GWFILE_MAX];
    int n = gwfile_load(gws, gwlen, GWFILE_MAX);
    if (n > 0) {
        if (icsp_endpoint_open_gw(a, &gws[0], gwlen[0], sk) < 0) {
            fprintf(stderr, "chat: cannot open the gateway tunnel\n");
            return -1;
        }
        printf("chat: tunnel via ~/.hosts69/gateways (%d gateway(s))\n", n);
        return 0;
    }
    if (icsp_endpoint_open(a, "auto", sk) < 0) {
        fprintf(stderr, "chat: no identity (ipv69 keygen)\n");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct icsp_assoc a;
    uint8_t sk[64];
    plat_sock_init();

    if (argc >= 2 && !strcmp(argv[1], "server")) {
        uint16_t port = 6969;
        if (argc >= 3 && argv[2][0] == ':' && argv[2][1])
            port = (uint16_t)atoi(argv[2] + 1);
        if (open_endpoint(&a, sk) < 0)
            return 1;
        if (a.tunnel) {
            a.announce_s = 2;
            icsp_announce_send(&a);
        }
        printf("chat: server on :%u\n", port);
        for (;;) {
            if (icsp_server_accept(&a, port, sk, NULL, 0, 0) < 0)
                return 1;
            a.hb_interval_s = 6;
            a.dead_timeout_s = 18;
            printf("chat: session_key == %02x%02x..%02x%02x\n",
                   a.send_key[0], a.send_key[1],
                   a.send_key[30], a.send_key[31]);
            icsp_relay(&a, 1, 1, on_msg, NULL);   /* until close/dead */
            printf("chat: waiting for the next association...\n");
        }
    }
    if (argc >= 3 && !strcmp(argv[1], "client")) {
        uint64_t dst;
        uint16_t port;
        if (parse_ipv69_addr_port(argv[2], &dst, &port) < 0) {
            fprintf(stderr, "chat client: requires <dst:port>\n");
            return 1;
        }
        if (open_endpoint(&a, sk) < 0)
            return 1;
        if (icsp_client_handshake(&a, dst, port, sk, NULL) < 0)
            return 1;
        a.hb_interval_s = 6;
        a.dead_timeout_s = 18;
        printf("chat: session_key == %02x%02x..%02x%02x\n",
               a.send_key[0], a.send_key[1],
               a.send_key[30], a.send_key[31]);
        return icsp_relay(&a, 1, 1, on_msg, NULL) < 0 ? 1 : 0;
    }
    fprintf(stderr, "usage: %s <server :port|client <addr:port>>\n", argv[0]);
    return 1;
}
