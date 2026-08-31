/* icsp_test.c - ICSP Phase 1 test: authenticated handshake.
 *
 *   ipv69 icsp server <ifname> [port]        # listens, accepts one assoc
 *   ipv69 icsp client <ifname> <dst> <port>  # connects (dst:40-bit addr)
 *
 * Runs over AF_PACKET (veth pair in tests). Identity = auto-key
 * (~/.hosts69/key, same as DHCP). Prints the session key on both
 * sides — acceptance: identical key + established state.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

int cmd_icsp(int argc, char **argv)
{
    uint8_t sk[64], pub[32], src_mac[6];
    struct icsp_assoc a;
    uint8_t peers[64][32];
    int n_peers = 0;
    int ifindex;
    int fd;

    setvbuf(stdout, NULL, _IOLBF, 0);   /* live logs (daemon/test) */

    if (argc < 3) {
        fprintf(stderr, "icsp: precisa <server|client> <ifname> [dst] [port] "
                "[--peer HEX] [--peer-file F]\n");
        return 1;
    }
    /* allowlist options (server) */
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--peer") && i + 1 < argc) {
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
        }
    }
    if (load_identity(sk, pub) < 0) {
        fprintf(stderr, "icsp: sem identidade (crie com ipv69 keygen)\n");
        return 1;
    }
    fd = raw_socket(argv[2], &ifindex, src_mac);
    if (fd < 0) {
        perror("icsp: raw_socket");
        return 1;
    }

    if (!strcmp(argv[1], "server")) {
        uint16_t port = argc > 3 && argv[3][0] != '-' ?
                        (uint16_t)atoi(argv[3]) : 6969;
        printf("icsp: servidor em %s, porta %u (identidade %02x%02x.., "
               "peers=%d)\n", argv[2], port, pub[0], pub[1], n_peers);
        if (icsp_server_accept(fd, ifindex, src_mac, 0, port, sk,
                               peers, n_peers, &a) < 0)
            return 1;
        printf("icsp: session_key == %02x%02x..%02x%02x\n",
               a.session_key[0], a.session_key[1],
               a.session_key[30], a.session_key[31]);
        return a.state == ICSP_ST_ESTABLISHED ? 0 : 1;
    }

    if (!strcmp(argv[1], "client")) {
        uint64_t dst;
        uint16_t port;
        if (argc < 5 || parse_ipv69_addr(argv[3], &dst) < 0) {
            fprintf(stderr, "icsp: client precisa <dst> <port>\n");
            return 1;
        }
        port = (uint16_t)atoi(argv[4]);
        printf("icsp: cliente -> %016llx:%u (identidade %02x%02x..)\n",
               (unsigned long long)dst, port, pub[0], pub[1]);
        if (icsp_client_handshake(fd, ifindex, src_mac, dst,
                                  40000 + (uint16_t)getpid() % 1000,
                                  port, sk, &a) < 0)
            return 1;
        printf("icsp: session_key == %02x%02x..%02x%02x\n",
               a.session_key[0], a.session_key[1],
               a.session_key[30], a.session_key[31]);
        return a.state == ICSP_ST_ESTABLISHED ? 0 : 1;
    }

    fprintf(stderr, "icsp: modo desconhecido '%s' (server|client)\n", argv[1]);
    return 1;
}
