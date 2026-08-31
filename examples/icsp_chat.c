/* icsp_chat.c - EXAMPLE: a terminal chat built on the ICSP API.
 *
 * This is NOT part of the ipv69 binary — it is a standalone example
 * showing how to build a tool on top of the ICSP stream transport.
 * It links only the ICSP core + keyring + ed25519 (see Makefile
 * target `chat`); the L2 helpers are duplicated here on purpose so
 * the example is self-contained and readable.
 *
 * Usage:
 *   ./icsp_chat server <ifname> [port] [--peer HEX] [--echo]
 *   ./icsp_chat client <ifname> <dst> <port>
 *
 * stdin = send (stream 1), socket = receive. Ctrl-D ends the chat
 * with a graceful SHUTDOWN. The session key (printed on both sides)
 * proves the authenticated ECDH handshake.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <errno.h>
#include "IPv69/header.h"
#include "IPv69/parse.h"
#include "IPv69/keyring.h"
#include "ed25519.h"
#include "ICSP/icsp.h"

/* ---- minimal L2 helpers (same as include/IPv69/l2.h).
 * build_frame/send_frame are non-static: the ICSP core links them. ---- */
static void put_addr40(uint8_t *d, uint64_t v)
{
    d[0] = (uint8_t)(v >> 32); d[1] = (uint8_t)(v >> 24);
    d[2] = (uint8_t)(v >> 16); d[3] = (uint8_t)(v >> 8);
    d[4] = (uint8_t)v;
}

uint64_t get_addr40(const uint8_t *s)
{
    return ((uint64_t)s[0] << 32) | ((uint64_t)s[1] << 24) |
           ((uint64_t)s[2] << 16) | ((uint64_t)s[3] << 8) | s[4];
}

static int hex_decode(const char *hex, uint8_t *out, size_t max)
{
    size_t hl = strlen(hex);
    if (hl % 2 || hl / 2 > max)
        return -1;
    for (size_t i = 0; i < hl; i += 2) {
        unsigned int b;
        if (sscanf(hex + i, "%2x", &b) != 1)
            return -1;
        out[i / 2] = (uint8_t)b;
    }
    return (int)(hl / 2);
}

size_t build_frame(uint8_t *frame, const uint8_t *dst_mac,
                   const uint8_t src_mac[6], uint64_t src,
                   uint64_t dst, uint8_t next_header,
                   uint8_t hop_limit, uint16_t src_port,
                   uint16_t dst_port, const uint8_t *payload,
                   size_t plen)
{
    struct ethernet_header *eth = (struct ethernet_header *)frame;
    struct ipv69_header *h = (struct ipv69_header *)(frame + 14);

    memcpy(eth->dst_mac, dst_mac, 6);
    memcpy(eth->src_mac, src_mac, 6);
    eth->ethertype = htons(ETHERTYPE_IPV69);
    memset(h, 0, IPV69_HEADER_LEN);
    h->ver_traffic = (IPV69_VERSION << 4) | IPV69_TRAFFIC_CLASS;
    wr_be16(&h->payload_len, plen);
    wr_be16(&h->flow_id, 1);
    h->next_header = next_header;
    h->hop_limit = hop_limit ? hop_limit : 64;
    h->flags = IPV69_FLAG_NOFRAG;
    wr_be16(&h->src_port, src_port);
    wr_be16(&h->dst_port, dst_port);
    put_addr40(h->source, src);
    put_addr40(h->dest, dst);
    memcpy(frame + 14 + IPV69_HEADER_LEN, payload, plen);
    return 14 + IPV69_HEADER_LEN + plen;
}

static int raw_socket(const char *ifname, int *ifindex, uint8_t *src_mac)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_IPV69));
    struct ifreq ifr;

    if (fd < 0) { perror("socket(AF_PACKET)"); return -1; }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); return -1; }
    *ifindex = ifr.ifr_ifindex;
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { perror("SIOCGIFHWADDR"); return -1; }
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);
    struct sockaddr_ll sll = {
        .sll_family = AF_PACKET, .sll_protocol = htons(ETHERTYPE_IPV69),
        .sll_ifindex = *ifindex,
    };
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind(AF_PACKET)");
        return -1;
    }
    return fd;
}

int send_frame(int fd, int ifindex, const uint8_t *dst_mac,
               const uint8_t *frame, size_t len)
{
    struct sockaddr_ll sll = {
        .sll_family = AF_PACKET, .sll_protocol = htons(ETHERTYPE_IPV69),
        .sll_ifindex = ifindex, .sll_halen = 6,
    };
    memcpy(sll.sll_addr, dst_mac, 6);
    return sendto(fd, frame, len, 0, (struct sockaddr *)&sll, sizeof(sll));
}

/* ---- identity: the ~/.hosts69 keyring (same as DHCP) ---- */
static int load_identity(uint8_t sk[64], uint8_t pub[32])
{
    char key[512], kpub[512], dir[256], comment[128];
    keyring_paths(dir, sizeof(dir), key, sizeof(key), kpub, sizeof(kpub));
    return keyring_load_or_create(key, kpub, sk, pub, comment,
                                  sizeof(comment));
}

/* ---- the chat loop ---- */
static int chat_loop(struct icsp_assoc *a, int fd, int ifindex,
                     const uint8_t src_mac[6], uint64_t dst_addr,
                     int echo_mode, int use_stdin)
{
    const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t buf[ICSP_MAX_PAYLOAD];
    char line[ICSP_MAX_PAYLOAD];
    int last_heartbeat = 0;

    printf("chat: conectado! digite mensagens (Ctrl-D sai)\n");
    fflush(stdout);

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        if (use_stdin)
            FD_SET(0, &rfds);
        FD_SET(fd, &rfds);
        struct timeval tv = { 2, 0 };

        int r = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            perror("chat: select");
            return 1;
        }
        if (r == 0 && time(NULL) - last_heartbeat >= 6) {
            icsp_heartbeat_send(a, fd, ifindex, src_mac, bcast, dst_addr, 0);
            last_heartbeat = (int)time(NULL);
            continue;
        }

        if (use_stdin && FD_ISSET(0, &rfds)) {
            if (!fgets(line, sizeof(line), stdin))
                break;              /* Ctrl-D */
            size_t n = strlen(line);
            while (n && (line[n - 1] == '\n' || line[n - 1] == '\r'))
                line[--n] = 0;
            if (!n)
                continue;
            if (icsp_data_send(a, fd, ifindex, src_mac, bcast, dst_addr, 0,
                               1, (const uint8_t *)line, n) < 0) {
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
                icsp_heartbeat_ack(a, fd, ifindex, src_mac, bcast,
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
                    icsp_data_send(a, fd, ifindex, src_mac, bcast,
                                   dst_addr, 0, ostream, buf, (size_t)m);
            }
            if (icsp_life_handle(a, payload,
                                 (size_t)(n - 14 - IPV69_HEADER_LEN))) {
                printf("chat: o outro lado fechou\n");
                break;
            }
        }
    }
    icsp_shutdown_send(a, fd, ifindex, src_mac, bcast, dst_addr, 0);
    printf("chat: encerrado\n");
    return 0;
}

int main(int argc, char **argv)
{
    uint8_t sk[64], pub[32], src_mac[6];
    uint8_t peers[64][32];
    int n_peers = 0, echo_mode = 0;
    struct icsp_assoc a;
    int ifindex, fd;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc < 3) {
        fprintf(stderr, "usage: icsp_chat <server|client> <ifname> "
                "[dst] [port] [--peer HEX] [--echo]\n");
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
    if (fd < 0)
        return 1;

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
        return chat_loop(&a, fd, ifindex, src_mac, 0, echo_mode, 0);
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
        return chat_loop(&a, fd, ifindex, src_mac, dst, 0, 1);
    }

    fprintf(stderr, "chat: modo desconhecido '%s'\n", argv[1]);
    return 1;
}
