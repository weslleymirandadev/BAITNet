/* af69_raw - IPv69 (ethertype 0x6969) over AF_PACKET, no kernel module.
 * For devices whose kernel lacks the AF_69 patch (e.g. stock Android).
 * Same wire format as the af69.ko module: Ethernet + 32B IPv69 header
 * (ports native at offsets 10/12) + [payload] for the dgram protocol.
 * Usage: af69_raw recv <ifname> [src_port_hex]
 *        af69_raw send <ifname> <dst> <src_port_hex> <dst_port_hex> [payload]
 *        af69_raw ping <ifname> <dst> [payload]   (echo request/reply)
 *        af69_raw dhcp <ifname>                   (lease from DHCP69 server)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include "IPv69/af69.h"
#include "IPv69/header.h"
#include "IPv69/parse.h"
#include "IPv69/hmac.h"

#define IPV69_CTRL_ECHO_REQUEST 3
#define IPV69_CTRL_ECHO_REPLY   4
#define IPV69_BCAST_ADDR        0xFFFFFFFFFFULL

static void put_addr40(uint8_t *d, uint64_t v)
{
    d[0] = (v >> 32) & 0xff; d[1] = (v >> 24) & 0xff;
    d[2] = (v >> 16) & 0xff; d[3] = (v >> 8) & 0xff; d[4] = v & 0xff;
}

static uint64_t get_addr40(const uint8_t *s)
{
    return ((uint64_t)s[0] << 32) | ((uint64_t)s[1] << 24) |
           ((uint64_t)s[2] << 16) | ((uint64_t)s[3] << 8) | s[4];
}

static uint32_t get_be32(const uint8_t *s)
{
    return ((uint32_t)s[0] << 24) | ((uint32_t)s[1] << 16) |
           ((uint32_t)s[2] << 8) | s[3];
}

/* build an Ethernet frame: [eth 14][ipv69 32][payload]; returns total len */
static size_t build_frame(uint8_t *frame, const uint8_t *dst_mac,
                          const uint8_t *src_mac, uint64_t src, uint64_t dst,
                          uint8_t next_header, uint8_t hop_limit,
                          uint16_t src_port, uint16_t dst_port,
                          const uint8_t *payload, size_t plen)
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
    int err;

    if (fd < 0) { perror("socket(AF_PACKET)"); return -1; }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); return -1; }
    *ifindex = ifr.ifr_ifindex;
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { perror("SIOCGIFHWADDR"); return -1; }
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);
    err = bind(fd, (struct sockaddr *)&(struct sockaddr_ll){
        .sll_family = AF_PACKET, .sll_protocol = htons(ETHERTYPE_IPV69),
        .sll_ifindex = *ifindex }, sizeof(struct sockaddr_ll));
    if (err < 0) { perror("bind(AF_PACKET)"); return -1; }
    return fd;
}

static int send_frame(int fd, int ifindex, const uint8_t *dst_mac,
                      const uint8_t *frame, size_t len)
{
    struct sockaddr_ll sll = {
        .sll_family = AF_PACKET, .sll_protocol = htons(ETHERTYPE_IPV69),
        .sll_ifindex = ifindex, .sll_halen = 6,
    };
    memcpy(sll.sll_addr, dst_mac, 6);
    return sendto(fd, frame, len, 0, (struct sockaddr *)&sll, sizeof(sll));
}

static void dump_frame(const uint8_t *frame, size_t len)
{
    const struct ethernet_header *eth = (const struct ethernet_header *)frame;
    const struct ipv69_header *h = (const struct ipv69_header *)(frame + 14);
    size_t plen;

    if (len < 14 + IPV69_HEADER_LEN) { printf("frame curto (%zu)\n", len); return; }
    plen = rd_be16(&h->payload_len);
    printf("frame: eth_dst=%02x:%02x:%02x:%02x:%02x:%02x src=%016llx dst=%016llx nh=%u",
           eth->dst_mac[0], eth->dst_mac[1], eth->dst_mac[2],
           eth->dst_mac[3], eth->dst_mac[4], eth->dst_mac[5],
           (unsigned long long)get_addr40(h->source),
           (unsigned long long)get_addr40(h->dest), h->next_header);
    if (h->next_header == IPV69_NEXT_DGRAM) {
        const uint8_t *p = frame + 14 + IPV69_HEADER_LEN;
        printf(" ports=%u/%u payload(%zu)=", rd_be16(&h->src_port),
               rd_be16(&h->dst_port), plen);
        for (size_t i = 0; i < plen && i < 128; i++)
            putchar((p[i] >= 0x20 && p[i] <= 0x7e) ? p[i] : '.');
    } else if (h->next_header == IPV69_NEXT_CONTROL && plen >= 1) {
        printf(" ctrl=%u", frame[14 + IPV69_HEADER_LEN]);
    }
    putchar('\n');
}

/* DHCP69 client: DISCOVER [7][mac][tok?] -> OFFER [8][mac][addr5][lease4][tok?]
 * -> REQUEST [9][mac][addr5][tok?] -> ACK [10][mac][addr5][lease4][tok?].
 * Same wire format for raw and AF_69 paths; client filters by its MAC.
 * With a secret, every message carries a trailing 8-byte HMAC token. */
static int dhcp_client(int fd, int ifindex, const uint8_t src_mac[6],
                       const uint8_t *secret, size_t secret_len)
{
    const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t frame[1600], pkt[1 + 6 + 5 + 4 + IPV69_TOKEN_LEN];
    struct timeval tv = { 3, 0 };
    uint64_t addr = 0;
    ssize_t n;
    size_t len;
    uint8_t digest[32];

    printf("dhcp: MAC %02x:%02x:%02x:%02x:%02x:%02x%s\n",
           src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
           secret_len ? " (HMAC)" : "");
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* DISCOVER [7][mac] + token */
    pkt[0] = IPV69_CTRL_DHCP_DISCOVER;
    memcpy(pkt + 1, src_mac, 6);
    size_t dlen = 7;
    if (secret_len) {
        ipv69_hmac(secret, secret_len, src_mac, 6, digest);
        memcpy(pkt + 7, digest, IPV69_TOKEN_LEN);
        dlen += IPV69_TOKEN_LEN;
    }
    len = build_frame(frame, bcast, src_mac, 0, 0xFFFFFFFFFFULL,
                      IPV69_NEXT_CONTROL, 64, 0, 0, pkt, dlen);
    if (send_frame(fd, ifindex, bcast, frame, len) < 0) { perror("sendto(DISCOVER)"); return 1; }
    printf("dhcp: DISCOVER enviado\n");

    /* wait OFFER [8][mac][addr5][lease4] + token */
    for (;;) {
        n = recv(fd, frame, sizeof(frame), 0);
        if (n < 0) { perror("recvfrom(OFFER): timeout?"); return 1; }
        if (n < 14 + IPV69_HEADER_LEN + 16 + (secret_len ? IPV69_TOKEN_LEN : 0)) continue;
        const struct ipv69_header *h = (const struct ipv69_header *)(frame + 14);
        const uint8_t *p = frame + 14 + IPV69_HEADER_LEN;
        size_t plen = n - 14 - IPV69_HEADER_LEN;
        if (h->next_header != IPV69_NEXT_CONTROL || p[0] != IPV69_CTRL_DHCP_OFFER)
            continue;
        if (memcmp(p + 1, src_mac, 6)) continue;
        if (secret_len) {
            ipv69_hmac(secret, secret_len, src_mac, 6, digest);
            if (plen < 16 + IPV69_TOKEN_LEN ||
                memcmp(p + 16, digest, IPV69_TOKEN_LEN)) {
                printf("dhcp: OFFER token invalido\n");
                return 1;
            }
        }
        addr = get_addr40(p + 7);
        printf("dhcp: OFFER %016llx lease %us\n",
               (unsigned long long)addr, get_be32(p + 12));
        break;
    }

    /* REQUEST [9][mac][addr5] + token */
    pkt[0] = IPV69_CTRL_DHCP_REQUEST;
    memcpy(pkt + 1, src_mac, 6);
    put_addr40(pkt + 7, addr);
    size_t rlen = 12;
    if (secret_len) {
        ipv69_hmac(secret, secret_len, src_mac, 6, digest);
        memcpy(pkt + 12, digest, IPV69_TOKEN_LEN);
        rlen += IPV69_TOKEN_LEN;
    }
    len = build_frame(frame, bcast, src_mac, 0, 0xFFFFFFFFFFULL,
                      IPV69_NEXT_CONTROL, 64, 0, 0, pkt, rlen);
    if (send_frame(fd, ifindex, bcast, frame, len) < 0) { perror("sendto(REQUEST)"); return 1; }
    printf("dhcp: REQUEST %016llx\n", (unsigned long long)addr);

    /* wait ACK [10][mac][addr5][lease4] + token */
    for (;;) {
        n = recv(fd, frame, sizeof(frame), 0);
        if (n < 0) { perror("recvfrom(ACK): timeout?"); return 1; }
        if (n < 14 + IPV69_HEADER_LEN + 16 + (secret_len ? IPV69_TOKEN_LEN : 0)) continue;
        const struct ipv69_header *h = (const struct ipv69_header *)(frame + 14);
        const uint8_t *p = frame + 14 + IPV69_HEADER_LEN;
        size_t plen = n - 14 - IPV69_HEADER_LEN;
        if (h->next_header != IPV69_NEXT_CONTROL || p[0] != IPV69_CTRL_DHCP_ACK)
            continue;
        if (memcmp(p + 1, src_mac, 6)) continue;
        if (secret_len) {
            ipv69_hmac(secret, secret_len, src_mac, 6, digest);
            if (plen < 16 + IPV69_TOKEN_LEN ||
                memcmp(p + 16, digest, IPV69_TOKEN_LEN)) {
                printf("dhcp: ACK token invalido\n");
                return 1;
            }
        }
        printf("dhcp: ACK %016llx — configurado!\n", (unsigned long long)addr);
        break;
    }

    /* keep receiving for a few seconds to show it works */
    tv.tv_sec = 5;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    printf("dhcp: bound src=%016llx, ouvindo 5s...\n", (unsigned long long)addr);
    for (;;) {
        n = recv(fd, frame, sizeof(frame), 0);
        if (n < 0) break;
        dump_frame(frame, (size_t)n);
    }
    return 0;
}

int main(int argc, char **argv)
{
    const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t src_mac[6], frame[1600];
    int ifindex;
    uint8_t secret[32];
    size_t secret_len = 0;

    setvbuf(stdout, NULL, _IONBF, 0);

    /* global option: --secret HEX (any position) */
    for (int i = 1; i < argc - 1; i++) {
        if (!strcmp(argv[i], "--secret")) {
            const char *hex = argv[i + 1];
            size_t hl = strlen(hex);
            if (hl % 2 || hl / 2 > sizeof(secret)) {
                fprintf(stderr, "secret: hex par <= 64 chars\n");
                return 1;
            }
            secret_len = hl / 2;
            for (size_t j = 0; j < secret_len; j++) {
                unsigned v;
                sscanf(hex + 2 * j, "%2x", &v);
                secret[j] = (uint8_t)v;
            }
            /* remove --secret and its value from argv */
            memmove(&argv[i], &argv[i + 2], sizeof(char *) * (argc - i - 1));
            argc -= 2;
            break;
        }
    }

    if (argc < 3) {
        fprintf(stderr,
                "Usage: %s recv <ifname> [src_addr] [src_port_hex]\n"
                "       %s send <ifname> <dst> <src_port_hex> <dst_port_hex> [payload]\n"
                "       %s ping <ifname> <dst> [payload]\n"
                "       %s dhcp <ifname> [--secret HEX]\n",
                argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    int fd = raw_socket(argv[2], &ifindex, src_mac);
    if (fd < 0) return 1;
    printf("iface=%s ifindex=%d mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
           argv[2], ifindex, src_mac[0], src_mac[1], src_mac[2],
           src_mac[3], src_mac[4], src_mac[5]);

    if (!strcmp(argv[1], "recv")) {
        /* optional bind: recv <ifname> [src_addr] [src_port_hex] */
        uint64_t my_addr = 0;
        uint16_t my_port = 0;
        if (argc > 3 && parse_ipv69_addr(argv[3], &my_addr) < 0) {
            fprintf(stderr, "recv: src_addr invalido\n");
            return 1;
        }
        if (argc > 4)
            my_port = (uint16_t)strtoul(argv[4], NULL, 16);
        if (my_addr)
            printf("bound src=%016llx port=%04x (filtrando)\n",
                   (unsigned long long)my_addr, my_port);
        for (;;) {
            ssize_t n = recv(fd, frame, sizeof(frame), 0);
            if (n < 0) { perror("recv"); return 1; }
            if (n < 14 + IPV69_HEADER_LEN)
                continue;
            const struct ipv69_header *h =
                (const struct ipv69_header *)(frame + 14);
            if (my_addr) {
                uint64_t dst = get_addr40(h->dest);
                if (dst != my_addr && dst != 0xFFFFFFFFFFULL)
                    continue;   /* not for us */
                if (my_port && h->next_header == IPV69_NEXT_DGRAM &&
                    rd_be16(&h->dst_port) != my_port)
                    continue;
            }
            dump_frame(frame, (size_t)n);
        }
    }

    if (!strcmp(argv[1], "send")) {
        uint64_t dst, src = 0;
        size_t plen;
        if (argc < 6 || parse_ipv69_addr(argv[3], &dst) < 0) {
            fprintf(stderr, "send: precisa <dst> <src_port> <dst_port> [payload] [src_addr]\n");
            return 1;
        }
        const char *data = argc > 6 ? argv[6] : "hello ipv69";
        size_t dlen = strlen(data);
        uint16_t sp = (uint16_t)strtoul(argv[4], NULL, 16);
        uint16_t dp = (uint16_t)strtoul(argv[5], NULL, 16);
        /* optional trailing src_addr (leased address) */
        if (argc > 7 && parse_ipv69_addr(argv[7], &src) < 0) {
            fprintf(stderr, "send: src_addr invalido\n");
            return 1;
        }
        plen = dlen;
        size_t len = build_frame(frame, bcast, src_mac, src, dst, IPV69_NEXT_DGRAM,
                                 64, sp, dp, (const uint8_t *)data, plen);
        if (send_frame(fd, ifindex, bcast, frame, len) < 0) { perror("sendto"); return 1; }
        printf("sent %zu bytes (dgram, dst=%016llx src=%016llx)\n",
               dlen, (unsigned long long)dst, (unsigned long long)src);
        return 0;
    }

    if (!strcmp(argv[1], "ping")) {
        uint64_t dst;
        uint8_t req[1 + 512];
        struct timeval tv = { 2, 0 };
        if (argc < 4 || parse_ipv69_addr(argv[3], &dst) < 0) {
            fprintf(stderr, "ping: precisa <dst> [payload]\n");
            return 1;
        }
        const char *data = argc > 4 ? argv[4] : "ping";
        size_t dlen = strlen(data);
        req[0] = IPV69_CTRL_ECHO_REQUEST;
        memcpy(req + 1, data, dlen);
        size_t len = build_frame(frame, bcast, src_mac, 1, dst, IPV69_NEXT_CONTROL,
                                 64, 0, 0, req, 1 + dlen);
        if (send_frame(fd, ifindex, bcast, frame, len) < 0) { perror("sendto"); return 1; }
        printf("ping enviado para %016llx, aguardando reply...\n",
               (unsigned long long)dst);
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        for (;;) {
            ssize_t n = recv(fd, frame, sizeof(frame), 0);
            if (n < 0) { perror("recvfrom: timeout?"); return 1; }
            if (n >= 14 + IPV69_HEADER_LEN + 1) {
                const struct ipv69_header *h =
                    (const struct ipv69_header *)(frame + 14);
                if (h->next_header == IPV69_NEXT_CONTROL &&
                    frame[14 + IPV69_HEADER_LEN] == IPV69_CTRL_ECHO_REPLY) {
                    printf("reply de %016llx: ",
                           (unsigned long long)get_addr40(h->source));
                    for (size_t i = 1; i < (size_t)n - 14 - IPV69_HEADER_LEN && i <= dlen; i++)
                        putchar((frame[14 + IPV69_HEADER_LEN + i] >= 0x20 &&
                                 frame[14 + IPV69_HEADER_LEN + i] <= 0x7e)
                                ? frame[14 + IPV69_HEADER_LEN + i] : '.');
                    putchar('\n');
                    return 0;
                }
            }
        }
    }

    if (!strcmp(argv[1], "dhcp"))
        return dhcp_client(fd, ifindex, src_mac, secret, secret_len);

    fprintf(stderr, "modo desconhecido: %s\n", argv[1]);
    return 1;
}
