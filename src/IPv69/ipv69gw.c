/* ipv69gw - IPv69 tunnel gateway (docs/network-architecture.md).
 *
 * Bridges IPv69 L2 frames over UDP so clients behind NAT can join a
 * network through any host with a public IP. Multi-gateway by design:
 * clients keep a list and fail over; no single gateway is required.
 *
 * Roles:
 *   - learn:  addr40/MAC -> UDP endpoint from incoming traffic (switch)
 *   - forward: unicast frames to the peer's endpoint; broadcast to all
 *   - QUERY:  "Q69" + addr40 -> "E69" + addr40 + "ip:port" so clients
 *             can talk directly (P2P) and the gateway leaves the path
 *   - relay:  when P2P fails, frames keep flowing through us
 *   - --iface eth0: bridge to a local L2 interface (e.g. where the
 *             DHCP69 server runs). Optional; without it, tunnel-only.
 *
 * Wire (UDP datagrams):
 *   data:    [full IPv69 frame: eth 14 + header 38 + payload]
 *   query:   "Q69" + addr40(5)
 *   answer:  "E69" + addr40(5) + "ip:port" text (NUL-terminated)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include "IPv69/af69.h"
#include "IPv69/header.h"
#include "IPv69/parse.h"

#define MAX_PEERS 256
#define PEER_TIMEOUT 300        /* seconds without traffic -> forget */
#define BCAST_MAC { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
#define QMAGIC "Q69"
#define EMAGIC "E69"

struct endpoint {
    struct sockaddr_storage ss;
    socklen_t slen;
};

struct peer {
    uint64_t addr;              /* 40-bit IPv69 address (0 = free) */
    uint8_t mac[6];             /* source MAC of the tunnel */
    struct endpoint ep;
    time_t last;
};

static struct peer peers[MAX_PEERS];

static uint64_t get_addr40(const uint8_t *s)
{
    return ((uint64_t)s[0] << 32) | ((uint64_t)s[1] << 24) |
           ((uint64_t)s[2] << 16) | ((uint64_t)s[3] << 8) | s[4];
}

static struct peer *peer_find_addr(uint64_t addr)
{
    for (int i = 0; i < MAX_PEERS; i++)
        if (peers[i].addr == addr)
            return &peers[i];
    return NULL;
}

static struct peer *peer_find_mac(const uint8_t *mac)
{
    for (int i = 0; i < MAX_PEERS; i++)
        if (peers[i].addr && !memcmp(peers[i].mac, mac, 6))
            return &peers[i];
    return NULL;
}

static struct peer *peer_learn(uint64_t addr, const uint8_t *mac,
                               const struct endpoint *ep)
{
    struct peer *p = peer_find_addr(addr);
    int slot = -1;

    if (p) {
        p->ep = *ep;
        p->last = time(NULL);
        return p;
    }
    for (int i = 0; i < MAX_PEERS; i++) {
        if (!peers[i].addr || time(NULL) - peers[i].last > PEER_TIMEOUT) {
            slot = i;
            break;
        }
    }
    if (slot < 0)
        return NULL;
    peers[slot].addr = addr;
    memcpy(peers[slot].mac, mac, 6);
    peers[slot].ep = *ep;
    peers[slot].last = time(NULL);
    return &peers[slot];
}

static void send_udp(int fd, const void *buf, size_t len,
                     const struct endpoint *ep)
{
    sendto(fd, buf, len, 0, (struct sockaddr *)&ep->ss, ep->slen);
}

static int udp_fd_from(const struct sockaddr_storage *ss, socklen_t slen,
                       struct endpoint *out)
{
    out->ss = *ss;
    out->slen = slen;
    return 0;
}

int cmd_gw(int argc, char **argv)
{
    int port = 6969;
    const char *iface = NULL;
    int ifindex = 0, l2fd = -1;
    uint8_t l2mac[6];

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc)
            port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--iface") && i + 1 < argc)
            iface = argv[++i];
        else {
            fprintf(stderr,
                    "Usage: %s [--port N] [--iface eth0]\n"
                    "  --port:   UDP port (default 6969)\n"
                    "  --iface:  optional local L2 interface to bridge\n"
                    "            (e.g. where af69d runs; needs root)\n",
                    argv[0]);
            return 1;
        }
    }

    /* UDP listener */
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    int v6only = 0;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    if (fd < 0) {
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { perror("socket"); return 1; }
    }
    struct sockaddr_in6 sa6 = {
        .sin6_family = AF_INET6,
        .sin6_addr = IN6ADDR_ANY_INIT,
        .sin6_port = htons(port),
    };
    if (bind(fd, (struct sockaddr *)&sa6, sizeof(sa6)) < 0) {
        struct sockaddr_in sa4 = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = INADDR_ANY,
            .sin_port = htons(port),
        };
        if (bind(fd, (struct sockaddr *)&sa4, sizeof(sa4)) < 0) {
            perror("bind"); return 1;
        }
    }

    /* optional local L2 bridge */
    if (iface) {
        l2fd = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_IPV69));
        if (l2fd < 0) { perror("socket(AF_PACKET)"); return 1; }
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
        if (ioctl(l2fd, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); return 1; }
        ifindex = ifr.ifr_ifindex;
        if (ioctl(l2fd, SIOCGIFHWADDR, &ifr) < 0) { perror("SIOCGIFHWADDR"); return 1; }
        memcpy(l2mac, ifr.ifr_hwaddr.sa_data, 6);
        struct sockaddr_ll sll = {
            .sll_family = AF_PACKET,
            .sll_protocol = htons(ETHERTYPE_IPV69),
            .sll_ifindex = ifindex,
        };
        if (bind(l2fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            perror("bind(AF_PACKET)"); return 1;
        }
    }

    printf("ipv69gw: listening on udp/%d%s%s\n", port,
           iface ? " + l2 bridge " : "", iface ? iface : "");
    fflush(stdout);

    uint8_t buf[1700];
    for (;;) {
        struct pollfd pf[2] = {
            { .fd = fd, .events = POLLIN },
            { .fd = l2fd, .events = POLLIN },
        };
        int npf = l2fd >= 0 ? 2 : 1;
        int pr = poll(pf, npf, 1000);
        if (pr <= 0)
            continue;

        /* ---- UDP side: data frames + queries ---- */
        if (pf[0].revents & POLLIN) {
            struct sockaddr_storage ss;
            socklen_t slen = sizeof(ss);
            ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&ss, &slen);
            if (n <= 0)
                continue;
            struct endpoint ep;
            udp_fd_from(&ss, slen, &ep);

            /* query: "Q69" + addr40 */
            if (n >= 8 && !memcmp(buf, QMAGIC, 3)) {
                uint64_t qaddr = get_addr40(buf + 3);
                struct peer *q = peer_find_addr(qaddr);
                char ans[128] = EMAGIC;
                memcpy(ans + 3, buf + 3, 5);
                if (q) {
                    char host[64];
                    uint16_t qport = 0;
                    if (q->ep.ss.ss_family == AF_INET) {
                        struct sockaddr_in *si =
                            (struct sockaddr_in *)&q->ep.ss;
                        inet_ntop(AF_INET, &si->sin_addr, host, sizeof(host));
                        qport = ntohs(si->sin_port);
                    } else {
                        struct sockaddr_in6 *si6 =
                            (struct sockaddr_in6 *)&q->ep.ss;
                        inet_ntop(AF_INET6, &si6->sin6_addr, host, sizeof(host));
                        qport = ntohs(si6->sin6_port);
                    }
                    size_t l = strlen(ans);
                    snprintf(ans + l, sizeof(ans) - l, "%s:%u", host, qport);
                } else {
                    size_t l = strlen(ans);
                    snprintf(ans + l, sizeof(ans) - l, "-");
                }
                send_udp(fd, ans, strlen(ans) + 1, &ep);
                continue;
            }

            /* data frame */
            if (n < 14 + IPV69_HEADER_LEN + 1)
                continue;
            const struct ethernet_header *eth =
                (const struct ethernet_header *)buf;
            const struct ipv69_header *h =
                (const struct ipv69_header *)(buf + 14);
            if (rd_be16(&eth->ethertype) != ETHERTYPE_IPV69)
                continue;
            uint64_t src = get_addr40(h->source);
            uint64_t dst = get_addr40(h->dest);

            peer_learn(src, eth->src_mac, &ep);

            /* broadcast: replicate to all other tunnels + local */
            const uint8_t bcast_mac[6] = BCAST_MAC;
            if (!memcmp(eth->dst_mac, bcast_mac, 6)) {
                for (int i = 0; i < MAX_PEERS; i++)
                    if (peers[i].addr && peers[i].addr != src)
                        send_udp(fd, buf, n, &peers[i].ep);
                if (l2fd >= 0)
                    sendto(l2fd, buf, n, 0, NULL, 0);
                continue;
            }

            /* unicast: by MAC first (DHCP OFFER/ACK), then by addr */
            struct peer *p = peer_find_mac(eth->dst_mac);
            if (!p)
                p = peer_find_addr(dst);
            if (p) {
                send_udp(fd, buf, n, &p->ep);
                continue;
            }
            /* unknown: try the local L2 bridge (maybe the DHCP server) */
            if (l2fd >= 0) {
                sendto(l2fd, buf, n, 0, NULL, 0);
                continue;
            }
            fprintf(stderr, "ipv69gw: sem destino para %016llx\n",
                    (unsigned long long)dst);
        }

        /* ---- local L2 side: frames from the bridge into tunnels ---- */
        if (l2fd >= 0 && (pf[1].revents & POLLIN)) {
            ssize_t n = recv(l2fd, buf, sizeof(buf), 0);
            if (n < 14 + IPV69_HEADER_LEN + 1)
                continue;
            const struct ethernet_header *eth =
                (const struct ethernet_header *)buf;
            const struct ipv69_header *h =
                (const struct ipv69_header *)(buf + 14);
            if (rd_be16(&eth->ethertype) != ETHERTYPE_IPV69)
                continue;
            uint64_t dst = get_addr40(h->dest);
            const uint8_t bcast_mac[6] = BCAST_MAC;
            if (!memcmp(eth->dst_mac, bcast_mac, 6) ||
                !peer_find_mac(eth->dst_mac)) {
                /* broadcast / unknown: replicate to all tunnels */
                for (int i = 0; i < MAX_PEERS; i++)
                    if (peers[i].addr)
                        send_udp(fd, buf, n, &peers[i].ep);
                continue;
            }
            struct peer *p = peer_find_mac(eth->dst_mac);
            if (!p)
                p = peer_find_addr(dst);
            if (p)
                send_udp(fd, buf, n, &p->ep);
        }
    }
    return 0;
}
