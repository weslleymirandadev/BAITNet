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
#include "IPv69/af69.h"
#include "IPv69/header.h"
#include "IPv69/parse.h"
#include "IPv69/plat.h"
#include "IPv69/ratelimit.h"
#include "ed25519.h"        /* INIT signature check (cryptokey routing) */
#ifdef _WIN32
/* the optional local L2 bridge (--iface) is AF_PACKET: Linux only */
#else
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#endif

#define MAX_PEERS 256
#define PEER_TIMEOUT 300        /* seconds without traffic -> forget */
#define BCAST_MAC { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
#define QMAGIC "Q69"
#define EMAGIC "E69"
#define GW_CHUNK_INIT 1         /* ICSP INIT chunk type (id in clear) */

struct endpoint {
    struct sockaddr_storage ss;
    socklen_t slen;
};

/* cryptokey routing (WireGuard): a peer is (identity key, addr range,
 * endpoint). The range comes from an AUTHENTICATED handshake (INIT
 * signature) or allowlist, so src validation is a hash lookup — no
 * per-packet crypto. */
struct peer {
    uint64_t addr;              /* 40-bit range base */
    uint8_t  prefix;            /* range bits (AllowedIPs-style) */
    uint8_t  mac[6];            /* source MAC of the tunnel */
    uint8_t  key[32];           /* authenticated identity pub */
    struct endpoint ep;
    time_t last;
};

/* --peer allowlist: (key, derived range) — WireGuard peers */
struct auth_peer {
    uint8_t  key[32];
    uint64_t base;
    int      prefix;
};
static struct auth_peer auth[MAX_PEERS];
static int n_auth;

static struct peer peers[MAX_PEERS];


/* longest-prefix match (WireGuard cryptokey routing): the most specific
 * range containing `addr` wins; exact /40 peers are the common case. */
static struct peer *peer_find_addr(uint64_t addr)
{
    struct peer *best = NULL;
    int best_pref = -1;

    for (int i = 0; i < MAX_PEERS; i++)
        if (peers[i].addr && (int)peers[i].prefix > best_pref &&
            ipv69_addr_in_range(addr, peers[i].addr, peers[i].prefix)) {
            best = &peers[i];
            best_pref = peers[i].prefix;
        }
    return best;
}

static struct peer *peer_find_key(const uint8_t key[32])
{
    for (int i = 0; i < MAX_PEERS; i++)
        if (peers[i].addr && !memcmp(peers[i].key, key, 32))
            return &peers[i];
    return NULL;
}

static int auth_allowed(const uint8_t key[32], uint64_t addr)
{
    if (n_auth == 0)
        return 1;               /* open mode: any valid signature */
    for (int i = 0; i < n_auth; i++)
        if (!memcmp(auth[i].key, key, 32) &&
            ipv69_addr_in_range(addr, auth[i].base, auth[i].prefix))
            return 1;
    return 0;
}

static struct peer *peer_find_mac(const uint8_t *mac)
{
    for (int i = 0; i < MAX_PEERS; i++)
        if (peers[i].addr && !memcmp(peers[i].mac, mac, 6))
            return &peers[i];
    return NULL;
}

static struct peer *peer_find_endpoint(const struct endpoint *ep)
{
    const struct sockaddr_in *si = (const struct sockaddr_in *)&ep->ss;
    const struct sockaddr_in6 *si6 = (const struct sockaddr_in6 *)&ep->ss;

    for (int i = 0; i < MAX_PEERS; i++) {
        if (!peers[i].addr)
            continue;
        if (ep->ss.ss_family == AF_INET && peers[i].ep.ss.ss_family == AF_INET) {
            if (si->sin_port == ((const struct sockaddr_in *)&peers[i].ep)->sin_port &&
                !memcmp(&si->sin_addr, &((const struct sockaddr_in *)&peers[i].ep)->sin_addr, 4))
                return &peers[i];
        } else if (ep->ss.ss_family == AF_INET6 && peers[i].ep.ss.ss_family == AF_INET6) {
            if (si6->sin6_port == ((const struct sockaddr_in6 *)&peers[i].ep)->sin6_port &&
                !memcmp(&si6->sin6_addr, &((const struct sockaddr_in6 *)&peers[i].ep)->sin6_addr, 16))
                return &peers[i];
        }
    }
    return NULL;
}

/* learn (or refresh) a peer from an AUTHENTICATED source: the identity
 * key + the address range it is allowed to use. WireGuard learns the
 * endpoint from traffic but only after the handshake authenticates. */
static struct peer *peer_learn_auth(uint64_t addr, const uint8_t *mac,
                                    const struct endpoint *ep,
                                    const uint8_t key[32], int prefix)
{
    struct peer *p = peer_find_key(key);
    int slot = -1;

    if (p) {
        p->addr = addr;
        p->prefix = (uint8_t)prefix;
        p->ep = *ep;
        p->last = time(NULL);
        return p;
    }
    /* WireGuard-style rate limit on learning NEW peers: one source MAC
       cannot flood the table (256 slots) faster than we can evict. */
    {
        uint8_t rid[8] = { 0 };
        memcpy(rid, mac, 6);
        if (!rate_allow(rid, 5, 10, 1))
            return NULL;
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
    peers[slot].prefix = (uint8_t)prefix;
    memcpy(peers[slot].mac, mac, 6);
    memcpy(peers[slot].key, key, 32);
    peers[slot].ep = *ep;
    peers[slot].last = time(NULL);
    return &peers[slot];
}

/* cryptokey routing: validate an ICSP INIT (nh=2, id in clear) and learn
 * the sender's range. Cost: one Ed25519 verify per handshake (rate
 * limited), then hash lookups forever. Returns 1 when learned. */
static int gw_learn_init(const uint8_t *buf, ssize_t n,
                         const struct endpoint *ep)
{
    const struct ethernet_header *eth =
        (const struct ethernet_header *)buf;
    const struct ipv69_header *h =
        (const struct ipv69_header *)(buf + 14);
    const uint8_t *ic = buf + 14 + IPV69_HEADER_LEN;
    /* ICSP header 12 + chunk hdr 4 + INIT data: [ver][flags][streams 4]
       [eph 32][ts 8][id 32][sig 64] = 77 + 64 bytes */
    if (n < 14 + IPV69_HEADER_LEN + 12 + 4 + 77 + 64)
        return 0;
    if (ic[12] != GW_CHUNK_INIT || (ic[13] & 0x01))
        return 0;               /* not an INIT, or id encrypted */
    {
        uint8_t rid[8] = { 0 };
        memcpy(rid, eth->src_mac, 6);
        if (!rate_allow(rid, 10, 20, 1))
            return 0;
    }
    {
        const uint8_t *cd = ic + 16;
        uint8_t pub[32];
        uint64_t src = get_addr40(h->source);
        memcpy(pub, cd + 45, 32);
        if (ed25519_verify(cd, 77, cd + 77, pub) != 0)
            return 0;           /* forged INIT */
        if (!auth_allowed(pub, src))
            return 0;
        if (peer_learn_auth(src, eth->src_mac, ep, pub, 40)) {
            printf("ipv69gw: peer autenticado %016llx (%02x%02x..)\n",
                   (unsigned long long)src, pub[0], pub[1]);
            fflush(stdout);
            return 1;
        }
    }
    return 0;
}

/* cryptokey routing: validate a signed ND announce — dgram clients
 * (send/recv --remote) authenticate their derived address with
 * [ND_REQUEST][addr 5][pub 32][sig 64]. One sign/verify per announce,
 * rate limited; then hash lookups forever. */
static int gw_learn_announce(const uint8_t *buf, ssize_t n,
                             const struct endpoint *ep)
{
    const struct ethernet_header *eth =
        (const struct ethernet_header *)buf;
    const uint8_t *ic = buf + 14 + IPV69_HEADER_LEN;

    if (n < 14 + IPV69_HEADER_LEN + 6 + 96)
        return 0;
    if (ic[0] != IPV69_CTRL_ND_REQUEST)
        return 0;
    {
        uint8_t rid[8] = { 0 };
        memcpy(rid, eth->src_mac, 6);
        if (!rate_allow(rid, 10, 20, 1))
            return 0;
    }
    {
        const uint8_t *pub = ic + 6, *sig = ic + 38;
        uint64_t addr = get_addr40(ic + 1);
        if (ed25519_verify(ic, 6, sig, pub) != 0)
            return 0;           /* forged announce */
        if (!auth_allowed(pub, addr))
            return 0;
        if (peer_learn_auth(addr, eth->src_mac, ep, pub, 40)) {
            printf("ipv69gw: peer autenticado %016llx (%02x%02x..)\n",
                   (unsigned long long)addr, pub[0], pub[1]);
            fflush(stdout);
            return 1;
        }
    }
    return 0;
}

/* cryptokey routing: drop frames whose src is not inside any
 * authenticated range (dgrams); control (src 0 = DHCP discover) and
 * handshakes (nh=2) always pass so the learning can happen. */
static int gw_src_ok(const struct ipv69_header *h)
{
    uint64_t src = get_addr40(h->source);

    if (src == 0 || h->next_header != IPV69_NEXT_DGRAM)
        return 1;               /* control/handshake: let it through */
    return peer_find_addr(src) != NULL;
}

static void send_udp(sock_t fd, const void *buf, size_t len,
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
    int l2fd = -1;
    int allow_private = 0;          /* --private: route class A/B too */
#ifndef _WIN32
    int ifindex = 0;
    uint8_t l2mac[6];
#endif

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc)
            port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--iface") && i + 1 < argc)
            iface = argv[++i];
        else if (!strcmp(argv[i], "--private"))
            allow_private = 1;
        else if (!strcmp(argv[i], "--peer") && i + 1 < argc) {
            /* cryptokey routing allowlist: PUB[/prefix] (WG peers) */
            if (n_auth >= MAX_PEERS) {
                fprintf(stderr, "gw: limite de peers %d\n", MAX_PEERS);
                return 1;
            }
            if (ipv69_addr_parse_peer(argv[++i], auth[n_auth].key,
                                      &auth[n_auth].base,
                                      &auth[n_auth].prefix) < 0) {
                fprintf(stderr, "gw: --peer invalido (%s) — PUB[/prefixo]\n",
                        argv[i]);
                return 1;
            }
            n_auth++;
        } else {
            fprintf(stderr,
                    "Usage: %s [--port N] [--iface eth0] [--private]\n"
                    "             [--peer PUB[/prefix]]...\n"
                    "  --port:    UDP port (default 6969)\n"
                    "  --iface:   optional local L2 interface to bridge\n"
                    "             (e.g. where dhcpd runs; needs root)\n"
                    "  --private: also route class A/B addresses (private\n"
                    "             VPN). Default: public class C only.\n"
                    "  --peer:    cryptokey routing allowlist (WireGuard\n"
                    "             style): only these identities may send;\n"
                    "             /prefix = AllowedIPs range (default /40)\n",
                    argv[0]);
            return 1;
        }
    }

    /* UDP listener */
    sock_t fd = socket(AF_INET6, SOCK_DGRAM, 0);
    int v6only = 0;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&v6only, sizeof(v6only));
    if (fd == SOCK_INVALID) {
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd == SOCK_INVALID) { perror_sock("socket"); return 1; }
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

    /* optional local L2 bridge (AF_PACKET — Linux only) */
    if (iface) {
#ifdef _WIN32
        fprintf(stderr, "ipv69gw: --iface nao e suportado no Windows "
                        "(bridge L2 local usa AF_PACKET)\n");
        return 1;
#else
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
#endif
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
        int pr = plat_poll(pf, npf, 1000);
        if (pr <= 0)
            continue;

        /* ---- UDP side: data frames + queries ---- */
        if (pf[0].revents & POLLIN) {
            struct sockaddr_storage ss;
            socklen_t slen = sizeof(ss);
            ssize_t n = recvfrom(fd, (char *)buf, sizeof(buf), 0,
                                 (struct sockaddr *)&ss, &slen);
            if (n <= 0)
                continue;
            struct endpoint ep;
            udp_fd_from(&ss, slen, &ep);

            /* query: "Q69" + addr40. Only answer peers we know, with a
               compatible class (no --private = public C only). */
            if (n >= 8 && !memcmp(buf, QMAGIC, 3)) {
                uint8_t rid[8] = { 0 };
                memcpy(rid, buf + 14 + 6, 6);   /* eth src of the frame */
                if (!rate_allow(rid, 20, 40, 1))
                    continue;                   /* query flood: silent */
                uint64_t qaddr = get_addr40(buf + 3);
                struct peer *asker = peer_find_endpoint(&ep);
                struct peer *q = peer_find_addr(qaddr);
                char ans[128] = EMAGIC;
                memcpy(ans + 3, buf + 3, 5);
                char qcls = ipv69_addr_class(qaddr);
                char acls = asker ? ipv69_addr_class(asker->addr) : '?';
                if (asker && q && (allow_private ||
                                   (qcls == 'C' && acls == 'C'))) {
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

            /* cryptokey routing: learn the sender's range from an
               authenticated handshake/announce, then validate src */
            if (h->next_header == IPV69_NEXT_STREAM)
                gw_learn_init(buf, n, &ep);
            else if (h->next_header == IPV69_NEXT_CONTROL)
                gw_learn_announce(buf, n, &ep);
            if (!gw_src_ok(h))
                continue;       /* unauthenticated src: silent drop */

            /* class filter: without --private, class A/B frames never
               cross the gateway — neither as source (private leaking
               out) nor as destination (public reaching private).
               Broadcast (class E, L2 control) always passes. */
            char scls = ipv69_addr_class(src);
            char dcls = ipv69_addr_class(dst);
            if (!allow_private &&
                (scls != 'C' || (dcls != 'C' && dcls != 'E'))) {
                fprintf(stderr, "ipv69gw: classe src=%c dst=%c nao roteada (--private ausente)\n",
                        scls, dcls);
                continue;
            }

            /* broadcast: replicate to all other tunnels + local, with
               split horizon (never back to the sender's endpoint) and a
               token bucket per source (amplification guard) */
            const uint8_t bcast_mac[6] = BCAST_MAC;
            if (!memcmp(eth->dst_mac, bcast_mac, 6)) {
                uint8_t rid[8] = { 0 };
                memcpy(rid, eth->src_mac, 6);
                if (!rate_allow(rid, 20, 40, 1))
                    continue;
                struct peer *from = peer_find_endpoint(&ep);
                for (int i = 0; i < MAX_PEERS; i++)
                    if (peers[i].addr && &peers[i] != from)
                        send_udp(fd, buf, n, &peers[i].ep);
                if (l2fd >= 0)
                    sendto(l2fd, (const char *)buf, n, 0, NULL, 0);
                continue;
            }

            /* unicast: by MAC first (DHCP OFFER/ACK), then by addr.
               L2-learned peers (empty endpoint) route back to the L2. */
            struct peer *p = peer_find_mac(eth->dst_mac);
            if (!p)
                p = peer_find_addr(dst);
            if (p) {
                if (p->ep.slen > 0)
                    send_udp(fd, buf, n, &p->ep);
                else if (l2fd >= 0)
                    sendto(l2fd, (const char *)buf, n, 0, NULL, 0);
                continue;
            }
            /* unknown: try the local L2 bridge (maybe the DHCP server) */
            if (l2fd >= 0) {
                sendto(l2fd, (const char *)buf, n, 0, NULL, 0);
                continue;
            }
            fprintf(stderr, "ipv69gw: sem destino para %016llx\n",
                    (unsigned long long)dst);
        }

        /* ---- local L2 side: frames from the bridge into tunnels ---- */
        if (l2fd >= 0 && (pf[1].revents & POLLIN)) {
            ssize_t n = recv(l2fd, (char *)buf, sizeof(buf), 0);
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
            char scls = ipv69_addr_class(src);
            char dcls = ipv69_addr_class(dst);
            if (!allow_private &&
                (scls != 'C' || (dcls != 'C' && dcls != 'E')))
                continue;       /* private frames never reach tunnels */
            /* cryptokey routing on the L2 side too: learn ranges (the
               empty endpoint marks a local-L2 peer: validation only) */
            if (h->next_header == IPV69_NEXT_STREAM) {
                struct endpoint lep;
                memset(&lep, 0, sizeof(lep));
                lep.slen = 0;   /* L2 peer marker (no UDP route) */
                gw_learn_init(buf, n, &lep);
            } else if (h->next_header == IPV69_NEXT_CONTROL) {
                struct endpoint lep;
                memset(&lep, 0, sizeof(lep));
                lep.slen = 0;
                gw_learn_announce(buf, n, &lep);
            }
            if (!gw_src_ok(h))
                continue;
            const uint8_t bcast_mac[6] = BCAST_MAC;
            if (!memcmp(eth->dst_mac, bcast_mac, 6) ||
                !peer_find_mac(eth->dst_mac)) {
                uint8_t rid[8] = { 0 };
                memcpy(rid, eth->src_mac, 6);
                if (!rate_allow(rid, 20, 40, 1))
                    continue;
                /* broadcast / unknown: replicate to all tunnels */
                for (int i = 0; i < MAX_PEERS; i++)
                    if (peers[i].addr)
                        send_udp(fd, buf, n, &peers[i].ep);
                continue;
            }
            struct peer *p = peer_find_mac(eth->dst_mac);
            if (!p)
                p = peer_find_addr(dst);
            if (p && p->ep.slen > 0)
                send_udp(fd, buf, n, &p->ep);
        }
    }
    return 0;
}
