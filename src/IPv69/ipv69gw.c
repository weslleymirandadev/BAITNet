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
#include "IPv69/l2.h"       /* build_frame, hex_decode */
#include "IPv69/keyring.h"  /* gw identity for --peer-gw links */
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

/* gateway mesh: federated gateways on the same L2 discover each other
 * with GW_ANN broadcasts; a QUERY the local table cannot answer is
 * forwarded to the L2 (GW_Q) and the reply (GW_R) is relayed back to
 * the UDP asker, so clients behind different gateways still find each
 * other P2P (WireGuard-style roaming across federated endpoints). */
struct gw_neigh {
    uint8_t mac[6];
    time_t last;
};
static struct gw_neigh gwn[MAX_PEERS];
static int n_gwn;

struct gw_pend {
    uint64_t addr;
    struct endpoint asker;
    int via_link;           /* asker is a federated link: GW_R frame back */
    time_t ts;
};
static struct gw_pend gwp[16];
static int n_gwp;

/* ---- federated gateway links (--peer-gw PUB@endpoint) ----
 * A link is a UDP tunnel to another gateway's listener. The peer is
 * authenticated by its fixed endpoint (WG-style) plus its Ed25519
 * identity: GW_ANN over a link carries a signature we check against
 * the configured pub. Mesh control flows over links exactly like on
 * the L2 mesh; data frames from a link are trusted (the sending
 * gateway already did cryptokey src validation) and routed locally
 * or re-forwarded to the other links. */
#define MAX_LINKS 8
struct gw_link {
    struct endpoint ep;         /* the peer gateway's UDP listener */
    uint8_t pub[32];            /* its Ed25519 identity */
    time_t last;                /* last authenticated GW_ANN */
};
static struct gw_link glink[MAX_LINKS];
static int n_glink;

/* listener state is process-global so mesh helpers stay short */
static sock_t g_udp_fd = SOCK_INVALID;
static int g_l2fd = -1;
static uint8_t g_l2mac[6];
static int g_allow_private;         /* --private: route class A/B too */

static int gw_link_find(const struct endpoint *ep);
static void gw_link_send_pkt(const struct gw_link *l,
                             const uint8_t *pkt, size_t plen);
static void send_udp(sock_t fd, const void *buf, size_t len,
                     const struct endpoint *ep);

static struct gw_neigh *gw_neigh_find(const uint8_t *mac)
{
    for (int i = 0; i < n_gwn; i++)
        if (!memcmp(gwn[i].mac, mac, 6))
            return &gwn[i];
    return NULL;
}

/* GW_R wire: [GW_R][addr40 5][ip4 4][port 2] (v4-only mesh reply).
 * Build it from the target peer; 0 when not routable (no UDP ep or
 * native-v6 endpoint). */
static int gw_r_build(uint8_t rpkt[12], uint64_t q, const struct peer *t)
{
    const struct sockaddr *sa =
        (const struct sockaddr *)&t->ep.ss;
    uint8_t ip4[4];
    uint16_t qport = 0;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *si = (const struct sockaddr_in *)sa;
        memcpy(ip4, &si->sin_addr, 4);
        qport = ntohs(si->sin_port);
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *si6 =
            (const struct sockaddr_in6 *)sa;
        if (!IN6_IS_ADDR_V4MAPPED(&si6->sin6_addr))
            return 0;
        memcpy(ip4, &si6->sin6_addr.s6_addr[12], 4);
        qport = ntohs(si6->sin6_port);
    } else {
        return 0;
    }
    rpkt[0] = IPV69_CTRL_GW_R;
    put_addr40(rpkt + 1, q);
    memcpy(rpkt + 6, ip4, 4);
    rpkt[10] = (uint8_t)(qport >> 8);
    rpkt[11] = (uint8_t)qport;
    return 12;
}

/* a GW_R arrived: relay the answer to the pending asker. The asker is
 * either a UDP client (text answer "E69...") or a federated gateway
 * link (the GW_R frame goes back verbatim). */
static void gw_pend_relay(const uint8_t *p)
{
    uint64_t q = get_addr40(p + 1);
    for (int i = 0; i < n_gwp; i++) {
        if (gwp[i].addr == q) {
            if (gwp[i].via_link) {
                int li = gw_link_find(&gwp[i].asker);
                if (li >= 0)
                    gw_link_send_pkt(&glink[li], p, 12);
            } else {
                struct sockaddr_in sin;
                memset(&sin, 0, sizeof(sin));
                sin.sin_family = AF_INET;
                memcpy(&sin.sin_addr, p + 6, 4);
                memcpy(&sin.sin_port, p + 10, 2);
                /* same wire format as the local QUERY answer:
                   "E69" + raw addr40 + "ip:port" text */
                char ans[128] = EMAGIC;
                ans[3] = (char)(q >> 32);
                ans[4] = (char)(q >> 24);
                ans[5] = (char)(q >> 16);
                ans[6] = (char)(q >> 8);
                ans[7] = (char)q;
                snprintf(ans + 8, sizeof(ans) - 8, "%s:%d",
                         inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
                sendto(g_udp_fd, ans, strlen(ans), 0,
                       (struct sockaddr *)&gwp[i].asker.ss,
                       gwp[i].asker.slen);
            }
            gwp[i] = gwp[--n_gwp];
            printf("ipv69gw: mesh: relayei %016llx -> asker\n",
                   (unsigned long long)q);
            fflush(stdout);
            return;
        }
    }
}

/* broadcast a mesh control frame on the L2 (eth dst comes from the
 * frame header — the AF_PACKET bind has no sll_addr) */
static void gw_mesh_send(const uint8_t *pkt, size_t plen)
{
    const uint8_t bcast_mac[6] = BCAST_MAC;
    uint8_t frame[128];

    size_t len = build_frame(frame, bcast_mac, g_l2mac, 0,
                             0xFFFFFFFFFFULL, IPV69_NEXT_CONTROL,
                             64, 0, 0, pkt, plen);
    sendto(g_l2fd, (const char *)frame, len, 0, NULL, 0);
}

/* handle mesh control on the L2 side: learn neighbors, answer GW_Q,
 * relay GW_R to the pending asker. Returns 1 when consumed. */
static int gw_mesh_handle(const uint8_t *buf, ssize_t n)
{
    const struct ethernet_header *eth =
        (const struct ethernet_header *)buf;
    const struct ipv69_header *h =
        (const struct ipv69_header *)(buf + 14);
    const uint8_t *p = buf + 14 + IPV69_HEADER_LEN;
    size_t plen = (size_t)n - 14 - IPV69_HEADER_LEN;

    if (h->next_header != IPV69_NEXT_CONTROL || plen < 1)
        return 0;
    if (p[0] == IPV69_CTRL_GW_ANN) {
        /* learn/refresh the announcing gateway */
        if (!gw_neigh_find(eth->src_mac) && n_gwn < MAX_PEERS) {
            memcpy(gwn[n_gwn].mac, eth->src_mac, 6);
            gwn[n_gwn].last = time(NULL);
            n_gwn++;
            printf("ipv69gw: mesh: vizinho %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
                   eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);
            fflush(stdout);
        } else if (gw_neigh_find(eth->src_mac)) {
            gw_neigh_find(eth->src_mac)->last = time(NULL);
        }
        return 1;
    }
    if (p[0] == IPV69_CTRL_GW_Q && plen >= 6) {
        uint64_t q = get_addr40(p + 1);
        struct peer *t = peer_find_addr(q);
        uint8_t rpkt[12];
        if (t && gw_r_build(rpkt, q, t) > 0) {
            gw_mesh_send(rpkt, sizeof(rpkt));
            printf("ipv69gw: mesh: respondi %016llx\n",
                   (unsigned long long)q);
            fflush(stdout);
        }
        return 1;
    }
    if (p[0] == IPV69_CTRL_GW_R && plen >= 12) {
        gw_pend_relay(p);
        return 1;
    }
    return 0;
}

/* a QUERY the local table cannot answer: remember the asker and ask the
 * L2 mesh and/or the federated links (once per addr, 2s expiry).
 * Returns 1 when forwarded anywhere. */
static int gw_mesh_query(uint64_t q, const struct endpoint *asker)
{
    if (n_gwn == 0 && n_glink == 0)
        return 0;
    for (int i = 0; i < n_gwp; i++)
        if (gwp[i].addr == q)
            return 1;               /* already asked */
    if (n_gwp < 16) {
        gwp[n_gwp].addr = q;
        gwp[n_gwp].asker = *asker;
        gwp[n_gwp].via_link = 0;
        gwp[n_gwp].ts = time(NULL);
        n_gwp++;
    }
    uint8_t qpkt[6];
    qpkt[0] = IPV69_CTRL_GW_Q;
    put_addr40(qpkt + 1, q);
    if (n_gwn > 0)
        gw_mesh_send(qpkt, sizeof(qpkt));       /* L2 mesh */
    for (int i = 0; i < n_glink; i++)
        gw_link_send_pkt(&glink[i], qpkt, sizeof(qpkt)); /* links */
    printf("ipv69gw: mesh: forwardei QUERY %016llx\n",
           (unsigned long long)q);
    fflush(stdout);
    return 1;
}

/* ---- federated link transport ---- */

/* the dual-stack listener delivers v4 peers v4-mapped: match by
 * address+port regardless of AF_INET/AF_INET6 representation */
static int link_ep_match(const struct endpoint *a, const struct gw_link *l)
{
    const struct sockaddr *sa = (const struct sockaddr *)&a->ss;
    const struct sockaddr *sl = (const struct sockaddr *)&l->ep.ss;
    uint8_t a4[4], l4[4];
    uint16_t ap = 0, lp = 0;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *si = (const struct sockaddr_in *)sa;
        memcpy(a4, &si->sin_addr, 4);
        ap = si->sin_port;
    } else if (sa->sa_family == AF_INET6 &&
               IN6_IS_ADDR_V4MAPPED(
                   &((const struct sockaddr_in6 *)sa)->sin6_addr)) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;
        memcpy(a4, &s6->sin6_addr.s6_addr[12], 4);
        ap = s6->sin6_port;
    } else if (sa->sa_family == AF_INET6 && sl->sa_family == AF_INET6) {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)sa;
        const struct sockaddr_in6 *l6 = (const struct sockaddr_in6 *)sl;
        return a6->sin6_port == l6->sin6_port &&
               !memcmp(&a6->sin6_addr, &l6->sin6_addr, 16);
    } else {
        return 0;
    }
    if (sl->sa_family == AF_INET) {
        const struct sockaddr_in *si = (const struct sockaddr_in *)sl;
        memcpy(l4, &si->sin_addr, 4);
        lp = si->sin_port;
    } else if (sl->sa_family == AF_INET6 &&
               IN6_IS_ADDR_V4MAPPED(
                   &((const struct sockaddr_in6 *)sl)->sin6_addr)) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sl;
        memcpy(l4, &s6->sin6_addr.s6_addr[12], 4);
        lp = s6->sin6_port;
    } else {
        return 0;
    }
    return ap == lp && !memcmp(a4, l4, 4);
}

static int gw_link_find(const struct endpoint *ep)
{
    for (int i = 0; i < n_glink; i++)
        if (link_ep_match(ep, &glink[i]))
            return i;
    return -1;
}

/* control frame to a link (the UDP datagram carries a full IPv69 frame
 * with a control payload, exactly like the L2 mesh wire) */
static void gw_link_send_pkt(const struct gw_link *l,
                             const uint8_t *pkt, size_t plen)
{
    const uint8_t bcast_mac[6] = BCAST_MAC;
    uint8_t frame[192];
    size_t len = build_frame(frame, bcast_mac, g_l2mac, 0,
                             0xFFFFFFFFFFULL, IPV69_NEXT_CONTROL,
                             64, 0, 0, pkt, plen);
    sendto(g_udp_fd, (const char *)frame, len, 0,
           (struct sockaddr *)&l->ep.ss, l->ep.slen);
}

/* raw data frame to a link (relay of client traffic) */
static void gw_link_send_raw(const struct gw_link *l,
                             const uint8_t *buf, size_t n)
{
    sendto(g_udp_fd, (const char *)buf, n, 0,
           (struct sockaddr *)&l->ep.ss, l->ep.slen);
}

/* authenticated GW_ANN to every link: [GW_ANN][port 2][sig 64] over
 * the first 3 bytes, signed with our identity (the pub the peer
 * configured in --peer-gw) */
static void gw_link_announce(uint16_t port, const uint8_t sk[64])
{
    uint8_t pkt[3 + 64];
    pkt[0] = IPV69_CTRL_GW_ANN;
    pkt[1] = (uint8_t)(port >> 8);
    pkt[2] = (uint8_t)port;
    ed25519_sign(pkt + 3, pkt, 3, sk);
    for (int i = 0; i < n_glink; i++)
        gw_link_send_pkt(&glink[i], pkt, sizeof(pkt));
}

/* mesh control from a federated link. Returns 1 when consumed. */
static int gw_fed_handle(int li, const uint8_t *buf, ssize_t n)
{
    const struct ipv69_header *h =
        (const struct ipv69_header *)(buf + 14);
    const uint8_t *p = buf + 14 + IPV69_HEADER_LEN;
    size_t plen = (size_t)n - 14 - IPV69_HEADER_LEN;

    if (h->next_header != IPV69_NEXT_CONTROL || plen < 1)
        return 0;
    if (p[0] == IPV69_CTRL_GW_ANN) {
        /* authenticate the link: signature against the configured pub,
           rate limited (a bad sig costs an Ed25519 verify) */
        if (plen >= 3 + 64 &&
            rate_allow(glink[li].pub, 10, 20, 1) &&
            ed25519_verify(p, 3, p + 3, glink[li].pub) == 0) {
            if (glink[li].last == 0) {
                printf("ipv69gw: link %d: vizinho autenticado "
                       "(pub %02x%02x..)\n",
                       li, glink[li].pub[0], glink[li].pub[1]);
                fflush(stdout);
            }
            glink[li].last = time(NULL);
        }
        return 1;
    }
    if (p[0] == IPV69_CTRL_GW_Q && plen >= 6) {
        uint64_t q = get_addr40(p + 1);
        struct peer *t = peer_find_addr(q);
        uint8_t rpkt[12];
        if (t && gw_r_build(rpkt, q, t) > 0) {
            gw_link_send_pkt(&glink[li], rpkt, sizeof(rpkt));
            printf("ipv69gw: mesh: respondi %016llx (link %d)\n",
                   (unsigned long long)q, li);
            fflush(stdout);
        } else if (!t && n_glink > 1) {
            /* unknown here: ask the other links (never back to li) */
            int asked = 0;
            for (int i = 0; i < n_gwp; i++)
                if (gwp[i].addr == q)
                    asked = 1;
            if (!asked && n_gwp < 16) {
                gwp[n_gwp].addr = q;
                gwp[n_gwp].asker = glink[li].ep;
                gwp[n_gwp].via_link = 1;
                gwp[n_gwp].ts = time(NULL);
                n_gwp++;
                for (int j = 0; j < n_glink; j++)
                    if (j != li)
                        gw_link_send_pkt(&glink[j], p, plen);
            }
        }
        return 1;
    }
    if (p[0] == IPV69_CTRL_GW_R && plen >= 12) {
        gw_pend_relay(p);
        return 1;
    }
    return 0;
}

/* data frame from a trusted federated link (the sending gateway did
 * the cryptokey src validation): route to local clients, the local L2
 * or the other links. Split horizon: never back to link li. */
static void gw_fed_data(int li, const uint8_t *buf, ssize_t n)
{
    const struct ethernet_header *eth =
        (const struct ethernet_header *)buf;
    const struct ipv69_header *h =
        (const struct ipv69_header *)(buf + 14);
    uint64_t src = get_addr40(h->source);
    uint64_t dst = get_addr40(h->dest);
    char scls = ipv69_addr_class(src);
    char dcls = ipv69_addr_class(dst);
    if (!g_allow_private &&
        (scls != 'C' || (dcls != 'C' && dcls != 'E')))
        return;                 /* defensive class filter (local policy) */
    const uint8_t bcast_mac[6] = BCAST_MAC;
    if (!memcmp(eth->dst_mac, bcast_mac, 6)) {
        uint8_t rid[8] = { 0 };
        memcpy(rid, eth->src_mac, 6);
        if (!rate_allow(rid, 20, 40, 1))
            return;
        for (int i = 0; i < MAX_PEERS; i++)
            if (peers[i].addr && peers[i].ep.slen > 0)
                send_udp(g_udp_fd, buf, n, &peers[i].ep);
        return;
    }
    struct peer *p = peer_find_mac(eth->dst_mac);
    if (!p)
        p = peer_find_addr(dst);
    if (p && p->ep.slen > 0) {
        send_udp(g_udp_fd, buf, n, &p->ep);
        return;
    }
    if (p && p->ep.slen == 0 && g_l2fd >= 0) {
        sendto(g_l2fd, (const char *)buf, n, 0, NULL, 0);
        return;
    }
    for (int j = 0; j < n_glink; j++)
        if (j != li)
            gw_link_send_raw(&glink[j], buf, n);
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
    uint8_t l2mac[6] = { 0 };       /* L2 bridge state (Linux only) */
#ifndef _WIN32
    int ifindex = 0;
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
        } else if (!strcmp(argv[i], "--peer-gw") && i + 1 < argc) {
            /* federated gateway link: PUB@endpoint (the other gateway's
               Ed25519 identity and its UDP listener) */
            if (n_glink >= MAX_LINKS) {
                fprintf(stderr, "gw: limite de links %d\n", MAX_LINKS);
                return 1;
            }
            char *arg = argv[++i];
            char *at = strchr(arg, '@');
            if (!at || at == arg) {
                fprintf(stderr,
                        "gw: --peer-gw invalido (%s) — PUB@endpoint\n",
                        arg);
                return 1;
            }
            *at = 0;
            if (hex_decode(arg, glink[n_glink].pub, 32) != 32) {
                fprintf(stderr, "gw: --peer-gw: pub invalida (%s)\n", arg);
                return 1;
            }
            char hp[256];
            snprintf(hp, sizeof(hp), "%s", at + 1);
            char *colon = strrchr(hp, ':');
            if (!colon) {
                fprintf(stderr, "gw: --peer-gw: endpoint invalido (%s)\n",
                        at + 1);
                return 1;
            }
            *colon = 0;
            int pport = atoi(colon + 1);
            char *host = hp;
            if (host[0] == '[') {   /* [v6]:port */
                host++;
                char *rb = strchr(host, ']');
                if (rb)
                    *rb = 0;
            }
            struct endpoint lep;
            memset(&lep, 0, sizeof(lep));
            struct sockaddr_in l4;
            struct sockaddr_in6 l6;
            if (inet_pton(AF_INET, host, &l4.sin_addr) == 1) {
                l4.sin_family = AF_INET;
                l4.sin_port = htons(pport);
                memcpy(&lep.ss, &l4, sizeof(l4));
                lep.slen = sizeof(l4);
            } else if (inet_pton(AF_INET6, host, &l6.sin6_addr) == 1) {
                l6.sin6_family = AF_INET6;
                l6.sin6_port = htons(pport);
                memcpy(&lep.ss, &l6, sizeof(l6));
                lep.slen = sizeof(l6);
            } else {
                fprintf(stderr, "gw: --peer-gw: endpoint invalido (%s)\n",
                        at + 1);
                return 1;
            }
            glink[n_glink].ep = lep;
            glink[n_glink].last = 0;
            printf("ipv69gw: link %d: %s -> pub %02x%02x..%02x%02x\n",
                   n_glink, at + 1, glink[n_glink].pub[0],
                   glink[n_glink].pub[1], glink[n_glink].pub[30],
                   glink[n_glink].pub[31]);
            fflush(stdout);
            n_glink++;
        } else {
            fprintf(stderr,
                    "Usage: %s [--port N] [--iface eth0] [--private]\n"
                    "             [--peer PUB[/prefix]]...\n"
                    "             [--peer-gw PUB@endpoint]...\n"
                    "  --port:    UDP port (default 6969)\n"
                    "  --iface:   optional local L2 interface to bridge\n"
                    "             (e.g. where dhcpd runs; needs root)\n"
                    "  --private: also route class A/B addresses (private\n"
                    "             VPN). Default: public class C only.\n"
                    "  --peer:    cryptokey routing allowlist (WireGuard\n"
                    "             style): only these identities may send;\n"
                    "             /prefix = AllowedIPs range (default /40)\n"
                    "  --peer-gw: federate with another gateway (this\n"
                    "             machine's ilha is bridged to its): the\n"
                    "             link is UDP to its listener, authenticated\n"
                    "             by its Ed25519 PUB (needs our keyring)\n",
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

    /* listener state is process-global for the mesh helpers */
    g_udp_fd = fd;
    g_l2fd = l2fd;
    g_allow_private = allow_private;
    memcpy(g_l2mac, l2mac, 6);

    /* federated links need our identity to sign GW_ANN */
    uint8_t gw_sk[64] = { 0 };
    int have_sk = 0;
    if (n_glink > 0) {
        char kdir[256], kpath[512], kpub[512], comment[128];
        keyring_paths(kdir, sizeof(kdir), kpath, sizeof(kpath),
                      kpub, sizeof(kpub));
        if (keyring_load_or_create(kpath, kpub, gw_sk, gw_sk + 32,
                                   comment, sizeof(comment)) == 0) {
            have_sk = 1;
            printf("ipv69gw: keyring %s (%s)\n", kpath, comment);
        } else {
            fprintf(stderr,
                    "gw: --peer-gw precisa da identidade local — crie\n"
                    "    com 'ipv69 keygen' (HOME=%s)\n", kdir);
            return 1;
        }
    }

    printf("ipv69gw: listening on udp/%d%s%s%s\n", port,
           iface ? " + l2 bridge " : "", iface ? iface : "",
           n_glink > 0 ? " + links federados" : "");
    fflush(stdout);

    uint8_t buf[1700];
    time_t last_ann = 0;
    time_t boot = time(NULL);
    for (;;) {
        /* gateway mesh: announce ourselves (L2 + federated links) every
           30s; retry every 2s during the first 6s so a gateway booting
           right after us still learns us (handshake retry, WG-style) */
        int ann_int = time(NULL) - boot < 6 ? 2 : 30;
        if (time(NULL) - last_ann >= ann_int) {
            if (g_l2fd >= 0) {
                uint8_t apkt[3];
                apkt[0] = IPV69_CTRL_GW_ANN;
                apkt[1] = (uint8_t)(port >> 8);
                apkt[2] = (uint8_t)port;
                gw_mesh_send(apkt, sizeof(apkt));
                printf("ipv69gw: mesh: anunciado na L2 (udp/%d)\n", port);
                fflush(stdout);
            }
            if (n_glink > 0 && have_sk)
                gw_link_announce((uint16_t)port, gw_sk);
            last_ann = time(NULL);
        }
        /* expire mesh pending queries (2s) */
        {
            time_t now = time(NULL);
            for (int i = 0; i < n_gwp;)
                if (now - gwp[i].ts > 2)
                    gwp[i] = gwp[--n_gwp];
                else
                    i++;
        }
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
                /* L2-learned entries have no UDP endpoint: they are
                   reachable only through their owning gateway, so the
                   mesh must be asked instead of answering garbage */
                if (q && q->ep.slen == 0)
                    q = NULL;
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
                } else if (!q && (n_gwn > 0 || n_glink > 0) && asker) {
                    /* mesh: a federated gateway (L2 or link) may know the
                       target — forward instead of answering "-" */
                    gw_mesh_query(qaddr, &ep);
                    continue;       /* wait for the mesh reply */
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
            /* federated gateway link: its endpoint matches a --peer-gw.
               Mesh control is consumed; data frames are trusted (the
               peer gateway validated src) and routed locally/onward. */
            {
                int li = gw_link_find(&ep);
                if (li >= 0) {
                    if (!gw_fed_handle(li, buf, n))
                        gw_fed_data(li, buf, n);
                    continue;
                }
            }
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
                for (int i = 0; i < n_glink; i++)   /* federation */
                    gw_link_send_raw(&glink[i], buf, n);
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
            /* unknown: try the local L2 bridge (maybe the DHCP server),
               then the federated links (the target may live in another
               ilha behind a peer gateway) */
            if (l2fd >= 0) {
                sendto(l2fd, (const char *)buf, n, 0, NULL, 0);
                continue;
            }
            if (n_glink > 0) {
                for (int i = 0; i < n_glink; i++)
                    gw_link_send_raw(&glink[i], buf, n);
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
            /* gateway mesh control (GW_ANN/GW_Q/GW_R): consume it,
               never replicate it to the tunnels */
            if (gw_mesh_handle(buf, n))
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
                /* broadcast / unknown: replicate to all tunnels and
                   the federated links (the target may be in another
                   ilha; its gateway will route it) */
                for (int i = 0; i < MAX_PEERS; i++)
                    if (peers[i].addr)
                        send_udp(fd, buf, n, &peers[i].ep);
                for (int i = 0; i < n_glink; i++)
                    gw_link_send_raw(&glink[i], buf, n);
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
