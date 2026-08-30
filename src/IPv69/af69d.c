/* af69d - DHCP69 server daemon (spec: docs/dhcp69-spec.md).
 *
 * Leases 80-bit addresses over the IPv69 control channel. Works with the
 * AF_69 kernel module (socket(AF_69)) or, without it, raw AF_PACKET
 * (same wire format).
 *
 * Security (Ed25519):
 *   --peer <pubkey_hex>   allowlist: only these public keys may get a
 *                         lease (repeatable). The private key stays on
 *                         the client device; a leaked/revoked key only
 *                         kills that one device.
 *   --peer-file <path>    same, but loaded from a file (one pubkey per
 *                         line, '#' comments); reloaded automatically
 *                         when the file mtime changes (~1s poll).
 *   --key <privkey_hex>   the server's own private key: OFFER/ACK are
 *                         signed so clients can detect rogue servers.
 *   --learn               auto-register: unknown pubkeys are accepted
 *                         and recorded (appended to --peer-file when
 *                         given). With --allow, only MACs in that list
 *                         are learned; without it, any valid signature
 *                         is registered (open network).
 *
 * Wire format with auth (next_header 0, payload):
 *   DISCOVER [7][mac 6][pub 32][sig 64]
 *   OFFER    [8][mac 6][addr 10][lease 4][pub 32][sig 64]
 *   REQUEST  [9][mac 6][addr 10][pub 32][sig 64]
 *   ACK      [10][mac 6][addr 10][lease 4][pub 32][sig 64]
 *   RELEASE  [11][mac 6][addr 10][pub 32][sig 64]
 * The signature covers every byte before it (type..lease). Without
 * --peer/--key the short legacy forms are used (DISCOVER 7, OFFER/ACK 21,
 * REQUEST/RELEASE 17).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include "IPv69/af69.h"
#include "IPv69/header.h"
#include "IPv69/parse.h"
#include "ed25519.h"

#define MAX_LEASES 256
#define MAX_PEERS 64
#define BCAST_MAC { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
#define PUB_LEN 32
#define SIG_LEN 64
#define IPV69_BCAST_ADDR 0xFFFFFFFFFFULL

static int hex_decode(const char *hex, uint8_t *out, size_t max)
{
    size_t hl = strlen(hex);

    if (hl % 2 || hl / 2 > max)
        return -1;
    for (size_t j = 0; j < hl / 2; j++) {
        unsigned v;
        if (sscanf(hex + 2 * j, "%2x", &v) != 1)
            return -1;
        out[j] = (uint8_t)v;
    }
    return (int)(hl / 2);
}

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

struct lease {
    uint8_t mac[6];
    uint64_t addr;
    time_t expiry;
    int used;
};

struct ctx {
    int mode;                 /* 0 = AF_69 socket, 1 = raw AF_PACKET */
    int fd;
    int ifindex;
    uint8_t mac[6];           /* own MAC (raw mode) */
    uint64_t pool_start, pool_end;
    uint32_t lease_sec;
    struct lease leases[MAX_LEASES];
    uint8_t allow[MAX_PEERS][6];      /* MAC allowlist (optional) */
    int n_allow;
    uint8_t peers[MAX_PEERS][PUB_LEN]; /* pubkey allowlist (optional) */
    int n_peers;
    int auth_enabled;                 /* --peer/--peer-file given */
    int learn;                        /* --learn: auto-register pubkeys */
    const char *peer_file;            /* pubkey file, reload on mtime */
    uint8_t sk[64];                   /* server signing key (optional) */
    int has_sk;
};

static volatile sig_atomic_t g_reload = 0;

static void on_hup(int sig)
{
    (void)sig;
    g_reload = 1;
}

/* (re)load pubkeys from a file: one hex key per line, '#' comments.
 * Polled via mtime every loop iteration, so edits take effect without
 * any signal (SIGHUP is just an immediate trigger). */
static void peer_file_load(struct ctx *c, const char *path)
{
    FILE *f = fopen(path, "r");
    char line[96];

    if (!f) {
        fprintf(stderr, "af69d: peer-file %s: %s\n", path, strerror(errno));
        return;
    }
    c->n_peers = 0;
    while (c->n_peers < MAX_PEERS && fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == 0)
            continue;
        line[strcspn(line, "\n")] = 0;
        if (hex_decode(p, c->peers[c->n_peers], PUB_LEN) == PUB_LEN)
            c->n_peers++;
        else
            fprintf(stderr, "af69d: peer-file: linha invalida ignorada: %s\n", p);
    }
    fclose(f);
    printf("af69d: peer-file %s: %d pubkey(s)\n", path, c->n_peers);
}

static void put_be32(uint8_t *d, uint32_t v)
{
    d[0] = v >> 24; d[1] = v >> 16; d[2] = v >> 8; d[3] = v;
}

static void mac_str(const uint8_t *m, char out[18])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void pub_str(const uint8_t *p, char out[65])
{
    for (int i = 0; i < 32; i++)
        snprintf(out + 2 * i, 3, "%02x", p[i]);
    out[64] = 0;
}

/* sign `plen` bytes at msg (type..lease); append pub + sig. Returns the
 * new total length, or plen unchanged when no server key is configured. */
static size_t sign_msg(struct ctx *c, uint8_t *msg, size_t plen)
{
    uint8_t *pub = msg + plen;
    uint8_t *sig = pub + PUB_LEN;

    if (!c->has_sk)
        return plen;
    /* public key = sk[32..63] (keypair appends it) */
    memcpy(pub, c->sk + 32, PUB_LEN);
    if (ed25519_sign(sig, msg, plen, c->sk) < 0)
        return plen;
    return plen + PUB_LEN + SIG_LEN;
}

static int mac_in_allowlist(struct ctx *c, const uint8_t *mac);
static int learn_peer(struct ctx *c, const uint8_t *pub, const uint8_t *mac);

/* verify a signed message: pub at msg+plen-96, sig at msg+plen-64.
 * Checks the pub against the allowlist and the signature over
 * msg[0..plen-96]. Returns 1 when valid (or when no auth configured).
 * With --learn, an unknown-but-valid pubkey is registered on the spot
 * (restricted to --allow MACs when given; open otherwise) and accepted. */
static int check_msg(struct ctx *c, const uint8_t *msg, size_t plen,
                     const uint8_t *mac)
{
    const uint8_t *pub, *sig;
    char ps[65];
    size_t body = plen - PUB_LEN - SIG_LEN;

    if (!c->auth_enabled)
        return 1;                       /* no pubkey auth: accept */
    if (plen < 1 + 6 + PUB_LEN + SIG_LEN)
        return 0;
    pub = msg + body;
    sig = msg + body + PUB_LEN;
    pub_str(pub, ps);
    for (int i = 0; i < c->n_peers; i++)
        if (!memcmp(c->peers[i], pub, PUB_LEN)) {
            if (ed25519_verify(msg, body, sig, pub) == 0)
                return 1;
            printf("af69d: assinatura invalida de %s\n", ps);
            return 0;
        }
    if (c->learn && (!c->n_allow || mac_in_allowlist(c, mac)) &&
        ed25519_verify(msg, body, sig, pub) == 0) {
        learn_peer(c, pub, mac);
        return 1;
    }
    printf("af69d: pub %s nao esta na allowlist -> ignorado\n", ps);
    return 0;
}

static int mac_allowed(struct ctx *c, const uint8_t *mac)
{
    if (!c->n_allow)
        return 1;
    for (int i = 0; i < c->n_allow; i++)
        if (!memcmp(c->allow[i], mac, 6))
            return 1;
    return 0;
}

/* strict check: mac must be explicitly listed in --allow */
static int mac_in_allowlist(struct ctx *c, const uint8_t *mac)
{
    for (int i = 0; i < c->n_allow; i++)
        if (!memcmp(c->allow[i], mac, 6))
            return 1;
    return 0;
}

/* --learn: register an unknown-but-valid pubkey. Only call after the
 * signature was verified against that pubkey (and, when --allow is
 * given, the MAC is in the explicit allowlist). Appends to
 * --peer-file (if any) so the key survives restarts. */
static int learn_peer(struct ctx *c, const uint8_t *pub, const uint8_t *mac)
{
    char ps[65], ms[18];

    for (int i = 0; i < c->n_peers; i++)
        if (!memcmp(c->peers[i], pub, PUB_LEN))
            return 0;               /* already known */
    if (c->n_peers >= MAX_PEERS) {
        fprintf(stderr, "af69d: learn: tabela de peers cheia (%d)\n",
                MAX_PEERS);
        return 0;
    }
    memcpy(c->peers[c->n_peers++], pub, PUB_LEN);
    if (c->peer_file) {
        FILE *f = fopen(c->peer_file, "a");
        if (f) {
            pub_str(pub, ps);
            fprintf(f, "%s\n", ps);
            fclose(f);
        }
    }
    mac_str(mac, ms);
    pub_str(pub, ps);
    printf("af69d: aprendi pub %s do MAC %s -> registrada%s\n", ps, ms,
           c->peer_file ? " no peer-file" : " (so memoria)");
    return 1;
}

/* tell the kernel module who owns a leased address (dgram source auth).
 * Best effort: on kernels without AF_69 there is nothing to update. */
static void binding_update(const uint8_t *mac, uint64_t addr,
                           uint32_t lease_sec, int del)
{
    struct ipv69_bind_req req;
    int fd = socket(AF_69, SOCK_DGRAM, 0);

    if (fd < 0)
        return;
    memset(&req, 0, sizeof(req));
    memcpy(req.mac, mac, 6);
    req.addr = addr;
    req.lease_sec = lease_sec;
    int rc = ioctl(fd, del ? IPV69_BIND_DEL : IPV69_BIND_ADD, &req);
    if (rc < 0)
        fprintf(stderr, "af69d: binding ioctl %s: %s\n",
                del ? "DEL" : "ADD", strerror(errno));
    close(fd);
}

/* ---- lease table ----------------------------------------------------- */

static struct lease *lease_find(struct ctx *c, const uint8_t *mac)
{
    for (int i = 0; i < MAX_LEASES; i++)
        if (c->leases[i].used && !memcmp(c->leases[i].mac, mac, 6))
            return &c->leases[i];
    return NULL;
}

static int lease_addr_taken(struct ctx *c, uint64_t addr, time_t now)
{
    for (int i = 0; i < MAX_LEASES; i++)
        if (c->leases[i].used && c->leases[i].addr == addr &&
            c->leases[i].expiry > now)
            return 1;
    return 0;
}

/* pick a free pool address for mac; renews an existing lease if any */
static int lease_alloc(struct ctx *c, const uint8_t *mac, time_t now)
{
    struct lease *l = lease_find(c, mac);
    uint64_t a;

    if (l) {                        /* renew: same address */
        l->expiry = now + c->lease_sec;
        return 1;
    }
    for (a = c->pool_start; a <= c->pool_end; a++) {
        if (lease_addr_taken(c, a, now))
            continue;
        for (int i = 0; i < MAX_LEASES; i++) {
            if (!c->leases[i].used || c->leases[i].expiry <= now) {
                c->leases[i].used = 1;
                memcpy(c->leases[i].mac, mac, 6);
                c->leases[i].addr = a;
                c->leases[i].expiry = now + c->lease_sec;
                return 1;
            }
        }
        return 0;                   /* table full */
    }
    return 0;                       /* pool full */
}

static void lease_release(struct ctx *c, const uint8_t *mac, uint64_t addr)
{
    struct lease *l = lease_find(c, mac);
    if (l && (!addr || l->addr == addr))
        l->used = 0;
}

/* ---- tx -------------------------------------------------------------- */

/* Send a control payload. In raw mode dst_mac (if non-NULL) is used
   instead of broadcast: DHCP replies go unicast to the client MAC so
   APs that filter wired->wireless broadcast still deliver them. */
static int send_ctrl(struct ctx *c, const uint8_t *payload, size_t plen,
                     const uint8_t *dst_mac)
{
    if (c->mode == 0) {
        struct sockaddr_69 sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_family = AF_69;
        sa.ifindex = c->ifindex;
        sa.src = IPV69_SERVER_ADDR;
        sa.dst = IPV69_BCAST_ADDR;
        sa.next_header = IPV69_NEXT_CONTROL;
        int r = sendto(c->fd, payload, plen, 0,
                      (struct sockaddr *)&sa, sizeof(sa));
        if (r < 0)
            perror("af69d sendto");
        return r;
    }
    /* raw AF_PACKET: build the full Ethernet frame */
    const uint8_t bcast[6] = BCAST_MAC;
    const uint8_t *dmac = dst_mac ? dst_mac : bcast;
    uint8_t frame[1600];
    struct ethernet_header *eth = (struct ethernet_header *)frame;
    struct ipv69_header *h = (struct ipv69_header *)(frame + 14);
    struct sockaddr_ll sll;

    memset(frame, 0, sizeof(frame));
    memcpy(eth->dst_mac, dmac, 6);
    memcpy(eth->src_mac, c->mac, 6);
    eth->ethertype = htons(ETHERTYPE_IPV69);
    memset(h, 0, IPV69_HEADER_LEN);
    h->ver_traffic = (IPV69_VERSION << 4) | IPV69_TRAFFIC_CLASS;
    wr_be16(&h->payload_len, plen);
    wr_be16(&h->flow_id, 1);
    h->next_header = IPV69_NEXT_CONTROL;
    h->hop_limit = 64;
    h->flags = IPV69_FLAG_NOFRAG;
    put_addr40(h->source, IPV69_SERVER_ADDR);
    put_addr40(h->dest, IPV69_BCAST_ADDR);
    memcpy(frame + 14 + IPV69_HEADER_LEN, payload, plen);

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETHERTYPE_IPV69);
    sll.sll_ifindex = c->ifindex;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, dmac, 6);
    return sendto(c->fd, frame, 14 + IPV69_HEADER_LEN + plen, 0,
                  (struct sockaddr *)&sll, sizeof(sll));
}

/* ---- rx (returns payload pointer + len) ------------------------------ */

static size_t recv_ctrl(struct ctx *c, uint8_t *buf, size_t bufsz)
{
    ssize_t n;

    if (c->mode == 0) {
        struct sockaddr_69 from;
        socklen_t flen = sizeof(from);
        n = recvfrom(c->fd, buf, bufsz, 0,
                     (struct sockaddr *)&from, &flen);
        return n > 0 ? (size_t)n : 0;
    }
    n = recv(c->fd, buf, bufsz, 0);
    if (n < 14 + IPV69_HEADER_LEN + 1)
        return 0;
    {
        const struct ipv69_header *h =
            (const struct ipv69_header *)(buf + 14);
        uint64_t dst = get_addr40(h->dest);
        if (h->next_header != IPV69_NEXT_CONTROL)
            return 0;
        if (dst != IPV69_BCAST_ADDR && dst != IPV69_SERVER_ADDR)
            return 0;               /* not for us */
    }
    memmove(buf, buf + 14 + IPV69_HEADER_LEN, n - 14 - IPV69_HEADER_LEN);
    return (size_t)(n - 14 - IPV69_HEADER_LEN);
}

/* ---- main ------------------------------------------------------------ */

int main(int argc, char **argv)
{
    struct ctx c;
    uint8_t buf[1500], offer[1 + 6 + 5 + 4 + PUB_LEN + SIG_LEN],
                   ack[1 + 6 + 5 + 4 + PUB_LEN + SIG_LEN];
    time_t now;
    int idx;

    setvbuf(stdout, NULL, _IONBF, 0);
    memset(&c, 0, sizeof(c));
    c.pool_start = IPV69_DHCP_POOL_START;
    c.pool_end = IPV69_DHCP_POOL_END;
    c.lease_sec = IPV69_DHCP_LEASE_DEFAULT;

    if (argc < 2) {
        fprintf(stderr,
                "Usage: %s <ifname|ifindex> [pool_start] [pool_end] [lease_sec]\n"
                "       [--raw] [--allow MAC]... [--peer PUBKEY_HEX]... [--peer-file PATH] [--key PRIVKEY_HEX]\n"
                "       [--learn]\n"
                "  pool_start/pool_end: ff.ff.ff.ff.ff or raw hex\n"
                "  defaults: pool 00.00.00.00.10-00.00.00.00.fe, lease 3600s\n"
                "  --raw:    force AF_PACKET (AP filtering wired->wireless\n"
                "            broadcast requires unicast replies)\n"
                "  --allow:  MAC allowlist (repeatable)\n"
                "  --peer:   Ed25519 pubkey allowlist (repeatable) - only\n"
                "            these devices may get a lease\n"
                "  --peer-file: file with one pubkey per line ('#' comments);\n"
                "            reloads automatically when the file changes\n"
                "  --learn:  auto-register unknown pubkeys (with a valid\n"
                "            signature); restricted to --allow MACs when\n"
                "            given, open otherwise; appended to\n"
                "            --peer-file when given\n"
                "  --key:    server privkey - signs OFFER/ACK so clients\n"
                "            can detect rogue servers\n"
                "Generate keys: ipv69-keygen\n",
                argv[0]);
        return 1;
    }
    idx = atoi(argv[1]);
    if (idx > 0) {
        c.ifindex = idx;
    } else {
        c.ifindex = if_nametoindex(argv[1]);
        if (!c.ifindex) { perror("if_nametoindex"); return 1; }
    }
    /* positional pool/lease (argv 2/3/4), flags anywhere */
    if (argc > 2 && strcmp(argv[2], "--raw") && strcmp(argv[2], "--allow") &&
        strcmp(argv[2], "--peer") && strcmp(argv[2], "--peer-file") &&
        strcmp(argv[2], "--key") && strcmp(argv[2], "--learn"))
        if (parse_ipv69_addr(argv[2], &c.pool_start) < 0) {
            fprintf(stderr, "pool_start invalido\n");
            return 1;
        }
    if (argc > 3 && strcmp(argv[3], "--raw") && strcmp(argv[3], "--allow") &&
        strcmp(argv[3], "--peer") && strcmp(argv[3], "--peer-file") &&
        strcmp(argv[3], "--key") && strcmp(argv[3], "--learn"))
        if (parse_ipv69_addr(argv[3], &c.pool_end) < 0) {
            fprintf(stderr, "pool_end invalido\n");
            return 1;
        }
    if (argc > 4 && strcmp(argv[4], "--raw") && strcmp(argv[4], "--allow") &&
        strcmp(argv[4], "--peer") && strcmp(argv[4], "--peer-file") &&
        strcmp(argv[4], "--key") && strcmp(argv[4], "--learn")) {
        char *end;
        long v = strtol(argv[4], &end, 10);
        if (*argv[4] && !*end && v > 0)
            c.lease_sec = (uint32_t)v;
    }
    /* flags in any position */
    int force_raw = 0;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--raw")) {
            force_raw = 1;
        } else if (!strcmp(argv[i], "--allow") && i + 1 < argc) {
            if (c.n_allow >= MAX_PEERS) {
                fprintf(stderr, "allow: limite %d\n", MAX_PEERS);
                return 1;
            }
            if (sscanf(argv[++i], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                       &c.allow[c.n_allow][0], &c.allow[c.n_allow][1],
                       &c.allow[c.n_allow][2], &c.allow[c.n_allow][3],
                       &c.allow[c.n_allow][4], &c.allow[c.n_allow][5]) != 6) {
                fprintf(stderr, "allow: MAC invalido %s\n", argv[i]);
                return 1;
            }
            c.n_allow++;
        } else if (!strcmp(argv[i], "--peer") && i + 1 < argc) {
            if (c.n_peers >= MAX_PEERS) {
                fprintf(stderr, "peer: limite %d\n", MAX_PEERS);
                return 1;
            }
            if (hex_decode(argv[++i], c.peers[c.n_peers], PUB_LEN) != PUB_LEN) {
                fprintf(stderr, "peer: pubkey invalida (32 bytes hex)\n");
                return 1;
            }
            c.n_peers++;
            c.auth_enabled = 1;
        } else if (!strcmp(argv[i], "--peer-file") && i + 1 < argc) {
            c.peer_file = argv[++i];
            c.auth_enabled = 1;
            peer_file_load(&c, c.peer_file);
        } else if (!strcmp(argv[i], "--learn")) {
            c.learn = 1;
        } else if (!strcmp(argv[i], "--key") && i + 1 < argc) {
            uint8_t seed[32];
            if (hex_decode(argv[++i], seed, 32) != 32) {
                fprintf(stderr, "key: privkey invalida (32 bytes hex)\n");
                return 1;
            }
            /* sk[64] = seed || pub (keypair layout) */
            memcpy(c.sk, seed, 32);
            ed25519_seed_to_pub(c.sk + 32, seed);
            c.has_sk = 1;
        }
    }

    /* AF_69 socket by default; --raw forces AF_PACKET */
    c.mode = 0;
    c.fd = socket(AF_69, SOCK_DGRAM, 0);
    if (c.fd >= 0 && !force_raw) {
        struct sockaddr_69 sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_family = AF_69;
        sa.ifindex = c.ifindex;
        sa.src = IPV69_SERVER_ADDR;
        if (bind(c.fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("bind(AF_69)"); return 1;
        }
        printf("af69d: AF_69 socket (ifindex %d), pool %016llx-%016llx lease %us\n",
               c.ifindex, (unsigned long long)c.pool_start,
               (unsigned long long)c.pool_end, c.lease_sec);
    } else {
        c.mode = 1;
        c.fd = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_IPV69));
        if (c.fd < 0) { perror("socket(AF_PACKET)"); return 1; }
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);
        if (ioctl(c.fd, SIOCGIFHWADDR, &ifr) < 0) { perror("SIOCGIFHWADDR"); return 1; }
        memcpy(c.mac, ifr.ifr_hwaddr.sa_data, 6);
        struct sockaddr_ll sll = {
            .sll_family = AF_PACKET,
            .sll_protocol = htons(ETHERTYPE_IPV69),
            .sll_ifindex = c.ifindex,
        };
        if (bind(c.fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) { perror("bind"); return 1; }
        printf("af69d: raw AF_PACKET (ifindex %d), pool %016llx-%016llx lease %us\n",
               c.ifindex, (unsigned long long)c.pool_start,
               (unsigned long long)c.pool_end, c.lease_sec);
    }
    printf("af69d: allow=%d mac(s), peers=%d pubkey(s), learn=%s, server-key=%s\n",
           c.n_allow, c.n_peers, c.learn ? "sim" : "nao",
           c.has_sk ? "sim" : "nao");
    if (c.peer_file)
        signal(SIGHUP, on_hup);
    struct stat pst = { 0 };
    if (c.peer_file)
        stat(c.peer_file, &pst);

    for (;;) {
        /* poll peer-file mtime: reload without signals */
        if (c.peer_file) {
            struct stat nst;
            if (stat(c.peer_file, &nst) == 0 &&
                (nst.st_mtime != pst.st_mtime || nst.st_size != pst.st_size)) {
                pst = nst;
                printf("af69d: peer-file mudou, recarregando...\n");
                peer_file_load(&c, c.peer_file);
            }
        }
        if (g_reload && c.peer_file) {
            g_reload = 0;
            printf("af69d: SIGHUP, recarregando peers...\n");
            peer_file_load(&c, c.peer_file);
        }
        /* poll with timeout: lets the peer-file mtime check run even
           without traffic, so edits take effect within ~1s */
        struct pollfd pf = { .fd = c.fd, .events = POLLIN };
        int pr = poll(&pf, 1, 1000);
        if (pr <= 0)
            continue;               /* timeout or EINTR: recheck mtime */
        size_t plen = recv_ctrl(&c, buf, sizeof(buf));
        uint8_t *mac;
        char ms[18];
        if (plen < 7)
            continue;
        if (buf[0] != IPV69_CTRL_DHCP_DISCOVER &&
            buf[0] != IPV69_CTRL_DHCP_REQUEST &&
            buf[0] != IPV69_CTRL_DHCP_RELEASE)
            continue;
        mac = buf + 1;
        mac_str(mac, ms);
        now = time(NULL);

        if (!mac_allowed(&c, mac)) {
            printf("af69d: %s nao esta na allowlist -> ignorado\n", ms);
            continue;
        }
        if (!check_msg(&c, buf, plen, mac)) {
            printf("af69d: %s assinatura/pubkey invalida -> ignorado\n", ms);
            continue;
        }

        if (buf[0] == IPV69_CTRL_DHCP_DISCOVER) {
            size_t olen = 16;
            uint64_t oaddr;
            if (!lease_alloc(&c, mac, now)) {
                printf("af69d: pool cheio, DISCOVER de %s ignorado\n", ms);
                continue;
            }
            struct lease *l = lease_find(&c, mac);
            oaddr = l->addr;
            offer[0] = IPV69_CTRL_DHCP_OFFER;
            memcpy(offer + 1, mac, 6);
            put_addr40(offer + 7, oaddr);
            put_be32(offer + 12, c.lease_sec);
            olen = sign_msg(&c, offer, olen);
            send_ctrl(&c, offer, olen, mac);
            printf("af69d: DISCOVER %s -> OFFER %016llx\n",
                   ms, (unsigned long long)oaddr);
        } else if (buf[0] == IPV69_CTRL_DHCP_REQUEST) {
            size_t alen = 16;
            if (plen < 12)
                continue;
            uint64_t req_addr = get_addr40(buf + 7);
            struct lease *l = lease_find(&c, mac);
            if (!l) {               /* fresh request without discover */
                if (!lease_alloc(&c, mac, now))
                    continue;
                l = lease_find(&c, mac);
            } else {
                l->expiry = now + c.lease_sec;
            }
            /* client asked for a specific address; confirm it matches
               the lease (else keep the leased one) */
            if (req_addr == l->addr) {
                ack[0] = IPV69_CTRL_DHCP_ACK;
                memcpy(ack + 1, mac, 6);
                put_addr40(ack + 7, req_addr);
                put_be32(ack + 12, c.lease_sec);
                alen = sign_msg(&c, ack, alen);
                send_ctrl(&c, ack, alen, mac);
                binding_update(mac, req_addr, c.lease_sec, 0);
                printf("af69d: REQUEST %s -> ACK %016llx\n",
                       ms, (unsigned long long)req_addr);
            } else {
                printf("af69d: REQUEST %s pediu %016llx != lease -> negado\n",
                       ms, (unsigned long long)req_addr);
            }
        } else {                    /* RELEASE */
            uint64_t rel_addr = plen >= 12 ? get_addr40(buf + 7) : 0;
            lease_release(&c, mac, rel_addr);
            if (rel_addr)
                binding_update(mac, rel_addr, 0, 1);
            printf("af69d: RELEASE %s %016llx\n",
                   ms, (unsigned long long)rel_addr);
        }
    }
    return 0;
}
