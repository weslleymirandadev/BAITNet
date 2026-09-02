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
#ifdef _WIN32
#include "IPv69/plat.h"   /* winsock: WSAStartup + socket types */
#else
#include <sys/socket.h>
#include <net/if.h>
#endif
#include "IPv69/af69.h"
#include "IPv69/header.h"
#include "IPv69/parse.h"
#include "IPv69/l2.h"
#include "IPv69/mac1.h"
#include "IPv69/ratelimit.h"
#include "ed25519.h"
#include "IPv69/keyring.h"

#define MAX_LEASES 256
#define MAX_PEERS 64
#define BCAST_MAC { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
#define PUB_LEN 32
#define SIG_LEN 64
#define IPV69_BCAST_ADDR 0xFFFFFFFFFFULL


struct lease {
    uint8_t mac[6];
    uint64_t addr;
    time_t expiry;
    int used;
    uint8_t key[32];            /* authenticated identity pub (signed) */
};

/* pubkey allowlist entry with an AllowedIPs-style range (WireGuard):
 * the base is derived from the key (class C), /prefix narrows it. */
struct peer_entry {
    uint8_t  pub[32];
    uint64_t base;
    int      prefix;
};

struct ctx {
    int mode;                 /* 0 = AF_69 socket, 1 = raw L2 */
    l2_handle fd;
    int ifindex;
    uint8_t mac[6];           /* own MAC (raw mode) */
    uint64_t pool_start, pool_end;
    uint32_t lease_sec;
    struct lease leases[MAX_LEASES];
    uint8_t allow[MAX_PEERS][6];      /* MAC allowlist (optional) */
    int n_allow;
    struct peer_entry peers[MAX_PEERS]; /* pubkey allowlist + ranges */
    int n_peers;
    int auth_enabled;                 /* --peer/--peer-file given */
    int learn;                        /* --learn: auto-register pubkeys */
    const char *peer_file;            /* pubkey file, reload on mtime */
    uint8_t sk[64];                   /* server signing key (optional) */
    int has_sk;
};

static volatile sig_atomic_t g_reload = 0;

#ifndef _WIN32
static void on_hup(int sig)
{
    (void)sig;
    g_reload = 1;
}
#endif

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
        if (ipv69_addr_parse_peer(p, c->peers[c->n_peers].pub,
                                  &c->peers[c->n_peers].base,
                                  &c->peers[c->n_peers].prefix) == 0)
            c->n_peers++;
        else
            fprintf(stderr, "af69d: peer-file: linha invalida ignorada: %s\n", p);
    }
    fclose(f);
    printf("af69d: peer-file %s: %d pubkey(s)\n", path, c->n_peers);
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
        if (!memcmp(c->peers[i].pub, pub, PUB_LEN)) {
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
        if (!memcmp(c->peers[i].pub, pub, PUB_LEN))
            return 0;               /* already known */
    if (c->n_peers >= MAX_PEERS) {
        fprintf(stderr, "af69d: learn: tabela de peers cheia (%d)\n",
                MAX_PEERS);
        return 0;
    }
    memcpy(c->peers[c->n_peers].pub, pub, PUB_LEN);
    {
        uint8_t derived[5];
        ipv69_addr_derive(derived, pub, 'C');
        c->peers[c->n_peers].base = get_addr40(derived);
        c->peers[c->n_peers].prefix = 40;
    }
    c->n_peers++;
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

/* pick a free pool address for mac; renews an existing lease if any.
 * O(1) allocation: hash the MAC into the pool + linear probe, so full
 * class-C pools (2^32) allocate without a linear scan. */
static int lease_alloc(struct ctx *c, const uint8_t *mac, time_t now)
{
    struct lease *l = lease_find(c, mac);
    uint64_t span, h, a;

    if (l) {                        /* renew: same address */
        l->expiry = now + c->lease_sec;
        return 1;
    }
    span = c->pool_end - c->pool_start + 1;
    h = 0;
    for (int i = 0; i < 6; i++)
        h = (h * 31 + mac[i]) & 0xFFFFFFFFu;
    a = c->pool_start + (h % span);
    for (int probe = 0; probe < 64; probe++) {
        if (!lease_addr_taken(c, a, now))
            break;
        a++;
        if (a > c->pool_end)
            a = c->pool_start;
    }
    if (lease_addr_taken(c, a, now))
        return 0;                   /* pool full */
    for (int i = 0; i < MAX_LEASES; i++) {
        if (!c->leases[i].used || c->leases[i].expiry <= now) {
            c->leases[i].used = 1;
            memcpy(c->leases[i].mac, mac, 6);
            c->leases[i].addr = a;
            c->leases[i].expiry = now + c->lease_sec;
            return 1;
        }
    }
    return 0;                       /* table full */
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
#ifndef _WIN32
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
#endif
    /* raw L2: build the full Ethernet frame and send it */
    const uint8_t bcast[6] = BCAST_MAC;
    const uint8_t *dmac = dst_mac ? dst_mac : bcast;
    uint8_t frame[1600];

    size_t len = build_frame(frame, dmac, c->mac, IPV69_SERVER_ADDR,
                             IPV69_BCAST_ADDR, IPV69_NEXT_CONTROL,
                             64, 0, 0, payload, plen);
    return l2_send(c->fd, c->ifindex, dmac, frame, len);
}

/* ---- rx (returns payload pointer + len) ------------------------------ */

static size_t recv_ctrl(struct ctx *c, uint8_t *buf, size_t bufsz,
                        uint64_t *dst)
{
    ssize_t n;

#ifndef _WIN32
    if (c->mode == 0) {
        struct sockaddr_69 from;
        socklen_t flen = sizeof(from);
        struct timeval tv = { 1, 0 };
        setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        n = recvfrom(c->fd, buf, bufsz, 0,
                     (struct sockaddr *)&from, &flen);
        if (dst)
            *dst = IPV69_BCAST_ADDR;
        return n > 0 ? (size_t)n : 0;
    }
#endif
    /* raw: 1s tick so the peer-file mtime check runs without traffic */
    n = l2_recv(c->fd, buf, bufsz, 1000);
    if (n < 14 + IPV69_HEADER_LEN + 1)
        return 0;
    {
        const struct ipv69_header *h =
            (const struct ipv69_header *)(buf + 14);
        uint64_t d = get_addr40(h->dest);
        if (h->next_header != IPV69_NEXT_CONTROL)
            return 0;
        if (d != IPV69_BCAST_ADDR && d != IPV69_SERVER_ADDR)
            return 0;               /* not for us */
        if (dst)
            *dst = d;
    }
    memmove(buf, buf + 14 + IPV69_HEADER_LEN, n - 14 - IPV69_HEADER_LEN);
    return (size_t)(n - 14 - IPV69_HEADER_LEN);
}

/* ---- main ------------------------------------------------------------ */

int cmd_dhcpd(int argc, char **argv)
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
#ifndef _WIN32
    if (idx > 0) {
        c.ifindex = idx;
    } else {
        c.ifindex = if_nametoindex(argv[1]);
        if (!c.ifindex) { perror("if_nametoindex"); return 1; }
    }
#else
    (void)idx;              /* Windows resolves the iface via l2_open */
#endif
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
            if (ipv69_addr_parse_peer(argv[++i], c.peers[c.n_peers].pub,
                                      &c.peers[c.n_peers].base,
                                      &c.peers[c.n_peers].prefix) != 0) {
                fprintf(stderr, "peer: pubkey invalida (%s) — PUB[/prefixo]\n",
                        argv[i]);
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
#ifdef _WIN32
    (void)force_raw;        /* raw L2 is the only mode on Windows */
#endif

    /* no --key: auto-load (or generate) the SSH-style keyring
       (~/.hosts69/key, optional passphrase via IPV69_PASSPHRASE) */
    if (!c.has_sk) {
        char kdir[256], kpath[512], kpub[512], comment[128];
        keyring_paths(kdir, sizeof(kdir), kpath, sizeof(kpath),
                      kpub, sizeof(kpub));
        if (keyring_load_or_create(kpath, kpub, c.sk, c.sk + 32,
                                   comment, sizeof(comment)) == 0) {
            c.has_sk = 1;
            printf("af69d: keyring %s (%s)\n", kpath, comment);
        } else {
            fprintf(stderr, "af69d: aviso: sem chave do servidor "
                    "(OFFER/ACK nao assinados); use --key ou crie com "
                    "'ipv69 keygen'\n");
        }
    }

    /* AF_69 socket by default (Linux kernel module); --raw forces the
       portable L2 backend. Windows has no AF_69 socket — always raw. */
    c.mode = 1;
#ifndef _WIN32
    c.fd = socket(AF_69, SOCK_DGRAM, 0);
    if (c.fd >= 0 && !force_raw) {
        c.mode = 0;
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
    }
#endif
    if (c.mode != 0) {
        if (l2_open(argv[1], &c.fd, &c.ifindex, c.mac) < 0)
            return 1;
        printf("af69d: raw L2 (%s), pool %016llx-%016llx lease %us\n",
               argv[1], (unsigned long long)c.pool_start,
               (unsigned long long)c.pool_end, c.lease_sec);
    }
    printf("af69d: allow=%d mac(s), peers=%d pubkey(s), learn=%s, server-key=%s\n",
           c.n_allow, c.n_peers, c.learn ? "sim" : "nao",
           c.has_sk ? "sim" : "nao");
#ifndef _WIN32
    if (c.peer_file)
        signal(SIGHUP, on_hup);
#endif
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
#ifndef _WIN32
        if (g_reload && c.peer_file) {
            g_reload = 0;
            printf("af69d: SIGHUP, recarregando peers...\n");
            peer_file_load(&c, c.peer_file);
        }
#endif
        /* recv_ctrl blocks up to 1s: the peer-file mtime check above
           runs even without traffic, so edits take effect within ~1s */
        uint64_t frm_dst = IPV69_BCAST_ADDR;
        size_t plen = recv_ctrl(&c, buf, sizeof(buf), &frm_dst);
        uint8_t *mac;
        char ms[18];
        if (plen < 7 + MAC1_LEN)
            continue;
        if (buf[0] != IPV69_CTRL_DHCP_DISCOVER &&
            buf[0] != IPV69_CTRL_DHCP_REQUEST &&
            buf[0] != IPV69_CTRL_DHCP_RELEASE)
            continue;
        /* WireGuard mac1 pre-auth filter + per-MAC rate limit: drop
           garbage/throttled senders silently BEFORE the Ed25519 verify */
        {
            uint8_t mkey[32];
            mac1_key(frm_dst, mkey);
            if (mac1_verify(mkey, buf, plen - MAC1_LEN,
                            buf + plen - MAC1_LEN) != 0)
                continue;               /* silent drop */
        }
        {
            uint8_t rid[8] = { 0 };
            memcpy(rid, buf + 1, 6);    /* payload MAC */
            if (!rate_allow(rid, 10, 20, 1))
                continue;
        }
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
            /* remember the authenticated identity (signed DISCOVER) */
            if (plen >= 7 + PUB_LEN + SIG_LEN + MAC1_LEN)
                memcpy(l->key, buf + 7, PUB_LEN);
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
               the lease — or, with a signed REQUEST, allow any free
               address inside the peer's AllowedIPs range (WireGuard
               cryptokey routing: the key authorizes a sub-prefix) */
            int in_range = 0;
            if (plen >= 12 + PUB_LEN + SIG_LEN + MAC1_LEN) {
                const uint8_t *pub = buf + 12;
                for (int i = 0; i < c.n_peers; i++)
                    if (!memcmp(c.peers[i].pub, pub, PUB_LEN) &&
                        ipv69_addr_in_range(req_addr, c.peers[i].base,
                                            c.peers[i].prefix))
                        in_range = 1;
            }
            if ((in_range && !lease_addr_taken(&c, req_addr, now)) ||
                req_addr == l->addr) {
                if (l->addr != req_addr)
                    l->addr = req_addr;
                if (plen >= 12 + PUB_LEN + SIG_LEN + MAC1_LEN)
                    memcpy(l->key, buf + 12, PUB_LEN);
                ack[0] = IPV69_CTRL_DHCP_ACK;
                memcpy(ack + 1, mac, 6);
                put_addr40(ack + 7, req_addr);
                put_be32(ack + 12, c.lease_sec);
                alen = sign_msg(&c, ack, alen);
                send_ctrl(&c, ack, alen, mac);
                printf("af69d: REQUEST %s -> ACK %016llx\n",
                       ms, (unsigned long long)req_addr);
            } else {
                printf("af69d: REQUEST %s pediu %016llx != lease -> negado\n",
                       ms, (unsigned long long)req_addr);
            }
        } else {                    /* RELEASE */
            uint64_t rel_addr = plen >= 12 ? get_addr40(buf + 7) : 0;
            lease_release(&c, mac, rel_addr);
            printf("af69d: RELEASE %s %016llx\n",
                   ms, (unsigned long long)rel_addr);
        }
    }
    return 0;
}
