/* af69d - DHCP69 server daemon (spec: docs/dhcp69-spec.md).
 *
 * Leases 40-bit addresses over the IPv69 control channel. Works with the
 * AF_69 kernel module (socket(AF_69)) or, without it, raw AF_PACKET
 * (same wire format).
 *
 * Security:
 *   --allow aa:bb:cc:dd:ee:ff   only these MACs may get a lease (repeatable)
 *   --secret <hex>              shared secret; every DHCP message carries an
 *                               8-byte HMAC-SHA256 token (client must know it)
 *
 * Usage: af69d <ifname|ifindex> [pool_start] [pool_end] [lease_sec]
 *             [--raw] [--allow MAC]... [--secret HEX]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include "IPv69/af69.h"
#include "IPv69/header.h"
#include "IPv69/parse.h"
#include "IPv69/hmac.h"

#define MAX_LEASES 256
#define MAX_ALLOW 64
#define BCAST_MAC { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }

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
    uint8_t allow[MAX_ALLOW][6];
    int n_allow;
    uint8_t secret[32];       /* shared secret (raw bytes) */
    int secret_len;
};

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

static void put_be32(uint8_t *d, uint32_t v)
{
    d[0] = v >> 24; d[1] = v >> 16; d[2] = v >> 8; d[3] = v;
}

/* append 8-byte HMAC-SHA256(secret, mac) token at *p; returns bytes written */
static int token_append(struct ctx *c, const uint8_t *mac, uint8_t *p)
{
    uint8_t digest[32];

    if (!c->secret_len)
        return 0;
    ipv69_hmac(c->secret, c->secret_len, mac, 6, digest);
    memcpy(p, digest, IPV69_TOKEN_LEN);
    return IPV69_TOKEN_LEN;
}

/* verify trailing token on a received message; plen is total payload len */
static int token_check(struct ctx *c, const uint8_t *msg, size_t plen,
                       const uint8_t *mac)
{
    uint8_t digest[32];

    if (!c->secret_len)
        return 1;               /* no auth configured: accept */
    if (plen < IPV69_TOKEN_LEN)
        return 0;
    ipv69_hmac(c->secret, c->secret_len, mac, 6, digest);
    return !memcmp(msg + plen - IPV69_TOKEN_LEN, digest, IPV69_TOKEN_LEN);
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

static void mac_str(const uint8_t *m, char out[18])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
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
static uint64_t lease_alloc(struct ctx *c, const uint8_t *mac, time_t now)
{
    struct lease *l = lease_find(c, mac);
    uint64_t a;

    if (l) {                        /* renew: same address */
        l->expiry = now + c->lease_sec;
        return l->addr;
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
                return a;
            }
        }
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
        sa.dst = 0xFFFFFFFFFFULL;   /* broadcast */
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
    put_addr40(h->dest, 0xFFFFFFFFFFULL);
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
        if (dst != 0xFFFFFFFFFFULL && dst != IPV69_SERVER_ADDR)
            return 0;               /* not for us */
    }
    memmove(buf, buf + 14 + IPV69_HEADER_LEN, n - 14 - IPV69_HEADER_LEN);
    return (size_t)(n - 14 - IPV69_HEADER_LEN);
}

/* ---- main ------------------------------------------------------------ */

int main(int argc, char **argv)
{
    struct ctx c;
    uint8_t buf[1500], offer[1 + 6 + 5 + 4 + IPV69_TOKEN_LEN],
                   ack[1 + 6 + 5 + 4 + IPV69_TOKEN_LEN];
    time_t now;
    uint64_t addr;
    int idx;

    setvbuf(stdout, NULL, _IONBF, 0);
    memset(&c, 0, sizeof(c));
    c.pool_start = IPV69_DHCP_POOL_START;
    c.pool_end = IPV69_DHCP_POOL_END;
    c.lease_sec = IPV69_DHCP_LEASE_DEFAULT;

    if (argc < 2) {
        fprintf(stderr,
                "Usage: %s <ifname|ifindex> [pool_start] [pool_end] [lease_sec]\n"
                "       [--raw] [--allow aa:bb:cc:dd:ee:ff]... [--secret HEX]\n"
                "  pool_start/pool_end: ff.ff.ff.ff.ff or raw hex\n"
                "  defaults: pool 00.00.00.00.10-00.00.00.00.fe, lease 3600s\n"
                "  --raw:    force AF_PACKET (AP filtering wired->wireless\n"
                "            broadcast requires unicast replies)\n"
                "  --allow:  restrict leases to these MACs (repeatable)\n"
                "  --secret: shared secret; DHCP msgs carry HMAC token\n",
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
        strcmp(argv[2], "--secret"))
        if (parse_ipv69_addr(argv[2], &c.pool_start) < 0) {
            fprintf(stderr, "pool_start invalido\n");
            return 1;
        }
    if (argc > 3 && strcmp(argv[3], "--raw") && strcmp(argv[3], "--allow") &&
        strcmp(argv[3], "--secret"))
        if (parse_ipv69_addr(argv[3], &c.pool_end) < 0) {
            fprintf(stderr, "pool_end invalido\n");
            return 1;
        }
    if (argc > 4 && strcmp(argv[4], "--raw") && strcmp(argv[4], "--allow") &&
        strcmp(argv[4], "--secret")) {
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
            if (c.n_allow >= MAX_ALLOW) {
                fprintf(stderr, "allow: limite %d\n", MAX_ALLOW);
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
        } else if (!strcmp(argv[i], "--secret") && i + 1 < argc) {
            const char *hex = argv[++i];
            size_t hl = strlen(hex);
            if (hl % 2 || hl / 2 > sizeof(c.secret)) {
                fprintf(stderr, "secret: hex par <= 64 chars\n");
                return 1;
            }
            c.secret_len = (int)(hl / 2);
            for (int j = 0; j < c.secret_len; j++) {
                unsigned v;
                sscanf(hex + 2 * j, "%2x", &v);
                c.secret[j] = (uint8_t)v;
            }
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
    printf("af69d: allow=%d mac(s)%s, secret=%s\n",
           c.n_allow, c.n_allow ? "" : " (todos)",
           c.secret_len ? "sim (HMAC)" : "nao");

    for (;;) {
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
        if (!token_check(&c, buf, plen, mac)) {
            printf("af69d: %s token HMAC invalido -> ignorado\n", ms);
            continue;
        }

        if (buf[0] == IPV69_CTRL_DHCP_DISCOVER) {
            size_t olen = sizeof(offer);
            addr = lease_alloc(&c, mac, now);
            if (!addr) {
                printf("af69d: pool cheio, DISCOVER de %s ignorado\n", ms);
                continue;
            }
            offer[0] = IPV69_CTRL_DHCP_OFFER;
            memcpy(offer + 1, mac, 6);
            put_addr40(offer + 7, addr);
            put_be32(offer + 12, c.lease_sec);
            olen = 16 + token_append(&c, mac, offer + 16);
            send_ctrl(&c, offer, olen, mac);
            printf("af69d: DISCOVER %s -> OFFER %016llx\n",
                   ms, (unsigned long long)addr);
        } else if (buf[0] == IPV69_CTRL_DHCP_REQUEST) {
            size_t alen = sizeof(ack);
            if (plen < 12 + (c.secret_len ? IPV69_TOKEN_LEN : 0))
                continue;
            addr = get_addr40(buf + 7);
            if (lease_addr_taken(&c, addr, now) &&
                (!lease_find(&c, mac) || lease_find(&c, mac)->addr != addr)) {
                printf("af69d: REQUEST %016llx de MAC estranho -> negado\n",
                       (unsigned long long)addr);
                continue;           /* no ACK: client restarts DISCOVER */
            }
            struct lease *l = lease_find(&c, mac);
            if (!l) {               /* fresh request without discover */
                addr = lease_alloc(&c, mac, now);
                if (!addr)
                    continue;
            } else {
                l->expiry = now + c.lease_sec;
            }
            ack[0] = IPV69_CTRL_DHCP_ACK;
            memcpy(ack + 1, mac, 6);
            put_addr40(ack + 7, addr);
            put_be32(ack + 12, c.lease_sec);
            alen = 16 + token_append(&c, mac, ack + 16);
            send_ctrl(&c, ack, alen, mac);
            binding_update(mac, addr, c.lease_sec, 0);
            printf("af69d: REQUEST %s -> ACK %016llx\n",
                   ms, (unsigned long long)addr);
        } else {                    /* RELEASE */
            addr = plen >= 12 ? get_addr40(buf + 7) : 0;
            lease_release(&c, mac, addr);
            if (addr)
                binding_update(mac, addr, 0, 1);
            printf("af69d: RELEASE %s %016llx\n",
                   ms, (unsigned long long)addr);
        }
    }
    return 0;
}
