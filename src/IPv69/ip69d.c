/* ip69d - IPv69 interface daemon.
 *
 * Owns a 40-bit address on behalf of the machine: runs the DHCP69
 * client on a real interface, keeps the address bound to a socket
 * (so it survives any single process), brings a TAP interface up
 * (ip69-0) and answers queries over a local unix socket.
 *
 * Usage: ip69d <ifname|ifindex> [--tap NAME] [--raw] [--sock PATH]
 *   --tap  TAP interface name (default ip69-0)
 *   --raw  force AF_PACKET (needed when the AF_69 module is absent)
 *   --sock unix socket path (default /tmp/ip69.sock)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include "IPv69/af69.h"
#include "IPv69/header.h"
#include "IPv69/parse.h"
#include "IPv69/tweetnacl.h"

#define BCAST_MAC { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
#define DHCP_TIMEOUT_MS 3000

struct lease {
    uint64_t addr;
    uint32_t lease_sec;
    time_t expiry;
};

static volatile int g_renew = 0;

static void on_sigusr1(int sig) { (void)sig; g_renew = 1; }

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

/* ---- TAP ------------------------------------------------------------ */

static int tap_create(const char *name)
{
    int fd = open("/dev/net/tun", O_RDWR);
    struct ifreq ifr;

    if (fd < 0) { perror("open /dev/net/tun"); return -1; }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) { perror("TUNSETIFF"); close(fd); return -1; }
    return fd;
}

static void tap_up(const char *name)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;

    if (fd < 0) return;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        ioctl(fd, SIOCSIFFLAGS, &ifr);
    }
    close(fd);
}

static void iface_mac(const char *name, uint8_t mac[6])
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;

    if (fd < 0) return;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
}

/* ---- DHCP69 client (raw AF_PACKET path) ------------------------------ */

struct dhcp_raw {
    int fd;
    int ifindex;
    uint8_t mac[6];
};

static int dhcp_raw_open(struct dhcp_raw *d, const char *ifname)
{
    d->fd = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_IPV69));
    if (d->fd < 0) { perror("socket(AF_PACKET)"); return -1; }
    d->ifindex = if_nametoindex(ifname);
    if (!d->ifindex) { perror("if_nametoindex"); return -1; }
    iface_mac(ifname, d->mac);
    struct sockaddr_ll sll = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETHERTYPE_IPV69),
        .sll_ifindex = d->ifindex,
    };
    if (bind(d->fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind"); return -1;
    }
    struct timeval tv = { .tv_sec = 0, .tv_usec = DHCP_TIMEOUT_MS * 1000 };
    setsockopt(d->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return 0;
}

static int dhcp_raw_send(struct dhcp_raw *d, const uint8_t *pkt, size_t plen)
{
    const uint8_t bcast[6] = BCAST_MAC;
    uint8_t frame[1600];
    struct ethernet_header *eth = (struct ethernet_header *)frame;
    struct ipv69_header *h = (struct ipv69_header *)(frame + 14);
    struct sockaddr_ll sll;

    memset(frame, 0, sizeof(frame));
    memcpy(eth->dst_mac, bcast, 6);
    memcpy(eth->src_mac, d->mac, 6);
    eth->ethertype = htons(ETHERTYPE_IPV69);
    memset(h, 0, IPV69_HEADER_LEN);
    h->ver_traffic = (IPV69_VERSION << 4) | IPV69_TRAFFIC_CLASS;
    wr_be16(&h->payload_len, plen);
    h->next_header = IPV69_NEXT_CONTROL;
    h->hop_limit = 64;
    put_addr40(h->source, 0);
    put_addr40(h->dest, 0xFFFFFFFFFFULL);
    memcpy(frame + 14 + IPV69_HEADER_LEN, pkt, plen);

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETHERTYPE_IPV69);
    sll.sll_ifindex = d->ifindex;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, bcast, 6);
    return sendto(d->fd, frame, 14 + IPV69_HEADER_LEN + plen, 0,
                  (struct sockaddr *)&sll, sizeof(sll));
}

/* wait for a DHCP control reply whose payload MAC matches ours */
static ssize_t dhcp_raw_recv(struct dhcp_raw *d, uint8_t *buf, size_t bufsz)
{
    ssize_t n;

    for (;;) {
        n = recv(d->fd, buf, bufsz, 0);
        if (n < 14 + IPV69_HEADER_LEN + 7)
            return -1;
        {
            const struct ipv69_header *h =
                (const struct ipv69_header *)(buf + 14);
            if (h->next_header != IPV69_NEXT_CONTROL)
                continue;
            if (!memcmp(buf + 14 + IPV69_HEADER_LEN + 1, d->mac, 6)) {
                memmove(buf, buf + 14 + IPV69_HEADER_LEN,
                        n - 14 - IPV69_HEADER_LEN);
                return n - 14 - IPV69_HEADER_LEN;
            }
        }
    }
}

/* ---- DHCP69 client (AF_69 socket path) ------------------------------- */

struct dhcp_af69 {
    int fd;
    int ifindex;
};

static int dhcp_af69_open(struct dhcp_af69 *d, const char *ifname)
{
    d->fd = socket(AF_69, SOCK_DGRAM, 0);
    if (d->fd < 0) return -1;
    d->ifindex = if_nametoindex(ifname);
    struct sockaddr_69 sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_family = AF_69;
    sa.ifindex = d->ifindex;
    if (bind(d->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        return -1;
    struct timeval tv = { .tv_sec = 0, .tv_usec = DHCP_TIMEOUT_MS * 1000 };
    setsockopt(d->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return 0;
}

static int dhcp_af69_send(struct dhcp_af69 *d, const uint8_t *pkt, size_t plen)
{
    struct sockaddr_69 sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_family = AF_69;
    sa.ifindex = d->ifindex;
    sa.dst = 0xFFFFFFFFFFULL;   /* broadcast */
    sa.next_header = IPV69_NEXT_CONTROL;
    return sendto(d->fd, pkt, plen, 0, (struct sockaddr *)&sa, sizeof(sa));
}

static ssize_t dhcp_af69_recv(struct dhcp_af69 *d, uint8_t *buf, size_t bufsz,
                              const uint8_t *mac)
{
    ssize_t n;

    for (;;) {
        n = recv(d->fd, buf, bufsz, 0);
        if (n <= 0)
            return -1;
        if (buf[0] == IPV69_CTRL_DHCP_OFFER ||
            buf[0] == IPV69_CTRL_DHCP_ACK) {
            if (n >= 7 && !memcmp(buf + 1, mac, 6))
                return n;
        }
    }
}

/* ---- lease acquisition (either transport) ---------------------------- */

struct transport {
    int mode;                 /* 0 = AF_69, 1 = raw */
    int fd;
    int ifindex;
    uint8_t mac[6];
    const char *ifname_s;
    uint8_t sk[64];           /* Ed25519 signing key (optional) */
    int has_sk;
    uint8_t server_pub[32];   /* validate OFFER/ACK (optional) */
    int has_server_pub;
};

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

/* sign `plen` bytes at msg (type..lease); append pub + sig */
static size_t sign_msg(const struct transport *t, uint8_t *msg, size_t plen)
{
    uint8_t *pub = msg + plen;
    uint8_t *sig = pub + 32;
    uint8_t tmp[64 + 16];
    unsigned long long slen;

    if (!t->has_sk)
        return plen;
    memcpy(pub, t->sk + 32, 32);
    crypto_sign(tmp, &slen, msg, plen, t->sk);
    memcpy(sig, tmp, 64);
    return plen + 32 + 64;
}

/* validate a signed reply (OFFER/ACK) with the server pubkey */
static int check_reply(const struct transport *t, const uint8_t *msg,
                       size_t plen)
{
    unsigned char sm[64 + 16], m[64 + 16];
    unsigned long long mlen;
    const uint8_t *spub, *ssig;
    size_t body;

    if (!t->has_server_pub)
        return 1;
    if (plen < 16 + 32 + 64)
        return 0;
    body = plen - 32 - 64;
    spub = msg + body;
    ssig = spub + 32;
    if (memcmp(spub, t->server_pub, 32))
        return 0;
    memcpy(sm, ssig, 64);
    memcpy(sm + 64, msg, body);
    return crypto_sign_open(m, &mlen, sm, 64 + body, t->server_pub) == 0;
}

static int dhcp_acquire(struct transport *t, struct lease *l, int force_raw)
{
    uint8_t discover[1 + 6 + 32 + 64], req[1 + 6 + 5 + 32 + 64], buf[1600];
    size_t dlen, rlen;
    ssize_t n;

    discover[0] = IPV69_CTRL_DHCP_DISCOVER;
    memcpy(discover + 1, t->mac, 6);
    dlen = 7;

    if (force_raw) {
        struct dhcp_raw dr;
        if (t->fd < 0) {
            if (dhcp_raw_open(&dr, t->ifname_s) < 0)
                return -1;
            t->fd = dr.fd;
            memcpy(t->mac, dr.mac, 6);
            memcpy(discover + 1, t->mac, 6);
        } else {
            dr.fd = t->fd;
            dr.ifindex = t->ifindex;
            memcpy(dr.mac, t->mac, 6);
        }
        t->mode = 1;
        dlen = sign_msg(t, discover, dlen);
        if (dhcp_raw_send(&dr, discover, dlen) < 0) {
            perror("send DISCOVER"); return -1;
        }
        n = dhcp_raw_recv(&dr, buf, sizeof(buf));
    } else {
        struct dhcp_af69 da;
        if (t->fd < 0) {
            if (dhcp_af69_open(&da, t->ifname_s) < 0) {
                /* no AF_69 in this kernel: fall back to raw */
                return dhcp_acquire(t, l, 1);
            }
            t->fd = da.fd;
        } else {
            da.fd = t->fd;
            da.ifindex = t->ifindex;
        }
        t->mode = 0;
        iface_mac(t->ifname_s, t->mac);
        memcpy(discover + 1, t->mac, 6);
        dlen = sign_msg(t, discover, dlen);
        if (dhcp_af69_send(&da, discover, dlen) < 0) {
            perror("send DISCOVER"); return -1;
        }
        n = dhcp_af69_recv(&da, buf, sizeof(buf), t->mac);
    }
    if (n < 16 || buf[0] != IPV69_CTRL_DHCP_OFFER) {
        fprintf(stderr, "ip69d: OFFER timeout\n");
        return -1;
    }
    if (!check_reply(t, buf, (size_t)n)) {
        fprintf(stderr, "ip69d: OFFER assinatura invalida\n");
        return -1;
    }
    l->addr = get_addr40(buf + 7);
    l->lease_sec = ((uint32_t)buf[12] << 24) | ((uint32_t)buf[13] << 16) |
                   ((uint32_t)buf[14] << 8) | buf[15];
    l->expiry = time(NULL) + l->lease_sec;

    req[0] = IPV69_CTRL_DHCP_REQUEST;
    memcpy(req + 1, t->mac, 6);
    put_addr40(req + 7, l->addr);
    rlen = 12;
    if (t->mode == 1) {
        struct dhcp_raw dr = { .fd = t->fd, .ifindex = t->ifindex };
        memcpy(dr.mac, t->mac, 6);
        rlen = sign_msg(t, req, rlen);
        dhcp_raw_send(&dr, req, rlen);
        n = dhcp_raw_recv(&dr, buf, sizeof(buf));
    } else {
        struct dhcp_af69 da = { .fd = t->fd, .ifindex = t->ifindex };
        rlen = sign_msg(t, req, rlen);
        dhcp_af69_send(&da, req, rlen);
        n = dhcp_af69_recv(&da, buf, sizeof(buf), t->mac);
    }
    if (n < 16 || buf[0] != IPV69_CTRL_DHCP_ACK) {
        fprintf(stderr, "ip69d: ACK timeout\n");
        return -1;
    }
    if (!check_reply(t, buf, (size_t)n)) {
        fprintf(stderr, "ip69d: ACK assinatura invalida\n");
        return -1;
    }
    l->expiry = time(NULL) + l->lease_sec;
    /* keep the socket bound to the (possibly renewed) address */
    if (t->mode == 0) {
        struct sockaddr_69 sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_family = AF_69;
        sa.ifindex = t->ifindex;
        sa.src = l->addr;
        bind(t->fd, (struct sockaddr *)&sa, sizeof(sa));
    }
    printf("ip69d: address %016llx (lease %us)\n",
           (unsigned long long)l->addr, l->lease_sec);
    return 0;
}

/* ---- control socket -------------------------------------------------- */

static int sock_create(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sun;

    if (fd < 0) return -1;
    unlink(path);
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, path, sizeof(sun.sun_path) - 1);
    if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0 ||
        listen(fd, 4) < 0) {
        perror("unix socket"); close(fd); return -1;
    }
    return fd;
}

static void sock_serve(int sfd, const struct transport *t,
                       const struct lease *l, const char *tapname)
{
    int cfd = accept(sfd, NULL, NULL);
    char cmd[64];
    ssize_t n;
    time_t now = time(NULL);
    long remain = l->expiry - now;

    if (cfd < 0) return;
    n = read(cfd, cmd, sizeof(cmd) - 1);
    if (n > 0) {
        cmd[n] = 0;
        if (!strncmp(cmd, "renew", 5)) {
            g_renew = 1;
            dprintf(cfd, "renew requested\n");
        } else if (!strncmp(cmd, "lease", 5)) {
            dprintf(cfd, "%ld\n", remain);
        } else {                    /* addr show */
            dprintf(cfd,
                    "%d: %s: <BROADCAST,UP,LOWER_UP> mtu 1500 state UP\n"
                    "    inet69 %016llx/40 brd ffffffffff scope global dynamic\n"
                    "       valid_lft %ldsec preferred_lft %ldsec\n"
                    "    link ifindex %d mode %s\n",
                    1, tapname, (unsigned long long)l->addr, remain, remain,
                    t->ifindex, t->mode == 0 ? "af69" : "raw");
        }
    }
    close(cfd);
}

/* ---- main ------------------------------------------------------------ */

int main(int argc, char **argv)
{
    const char *ifname = NULL, *tapname = "ip69-0", *sockpath = "/tmp/ip69.sock";
    int force_raw = 0;
    struct transport t;
    struct lease l;
    struct pollfd pfd[2];
    int tapfd = -1, sfd;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--raw")) force_raw = 1;
        else if (!strcmp(argv[i], "--tap") && i + 1 < argc) tapname = argv[++i];
        else if (!strcmp(argv[i], "--sock") && i + 1 < argc) sockpath = argv[++i];
        else if (!strcmp(argv[i], "--key") && i + 1 < argc) {
            uint8_t seed[32];
            if (hex_decode(argv[++i], seed, 32) != 32) {
                fprintf(stderr, "key: privkey invalida (32 bytes hex)\n");
                return 1;
            }
            memcpy(t.sk, seed, 32);
            crypto_sign_seed_to_pk(t.sk + 32, seed);
            t.has_sk = 1;
        } else if (!strcmp(argv[i], "--server-pub") && i + 1 < argc) {
            if (hex_decode(argv[++i], t.server_pub, 32) != 32) {
                fprintf(stderr, "server-pub: pubkey invalida (32 bytes hex)\n");
                return 1;
            }
            t.has_server_pub = 1;
        } else if (!ifname) ifname = argv[i];
        else {
            fprintf(stderr,
                    "Usage: %s <ifname|ifindex> [--tap NAME] [--raw] [--sock PATH]\n"
                    "       [--key PRIV_HEX] [--server-pub PUB_HEX]\n",
                    argv[0]);
            return 1;
        }
    }
    if (!ifname) {
        fprintf(stderr, "Usage: %s <ifname|ifindex> [--tap NAME] [--raw] [--sock PATH]\n",
                argv[0]);
        return 1;
    }

    setvbuf(stdout, NULL, _IONBF, 0);
    fprintf(stderr, "ip69d: starting ifname=%s raw=%d\n", ifname, force_raw);
    memset(&t, 0, sizeof(t));
    t.fd = -1;
    int inum = atoi(ifname);
    t.ifindex = inum ? inum : (int)if_nametoindex(ifname);
    if (!t.ifindex) { perror("if_nametoindex"); return 1; }
    /* keep the name too: raw path reopens the socket on renew */
    t.ifname_s = ifname;

    signal(SIGUSR1, on_sigusr1);
    tapfd = tap_create(tapname);
    if (tapfd >= 0)
        tap_up(tapname);
    else
        fprintf(stderr, "ip69d: no TAP (address still held by socket)\n");

    if (dhcp_acquire(&t, &l, force_raw) < 0)
        return 1;

    sfd = sock_create(sockpath);
    if (sfd < 0) return 1;
    printf("ip69d: %s inet69 %016llx (sock %s)\n", tapname,
           (unsigned long long)l.addr, sockpath);

    pfd[0].fd = sfd;  pfd[0].events = POLLIN;
    pfd[1].fd = t.fd; pfd[1].events = POLLIN;
    for (;;) {
        time_t now = time(NULL);
        long rem = l.expiry - now;
        int to = (int)(rem / 2) * 1000;
        if (to < 1000) to = 1000;
        if (g_renew || rem < (time_t)l.lease_sec / 3) {
            g_renew = 0;
            printf("ip69d: renewing lease...\n");
            if (dhcp_acquire(&t, &l, force_raw) < 0)
                fprintf(stderr, "ip69d: renew failed, will retry\n");
        }
        if (poll(pfd, 2, to) > 0) {
            if (pfd[0].revents & POLLIN)
                sock_serve(sfd, &t, &l, tapname);
            if (pfd[1].revents & POLLIN) {
                uint8_t buf[1600];
                if (t.mode == 0)
                    recv(t.fd, buf, sizeof(buf), 0);
                else
                    recv(t.fd, buf, sizeof(buf), 0);
            }
        }
    }
    return 0;
}
