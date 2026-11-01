/* ip69d - IPv69 bring-up daemon (net up / tun).
 *
 * Brings the device up and keeps it up: runs the DHCP69 client on a
 * real interface with retry + backoff, keeps the lease alive (renew on
 * timer or SIGUSR1), optionally creates a TAP interface (--tap) and
 * answers lease/renew/status queries over a local unix socket.
 *
 * Usage: ipv69 <net up|tun> <ifname|ifindex> [--tap NAME] [--sock PATH]
 *   --tap  TAP interface name (optional: no TAP by default)
 *   --sock unix socket path (default /tmp/ip69.sock)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include "IPv69/l2.h"
#include "IPv69/plat.h"
#include "IPv69/keyring.h"
#include "IPv69/mac1.h"
#include "ed25519.h"

#define BCAST_MAC { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
#define DHCP_TIMEOUT_MS 3000
#define DHCP_ATTEMPTS 3

struct lease {
    uint64_t addr;
    uint32_t lease_sec;
    time_t expiry;
};

static volatile int g_renew = 0;

static void on_sigusr1(int sig) { (void)sig; g_renew = 1; }



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

/* wait for a DHCP control reply whose payload MAC matches ours, up to
 * timeout_ms (SO_RCVTIMEO is set per call so retries can back off) */
static ssize_t dhcp_raw_recv(struct dhcp_raw *d, uint8_t *buf, size_t bufsz,
                             int timeout_ms)
{
    ssize_t n;
    struct timeval tv = { timeout_ms / 1000,
                          (timeout_ms % 1000) * 1000 };

    setsockopt(d->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
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

/* ---- lease acquisition ----------------------------------------------- */

struct transport {
    int fd;
    int ifindex;
    uint8_t mac[6];
    const char *ifname_s;
    uint8_t sk[64];           /* Ed25519 signing key (optional) */
    int has_sk;
    uint8_t server_pub[32];   /* validate OFFER/ACK (optional) */
    int has_server_pub;
};

/* sign `plen` bytes at msg (type..lease); append pub + sig */
static size_t sign_msg(const struct transport *t, uint8_t *msg, size_t plen)
{
    uint8_t *pub = msg + plen;
    uint8_t *sig = pub + 32;

    if (!t->has_sk)
        return plen;
    memcpy(pub, t->sk + 32, 32);
    if (ed25519_sign(sig, msg, plen, t->sk) < 0)
        return plen;
    return plen + 32 + 64;
}

/* validate a signed reply (OFFER/ACK) with the server pubkey */
static int check_reply(const struct transport *t, const uint8_t *msg,
                       size_t plen)
{
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
    return ed25519_verify(msg, body, ssig, t->server_pub) == 0;
}

/* one DISCOVER->OFFER->REQUEST->ACK round with retry + backoff on each
 * wait (WireGuard REKEY_TIMEOUT discipline, same as dhcp_discover).
 * Every outgoing control carries the mac1 pre-auth tag the dhcpd
 * requires before any Ed25519 work. Returns 0 with *l filled. */
static int dhcp_acquire(struct transport *t, struct lease *l)
{
    uint8_t discover[1 + 6 + 32 + 64 + MAC1_LEN];
    uint8_t req[1 + 6 + 5 + 32 + 64 + MAC1_LEN];
    uint8_t buf[1600], mkey[32];
    size_t dlen, rlen;
    ssize_t n;
    struct dhcp_raw dr;
    int offer_ok = 0, ack_ok = 0;

    if (t->fd < 0) {
        if (dhcp_raw_open(&dr, t->ifname_s) < 0)
            return -1;
        t->fd = dr.fd;
        memcpy(t->mac, dr.mac, 6);
    } else {
        dr.fd = t->fd;
        dr.ifindex = t->ifindex;
        memcpy(dr.mac, t->mac, 6);
    }

    /* mac1 key is bound to the frame dst (broadcast for DHCP): the
       server re-derives it from the received frame, zero config */
    mac1_key(IPV69_BCAST_ADDR, mkey);

    /* DISCOVER [7][mac] + pub + sig + mac1 */
    discover[0] = IPV69_CTRL_DHCP_DISCOVER;
    memcpy(discover + 1, t->mac, 6);
    dlen = sign_msg(t, discover, 7);
    mac1_compute(mkey, discover, dlen, discover + dlen);
    dlen += MAC1_LEN;
    if (dhcp_raw_send(&dr, discover, dlen) < 0) {
        perror("send DISCOVER"); return -1;
    }

    for (int attempt = 0; attempt < DHCP_ATTEMPTS && !offer_ok; attempt++) {
        if (attempt > 0) {
            plat_sleep_ms(200 * attempt);
            dhcp_raw_send(&dr, discover, dlen);     /* re-send DISCOVER */
        }
        uint64_t wait = (uint64_t)(1000 << attempt) + rand() % 200;
        for (;;) {
            n = dhcp_raw_recv(&dr, buf, sizeof(buf), (int)wait);
            if (n <= 0) break;                      /* timeout: retry */
            if (n < 16 || buf[0] != IPV69_CTRL_DHCP_OFFER) continue;
            if (memcmp(buf + 1, t->mac, 6)) continue;
            if (!check_reply(t, buf, (size_t)n)) {
                fprintf(stderr, "ip69d: OFFER signature invalid\n");
                return -1;
            }
            l->addr = get_addr40(buf + 7);
            l->lease_sec = ((uint32_t)buf[12] << 24) | ((uint32_t)buf[13] << 16) |
                           ((uint32_t)buf[14] << 8) | buf[15];
            l->expiry = time(NULL) + l->lease_sec;
            offer_ok = 1;
            break;
        }
    }
    if (!offer_ok) {
        fprintf(stderr, "ip69d: OFFER timeout\n");
        return -1;
    }

    /* REQUEST [9][mac][addr5] + pub + sig + mac1 */
    req[0] = IPV69_CTRL_DHCP_REQUEST;
    memcpy(req + 1, t->mac, 6);
    put_addr40(req + 7, l->addr);
    rlen = sign_msg(t, req, 12);
    mac1_compute(mkey, req, rlen, req + rlen);
    rlen += MAC1_LEN;
    if (dhcp_raw_send(&dr, req, rlen) < 0) {
        perror("send REQUEST"); return -1;
    }

    for (int attempt = 0; attempt < DHCP_ATTEMPTS && !ack_ok; attempt++) {
        if (attempt > 0) {
            plat_sleep_ms(200 * attempt);
            dhcp_raw_send(&dr, req, rlen);          /* re-send REQUEST */
        }
        uint64_t wait = (uint64_t)(1000 << attempt) + rand() % 200;
        for (;;) {
            n = dhcp_raw_recv(&dr, buf, sizeof(buf), (int)wait);
            if (n <= 0) break;
            if (n < 16 || buf[0] != IPV69_CTRL_DHCP_ACK) continue;
            if (memcmp(buf + 1, t->mac, 6)) continue;
            if (!check_reply(t, buf, (size_t)n)) {
                fprintf(stderr, "ip69d: ACK signature invalid\n");
                return -1;
            }
            l->expiry = time(NULL) + l->lease_sec;
            ack_ok = 1;
            break;
        }
    }
    if (!ack_ok) {
        fprintf(stderr, "ip69d: ACK timeout\n");
        return -1;
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
                       const struct lease *l, const char *showname)
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
                    "    link ifindex %d mode raw\n",
                    1, showname, (unsigned long long)l->addr, remain, remain,
                    t->ifindex);
        }
    }
    close(cfd);
}

/* ---- main ------------------------------------------------------------ */

int cmd_tun(int argc, char **argv)
{
    const char *ifname = NULL, *tapname = NULL, *sockpath = "/tmp/ip69.sock";
    struct transport t;
    struct lease l;
    struct pollfd pfd[2];
    int tapfd = -1, sfd;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--tap") && i + 1 < argc) tapname = argv[++i];
        else if (!strcmp(argv[i], "--sock") && i + 1 < argc) sockpath = argv[++i];
        else if (!strcmp(argv[i], "--key") && i + 1 < argc) {
            uint8_t seed[32];
            if (hex_decode(argv[++i], seed, 32) != 32) {
                fprintf(stderr, "key: invalid private key (32 bytes hex)\n");
                return 1;
            }
            memcpy(t.sk, seed, 32);
            ed25519_seed_to_pub(t.sk + 32, seed);
            t.has_sk = 1;
        } else if (!strcmp(argv[i], "--server-pub") && i + 1 < argc) {
            if (hex_decode(argv[++i], t.server_pub, 32) != 32) {
                fprintf(stderr, "server-pub: invalid pubkey (32 bytes hex)\n");
                return 1;
            }
            t.has_server_pub = 1;
        } else if (!ifname) ifname = argv[i];
        else {
            fprintf(stderr,
                    "Usage: ipv69 <net up|tun> <ifname|ifindex> [--tap NAME]\n"
                    "       [--sock PATH] [--key PRIV_HEX] [--server-pub PUB_HEX]\n");
            return 1;
        }
    }
    if (!ifname) {
        fprintf(stderr,
                "Usage: ipv69 <net up|tun> <ifname|ifindex> [--tap NAME]\n"
                "       [--sock PATH] [--key PRIV_HEX] [--server-pub PUB_HEX]\n");
        return 1;
    }

    setvbuf(stdout, NULL, _IONBF, 0);
    fprintf(stderr, "ip69d: starting ifname=%s\n", ifname);
    memset(&t, 0, sizeof(t));
    t.fd = -1;
    int inum = atoi(ifname);
    t.ifindex = inum ? inum : (int)if_nametoindex(ifname);
    if (!t.ifindex) { perror("if_nametoindex"); return 1; }
    /* keep the name too: raw path reopens the socket on renew */
    t.ifname_s = ifname;

    signal(SIGUSR1, on_sigusr1);

    if (!t.has_sk) {
        /* auto: load/create the ~/.hosts69 keyring (same identity the
           rest of the stack uses — dhcpd allowlists match this key) */
        char kdir[256], kpath[512], kpub[512], comment[128];
        uint8_t pub[32];
        keyring_paths(kdir, sizeof(kdir), kpath, sizeof(kpath),
                      kpub, sizeof(kpub));
        if (keyring_load_or_create(kpath, kpub, t.sk, pub, comment,
                                   sizeof(comment)) < 0) {
            fprintf(stderr, "ip69d: could not load/create key at %s\n", kpath);
            return 1;
        }
        t.has_sk = 1;
    }

    /* the name status shows: the TAP when one was really created
       (tapfd >= 0), the raw ifname otherwise */
    const char *showname = ifname;
    if (tapname) {
        tapfd = tap_create(tapname);
        if (tapfd >= 0) {
            tap_up(tapname);
            showname = tapname;
        } else {
            fprintf(stderr, "ip69d: could not create TAP %s "
                    "(address still held by socket)\n", tapname);
        }
    } else {
        fprintf(stderr, "ip69d: no TAP interface (use --tap NAME to create one)\n");
    }

    if (dhcp_acquire(&t, &l) < 0)
        return 1;

    sfd = sock_create(sockpath);
    if (sfd < 0) return 1;
    /* status shows the TAP name when one exists, the raw ifname otherwise */
    printf("ip69d: %s inet69 %016llx (sock %s)\n",
           showname,
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
            if (dhcp_acquire(&t, &l) < 0)
                fprintf(stderr, "ip69d: renew failed, will retry\n");
        }
        if (poll(pfd, 2, to) > 0) {
            if (pfd[0].revents & POLLIN)
                sock_serve(sfd, &t, &l, showname);
            if (pfd[1].revents & POLLIN) {
                uint8_t buf[1600];
                recv(t.fd, buf, sizeof(buf), 0);  /* drain */
            }
        }
    }
    return 0;
}
