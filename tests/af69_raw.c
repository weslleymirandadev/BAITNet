/* af69_raw - IPv69 (ethertype 0x6969) client over raw L2, no kernel
 * module. For devices whose kernel lacks the AF_69 patch (e.g. stock
 * Android) and for Windows (Npcap backend). Same wire format as the
 * af69.ko module: Ethernet + 32B IPv69 header + payload.
 *
 * The L2 endpoint is the portable l2_* API (l2.c / l2_win.c); the UDP
 * tunnel (--remote) rides on top with plain sockets (plat.h).
 *
 * Usage: af69_raw recv <ifname> [src_addr[:port]]
 *        af69_raw send <ifname> <dst[:port]> <src_port> [payload]
 *        af69_raw ping <ifname> <dst> [payload]   (echo request/reply)
 *        af69_raw dhcp <ifname>                   (lease from DHCP69 server)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include "IPv69/plat.h"
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include "IPv69/af69.h"
#include "IPv69/header.h"
#include "IPv69/parse.h"
#include "IPv69/plat.h"
#include "IPv69/l2.h"
#include "IPv69/mac1.h"
#include "IPv69/keyring.h"
#include "ed25519.h"

/* ---- UDP tunnel backend (--remote gw1,gw2:port) ---------------------- */
#define MAX_GW 4

static sock_t g_udp_fd = SOCK_INVALID;      /* UDP socket (tunnel) */
static l2_handle g_l2;                      /* raw L2 endpoint (local) */
static int g_ifindex = 0;                   /* local ifindex */
static struct sockaddr_storage g_gw[MAX_GW];
static socklen_t g_gwlen[MAX_GW];
static int g_ngw = 0;

/* resolve "host:port[,host:port...]" into the gateway list.
 * Hosts must be numeric IPs (static binary: no DNS at runtime). */
static int gw_parse(const char *list)
{
    char buf[512];
    strncpy(buf, list, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    char *save = NULL;
    for (char *tok = strtok_r(buf, ",", &save);
         tok && g_ngw < MAX_GW; tok = strtok_r(NULL, ",", &save)) {
        char *colon = strrchr(tok, ':');
        if (!colon)
            return -1;
        *colon = 0;
        const char *host = tok;
        int port = atoi(colon + 1);
        struct sockaddr_in sa4;
        struct sockaddr_in6 sa6;
        if (inet_pton(AF_INET, host, &sa4.sin_addr) == 1) {
            sa4.sin_family = AF_INET;
            sa4.sin_port = htons(port);
            memcpy(&g_gw[g_ngw], &sa4, sizeof(sa4));
            g_gwlen[g_ngw] = sizeof(sa4);
        } else if (inet_pton(AF_INET6, host, &sa6.sin6_addr) == 1) {
            sa6.sin6_family = AF_INET6;
            sa6.sin6_port = htons(port);
            memcpy(&g_gw[g_ngw], &sa6, sizeof(sa6));
            g_gwlen[g_ngw] = sizeof(sa6);
        } else {
            return -1;
        }
        g_ngw++;
    }
    return g_ngw > 0 ? 0 : -1;
}

/* QUERY the gateway: where is addr? fills ep on success (P2P direct).
 * Keeps receiving until the matching E69 answer arrives (the socket
 * also sees replicated broadcasts), or the 1s timeout expires. */
static int gw_query(uint64_t addr, struct sockaddr_storage *ep,
                    socklen_t *eplen)
{
    uint8_t q[8] = { 'Q', '6', '9' };
    uint8_t ans[128];
    struct timeval tv = { 1, 0 };

    q[3] = (addr >> 32) & 0xff; q[4] = (addr >> 24) & 0xff;
    q[5] = (addr >> 16) & 0xff; q[6] = (addr >> 8) & 0xff; q[7] = addr & 0xff;
    for (int i = 0; i < g_ngw; i++) {
        sendto(g_udp_fd, (const char *)q, sizeof(q), 0,
               (struct sockaddr *)&g_gw[i], g_gwlen[i]);
    }
    setsockopt(g_udp_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    for (;;) {
        ssize_t n = recvfrom(g_udp_fd, (char *)ans, sizeof(ans), 0,
                             (struct sockaddr *)ep, eplen);
        if (n < 0)
            break;              /* timeout: no answer */
        if (n <= 8 || memcmp(ans, "E69", 3) ||
            memcmp(ans + 3, q + 3, 5))
            continue;           /* replicated frame, not our answer */
        if (ans[8] == '-')
            break;              /* gateway does not know the peer */
        {
            /* endpoint as "ip:port" text after the addr */
            char *hostport = (char *)ans + 8;
            char *colon = strrchr(hostport, ':');
            if (!colon)
                continue;
            *colon = 0;
            int port = atoi(colon + 1);
            struct sockaddr_in sa4;
            struct sockaddr_in6 sa6;
            /* unwrap IPv4-mapped (::ffff:a.b.c.d) from dual-stack gw */
            if (!strncmp(hostport, "::ffff:", 7))
                hostport += 7;
            if (inet_pton(AF_INET, hostport, &sa4.sin_addr) == 1) {
                sa4.sin_family = AF_INET;
                sa4.sin_port = htons(port);
                memcpy(ep, &sa4, sizeof(sa4));
                *eplen = sizeof(sa4);
                return 1;
            }
            if (inet_pton(AF_INET6, hostport, &sa6.sin6_addr) == 1) {
                sa6.sin6_family = AF_INET6;
                sa6.sin6_port = htons(port);
                memcpy(ep, &sa6, sizeof(sa6));
                *eplen = sizeof(sa6);
                return 1;
            }
        }
    }
    return 0;
}

/* ---- endpoint: UDP tunnel when --remote, raw L2 otherwise ------------ */

/* open the endpoint. Tunnel mode uses one UDP socket (family of gw[0])
 * and still reads the local MAC via l2_open (the frames carry it). */
static int tun_open(const char *ifname, int *ifindex, uint8_t *src_mac)
{
    if (g_ngw > 0) {
        g_udp_fd = socket(g_gw[0].ss_family, SOCK_DGRAM, 0);
        if (g_udp_fd == SOCK_INVALID) { perror_sock("socket(UDP)"); return -1; }
        l2_handle probe;
        if (l2_open(ifname, &probe, ifindex, src_mac) == 0)
            l2_close(probe);            /* local MAC for the frames */
        return 0;
    }
    if (l2_open(ifname, &g_l2, ifindex, src_mac) < 0)
        return -1;
    g_ifindex = *ifindex;
    return 0;
}

/* send one frame: to every gateway (failover) in tunnel mode, else L2. */
static int tun_send(const uint8_t *dst_mac, const uint8_t *frame, size_t len)
{
    if (g_ngw > 0) {
        int sent = 0;
        for (int i = 0; i < g_ngw; i++)
            if (sendto(g_udp_fd, (const char *)frame, len, 0,
                       (struct sockaddr *)&g_gw[i], g_gwlen[i]) >= 0)
                sent++;
        return sent > 0 ? (int)len : -1;
    }
    return l2_send(g_l2, g_ifindex, dst_mac, frame, len);
}

/* receive one frame, waiting up to timeout_ms (0 = forever).
 * Returns the frame length, 0 on timeout, -1 on error. */
static ssize_t tun_recv(uint8_t *frame, size_t maxlen, int timeout_ms)
{
    if (g_ngw > 0) {
        struct timeval tv = { timeout_ms / 1000,
                              (timeout_ms % 1000) * 1000 };
        setsockopt(g_udp_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
        ssize_t n = recvfrom(g_udp_fd, (char *)frame, maxlen, 0, NULL, NULL);
        return n < 0 ? 0 : n;           /* timeout counts as "nothing" */
    }
    return l2_recv(g_l2, frame, maxlen, timeout_ms);
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

/* silent DHCP69 lease acquisition: DISCOVER -> OFFER -> REQUEST -> ACK.
 * Used by `send`/`recv` to discover the real src address (anti-spoofing:
 * the src is never user-chosen; it is the lease the server actually gave
 * this MAC). Returns 0 with *out_addr set, -1 on timeout/failure. */
static int dhcp_discover(const uint8_t src_mac[6],
                         const uint8_t *sk, int has_sk,
                         const uint8_t *server_pub, int has_server_pub,
                         uint64_t *out_addr)
{
    const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t frame[1600], pkt[1 + 6 + 5 + 4 + 32 + 64 + MAC1_LEN];
    uint64_t addr = 0;
    ssize_t n;
    size_t len;
    const size_t SIGSZ = has_server_pub ? (32 + 64) : 0;
    uint8_t mkey[32];

    /* mac1 pre-auth filter key: bound to the frame's dst (broadcast for
       DHCP) — the server re-derives it from the received frame. */
    mac1_key(IPV69_BCAST_ADDR, mkey);

    /* DISCOVER [7][mac] + pub + sig + mac1 */
    pkt[0] = IPV69_CTRL_DHCP_DISCOVER;
    memcpy(pkt + 1, src_mac, 6);
    size_t dlen = 7;
    if (has_sk) {
        memcpy(pkt + 7, sk + 32, 32);           /* pub */
        ed25519_sign(pkt + 7 + 32, pkt, 7, sk);
        dlen += 32 + 64;
    }
    mac1_compute(mkey, pkt, dlen, pkt + dlen);
    dlen += MAC1_LEN;
    len = build_frame(frame, bcast, src_mac, 0, 0xFFFFFFFFFFULL,
                      IPV69_NEXT_CONTROL, 64, 0, 0, pkt, dlen);
    if (tun_send(bcast, frame, len) < 0)
        return -1;

    /* wait OFFER [8][mac][addr5][lease4] + pub + sig */
    for (;;) {
        n = tun_recv(frame, sizeof(frame), 3000);
        if (n <= 0) return -1;                  /* timeout */
        if (n < 14 + IPV69_HEADER_LEN + 16 + (ssize_t)SIGSZ) continue;
        const struct ipv69_header *h = (const struct ipv69_header *)(frame + 14);
        const uint8_t *p = frame + 14 + IPV69_HEADER_LEN;
        if (h->next_header != IPV69_NEXT_CONTROL || p[0] != IPV69_CTRL_DHCP_OFFER)
            continue;
        if (memcmp(p + 1, src_mac, 6)) continue;
        if (has_server_pub) {
            const uint8_t *spub = p + 16, *ssig = p + 16 + 32;
            if (memcmp(spub, server_pub, 32) ||
                ed25519_verify(p, 16, ssig, server_pub) != 0)
                return -1;
        }
        addr = get_addr40(p + 7);
        break;
    }

    /* REQUEST [9][mac][addr5] + pub + sig + mac1 */
    pkt[0] = IPV69_CTRL_DHCP_REQUEST;
    memcpy(pkt + 1, src_mac, 6);
    put_addr40(pkt + 7, addr);
    size_t rlen = 12;
    if (has_sk) {
        memcpy(pkt + 12, sk + 32, 32);
        ed25519_sign(pkt + 12 + 32, pkt, 12, sk);
        rlen += 32 + 64;
    }
    mac1_compute(mkey, pkt, rlen, pkt + rlen);
    rlen += MAC1_LEN;
    len = build_frame(frame, bcast, src_mac, 0, 0xFFFFFFFFFFULL,
                      IPV69_NEXT_CONTROL, 64, 0, 0, pkt, rlen);
    if (tun_send(bcast, frame, len) < 0)
        return -1;

    /* wait ACK [10][mac][addr5][lease4] + pub + sig */
    for (;;) {
        n = tun_recv(frame, sizeof(frame), 3000);
        if (n <= 0) return -1;                  /* timeout */
        if (n < 14 + IPV69_HEADER_LEN + 16 + (ssize_t)SIGSZ) continue;
        const struct ipv69_header *h = (const struct ipv69_header *)(frame + 14);
        const uint8_t *p = frame + 14 + IPV69_HEADER_LEN;
        if (h->next_header != IPV69_NEXT_CONTROL || p[0] != IPV69_CTRL_DHCP_ACK)
            continue;
        if (memcmp(p + 1, src_mac, 6)) continue;
        if (has_server_pub) {
            const uint8_t *spub = p + 16, *ssig = p + 16 + 32;
            if (memcmp(spub, server_pub, 32) ||
                ed25519_verify(p, 16, ssig, server_pub) != 0)
                return -1;
        }
        break;
    }
    *out_addr = addr;
    return 0;
}

/* load the ~/.hosts69 keyring (auto-key) into sk, or generate + print
 * the pub. Returns 0 with has_sk=1 on success. Needed so silent DHCP
 * (send/recv) signs its DISCOVER — the server rejects unsigned ones
 * when it has an allowlist (--peer/--peer-file). */
static int load_auto_key(uint8_t sk[64])
{
    char dir[256], key[512], kpub[512], comment[128];
    uint8_t pub[32];
    keyring_paths(dir, sizeof(dir), key, sizeof(key), kpub, sizeof(kpub));
    if (keyring_load_or_create(key, kpub, sk, pub, comment,
                               sizeof(comment)) < 0) {
        fprintf(stderr, "nao foi possivel carregar/criar chave em %s\n", key);
        return -1;
    }
    return 0;
}

/* interactive DHCP69 client: runs dhcp_discover, prints the flow and
 * holds the address for a few seconds. */
static int dhcp_client(const uint8_t src_mac[6],
                       const uint8_t *sk, int has_sk,
                       const uint8_t *server_pub, int has_server_pub)
{
    uint8_t frame[1600];
    uint64_t addr;
    ssize_t n;
    printf("dhcp: MAC %02x:%02x:%02x:%02x:%02x:%02x%s\n",
           src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
           has_sk ? " (Ed25519)" : "");
    if (dhcp_discover(src_mac, sk, has_sk, server_pub, has_server_pub,
                      &addr) < 0) {
        printf("dhcp: nao foi possivel obter lease (timeout/recusado)\n");
        return 1;
    }
    printf("dhcp: ACK %016llx — configurado!\n", (unsigned long long)addr);

    /* keep receiving for a few seconds to show it works */
    printf("dhcp: bound src=%016llx, ouvindo 5s...\n", (unsigned long long)addr);
    for (;;) {
        n = tun_recv(frame, sizeof(frame), 5000);
        if (n <= 0) break;
        dump_frame(frame, (size_t)n);
    }
    return 0;
}

int cmd_raw(int argc, char **argv)
{
    const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t src_mac[6], frame[1600];
    int ifindex;
    uint8_t sk[64], server_pub[32];
    int has_sk = 0, has_server_pub = 0;

    setvbuf(stdout, NULL, _IONBF, 0);

    /* global options (any position):
       --key PRIV_HEX --server-pub PUB_HEX --remote gw1,gw2:port */
    for (int i = 1; i < argc - 1; i++) {
        if (!strcmp(argv[i], "--key")) {
            uint8_t seed[32];
            if (hex_decode(argv[i + 1], seed, 32) != 32) {
                fprintf(stderr, "key: privkey invalida (32 bytes hex)\n");
                return 1;
            }
            memcpy(sk, seed, 32);
            ed25519_seed_to_pub(sk + 32, seed);
            has_sk = 1;
        } else if (!strcmp(argv[i], "--server-pub")) {
            if (hex_decode(argv[i + 1], server_pub, 32) != 32) {
                fprintf(stderr, "server-pub: pubkey invalida (32 bytes hex)\n");
                return 1;
            }
            has_server_pub = 1;
        } else if (!strcmp(argv[i], "--remote")) {
            if (gw_parse(argv[i + 1]) < 0) {
                fprintf(stderr, "remote: lista de gateways invalida (%s)\n",
                        argv[i + 1]);
                return 1;
            }
        } else {
            continue;
        }
        /* remove the flag and its value from argv */
        memmove(&argv[i], &argv[i + 2], sizeof(char *) * (argc - i - 1));
        argc -= 2;
        i--;
    }

    /* `addr` needs no iface/socket: dispatch before the argc>=3 gate */
    if (!strcmp(argv[1], "addr")) {
        uint8_t sk[64], pub[32], derived[5];
        char cls = 'C';                 /* public by default */
        int do_dad = 0;
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--dad"))
                do_dad = 1;
            else if (!strcmp(argv[i], "--class") && i + 1 < argc) {
                cls = (char)argv[i + 1][0];
                i++;
            }
        }
        if (cls != 'A' && cls != 'B' && cls != 'C' &&
            cls != 'D' && cls != 'E') {
            fprintf(stderr, "addr: classe invalida '%c' (A-E)\n", cls);
            return 1;
        }
        if (load_auto_key(sk) < 0) {
            fprintf(stderr, "addr: sem identidade (ipv69 keygen)\n");
            return 1;
        }
        memcpy(pub, sk + 32, 32);
        ipv69_addr_derive(derived, pub, cls);
        printf("addr: %02x.%02x.%02x.%02x.%02x (derivado da identidade, classe %c)\n",
               derived[0], derived[1], derived[2], derived[3], derived[4], cls);
        if (do_dad) {
            if (argc < 3) {
                fprintf(stderr, "addr --dad: precisa <ifname>\n");
                return 1;
            }
            /* DAD: ND request pro proprio endereco; reply = colisao */
            uint8_t req[1 + 5] = { IPV69_CTRL_ND_REQUEST };
            memcpy(req + 1, derived, 5);
            if (tun_open(argv[2], &ifindex, src_mac) < 0)
                return 1;
            size_t len = build_frame(frame, bcast, src_mac, 0, 0xFFFFFFFFFFULL,
                                     IPV69_NEXT_CONTROL, 64, 0, 0, req, sizeof(req));
            if (tun_send(bcast, frame, len) < 0) {
                perror_sock("sendto(DAD)"); return 1;
            }
            int collision = 0;
            for (;;) {
                ssize_t n = tun_recv(frame, sizeof(frame), 1000);
                if (n <= 0) break;
                if (n >= 14 + IPV69_HEADER_LEN + 1) {
                    const struct ipv69_header *h =
                        (const struct ipv69_header *)(frame + 14);
                    if (h->next_header == IPV69_NEXT_CONTROL &&
                        frame[14 + IPV69_HEADER_LEN] == IPV69_CTRL_ND_REPLY)
                        collision = 1;
                }
            }
            printf("dad: %s\n", collision ? "COLISAO - endereco em uso" : "endereco livre");
        }
        return 0;
    }

    if (argc < 3) {
        fprintf(stderr,
                "Usage: %s recv <ifname> [src_addr[:port]]\n"
                "       %s send <ifname> <dst[:port]> <src_port> [payload]\n"
                "       %s ping <ifname> <dst> [payload]\n"
                "       %s dhcp <ifname> [--key PRIV_HEX] [--server-pub PUB_HEX]\n"
                "  --remote gw:port[,gw:port]  tunnel through a gateway\n"
                "  --key:        your Ed25519 privkey (ipv69 keygen) - signs DHCP msgs\n"
                "  --server-pub: server pubkey - validates OFFER/ACK (rogue-server guard)\n",
                argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    if (tun_open(argv[2], &ifindex, src_mac) < 0) return 1;
    printf("iface=%s ifindex=%d mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
           argv[2], ifindex, src_mac[0], src_mac[1], src_mac[2],
           src_mac[3], src_mac[4], src_mac[5]);

    if (!strcmp(argv[1], "recv")) {
        /* optional bind: recv [ifname] [src_addr[:port]] — without
           an address, it discovers the lease via silent DHCP (local) or
           derives it from the identity (tunnel). */
        uint64_t my_addr = 0;
        uint16_t my_port = 0;
        if (argc > 3 && parse_ipv69_addr_port(argv[3], &my_addr, &my_port) < 0) {
            fprintf(stderr, "recv: src_addr[:porta] invalido\n");
            return 1;
        }
        if (g_ngw > 0 && !my_addr) {
            /* tunnel mode: derive the address from the identity when none
               given, and announce periodically so the gateway learns us */
            uint8_t derived[5];
            if (load_auto_key(sk) == 0) {
                ipv69_addr_derive(derived, sk + 32, 'C');
                my_addr = get_addr40(derived);
                printf("recv: addr derivado da identidade: %016llx (classe C)\n",
                       (unsigned long long)my_addr);
            }
            has_sk = 1;
        } else if (!my_addr) {
            /* local: discover the lease silently (registers the kernel
               binding for this MAC) — the address is never user-chosen.
               Load the auto-key so the DISCOVER is signed. */
            if (!has_sk && load_auto_key(sk) < 0)
                return 1;
            has_sk = 1;
            if (dhcp_discover(src_mac, sk, has_sk,
                              server_pub, has_server_pub, &my_addr) < 0) {
                fprintf(stderr, "recv: sem servidor DHCP na rede local; "
                        "suba um dhcpd ou use --remote\n");
                return 1;
            }
            printf("recv: addr = lease %016llx (auto)\n",
                   (unsigned long long)my_addr);
        }
        if (my_addr)
            printf("bound src=%016llx port=%04x (filtrando)\n",
                   (unsigned long long)my_addr, my_port);
        /* the signed announce needs the identity even with --remote */
        if (g_ngw > 0 && !has_sk) {
            if (load_auto_key(sk) < 0)
                return 1;
            has_sk = 1;
        }
        time_t last_ann = 0;
        for (;;) {
            /* announce: signed ND request for ourselves -> the gateway
               learns our authenticated range (cryptokey routing) */
            if (g_ngw > 0 && my_addr && time(NULL) - last_ann >= 2) {
                uint8_t ann[1 + 5 + 32 + 64] = { IPV69_CTRL_ND_REQUEST };
                put_addr40(ann + 1, my_addr);
                memcpy(ann + 6, sk + 32, 32);
                ed25519_sign(ann + 38, ann, 6, sk);
                size_t l = build_frame(frame, bcast, src_mac, my_addr,
                                       0xFFFFFFFFFFULL, IPV69_NEXT_CONTROL,
                                       64, 0, 0, ann, sizeof(ann));
                tun_send(bcast, frame, l);
                last_ann = time(NULL);
            }
            ssize_t n = tun_recv(frame, sizeof(frame), 2000);
            if (n <= 0)
                continue;       /* timeout tick: announce or keep waiting */
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
        uint16_t dp = 0;
        size_t plen;
        if (argc < 5 || parse_ipv69_addr_port(argv[3], &dst, &dp) < 0) {
            fprintf(stderr, "send: precisa <dst[:porta]> <src_port> [payload]\n");
            return 1;
        }
        const char *data = argc > 5 ? argv[5] : "hello ipv69";
        size_t dlen = strlen(data);
        uint16_t sp = (uint16_t)strtoul(argv[4], NULL, 10);
        if (argc > 6) {
            fprintf(stderr, "send: src manual removido (anti-spoofing) - "
                    "o src agora e descoberto automaticamente\n");
            return 1;
        }
        /* src automatico (anti-spoofing): never user-chosen.
           local: silent DHCP discovers the real lease;
           tunnel: derived from the identity (class C). */
        if (g_ngw > 0) {
            uint8_t derived[5];
            if (load_auto_key(sk) == 0) {
                ipv69_addr_derive(derived, sk + 32, 'C');
                src = get_addr40(derived);
                printf("send: src derivado da identidade: %016llx\n",
                       (unsigned long long)src);
            }
            has_sk = 1;
        } else {
            if (!has_sk && load_auto_key(sk) < 0)
                return 1;
            has_sk = 1;
            if (dhcp_discover(src_mac, sk, has_sk,
                              server_pub, has_server_pub, &src) < 0) {
                fprintf(stderr, "send: sem servidor DHCP na rede local; "
                        "suba um dhcpd ou use --remote\n");
                return 1;
            }
            printf("send: src = lease %016llx (auto)\n",
                   (unsigned long long)src);
        }
        plen = dlen;
        if (g_ngw > 0 && dst != 0xFFFFFFFFFFULL) {
            /* announce first so the gateway knows us (QUERY gate) —
               signed, so the gateway can authenticate our range. Uses
               `af`; the dgram is built AFTER, in its own buffer, so the
               announce does not clobber it. */
            uint8_t ann[1 + 5 + 32 + 64] = { IPV69_CTRL_ND_REQUEST };
            uint8_t af[1600];
            put_addr40(ann + 1, src);
            memcpy(ann + 6, sk + 32, 32);
            ed25519_sign(ann + 38, ann, 6, sk);
            size_t alen = build_frame(af, bcast, src_mac, src,
                                      0xFFFFFFFFFFULL, IPV69_NEXT_CONTROL,
                                      64, 0, 0, ann, sizeof(ann));
            tun_send(bcast, af, alen);
            /* P2P: ask the gateway where dst lives; send direct if known */
            struct sockaddr_storage ep;
            socklen_t eplen = sizeof(ep);
            if (gw_query(dst, &ep, &eplen) > 0) {
                size_t len = build_frame(frame, bcast, src_mac, src, dst,
                                         IPV69_NEXT_DGRAM, 64, sp, dp,
                                         (const uint8_t *)data, plen);
                if (sendto(g_udp_fd, (const char *)frame, len, 0,
                           (struct sockaddr *)&ep, eplen) >= 0) {
                    printf("sent %zu bytes (dgram P2P, dst=%016llx src=%016llx)\n",
                           dlen, (unsigned long long)dst, (unsigned long long)src);
                    return 0;
                }
            }
            /* fallback: relay through the gateway */
        }
        size_t len = build_frame(frame, bcast, src_mac, src, dst, IPV69_NEXT_DGRAM,
                                 64, sp, dp, (const uint8_t *)data, plen);
        if (tun_send(bcast, frame, len) < 0) { perror_sock("sendto"); return 1; }
        printf("sent %zu bytes (dgram, dst=%016llx src=%016llx)\n",
               dlen, (unsigned long long)dst, (unsigned long long)src);
        return 0;
    }

    if (!strcmp(argv[1], "ping")) {
        uint64_t dst;
        uint8_t req[1 + 512];
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
        if (tun_send(bcast, frame, len) < 0) { perror_sock("sendto"); return 1; }
        printf("ping enviado para %016llx, aguardando reply...\n",
               (unsigned long long)dst);
        for (;;) {
            ssize_t n = tun_recv(frame, sizeof(frame), 2000);
            if (n <= 0) { fprintf(stderr, "ping: timeout\n"); return 1; }
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

    if (!strcmp(argv[1], "dhcp")) {
        if (!has_sk) {
            /* auto: load the keyring or generate + register it */
            if (load_auto_key(sk) < 0)
                return 1;
            has_sk = 1;
        }
        return dhcp_client(src_mac, sk, has_sk, server_pub, has_server_pub);
    }

    fprintf(stderr, "modo desconhecido: %s\n", argv[1]);
    return 1;
}
