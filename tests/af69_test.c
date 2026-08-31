#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "IPv69/af69.h"
#include "IPv69/parse.h"
#include "ed25519.h"

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

/* MAC of the interface with the given ifindex (for DHCP client) */
static int ifindex_mac(int ifindex, uint8_t mac[6])
{
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0)
        return -1;
    if (if_indextoname(ifindex, ifr.ifr_name) == NULL) {
        close(fd);
        return -1;
    }
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

/* DHCP69 client: DISCOVER -> OFFER -> REQUEST -> ACK, then bind(src).
 * On success prints the leased address and keeps receiving until timeout.
 * With --key the messages are signed (Ed25519); --server-pub validates
 * the server's OFFER/ACK (rogue-server protection). */
static int dhcp_client(int fd, struct sockaddr_69 *sa, uint64_t dst,
                       const uint8_t *sk, int has_sk,
                       const uint8_t *server_pub, int has_server_pub)
{
    uint8_t mac[6];
    uint8_t pkt[1 + 6 + 5 + 4 + 32 + 64];
    struct sockaddr_69 from;
    socklen_t flen = sizeof(from);
    struct timeval tv = { 3, 0 };
    char buf[1500];
    uint64_t addr = 0;
    uint32_t lease = 0;
    ssize_t n;
    const size_t SIGSZ = has_server_pub ? (32 + 64) : 0;

    if (ifindex_mac(sa->ifindex, mac) < 0) {
        fprintf(stderr, "dhcp: nao achei MAC do ifindex %d\n", sa->ifindex);
        return 1;
    }
    printf("dhcp: MAC %02x:%02x:%02x:%02x:%02x:%02x%s\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
           has_sk ? " (Ed25519)" : "");
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* DISCOVER [7][mac] + pub + sig -> broadcast */
    pkt[0] = IPV69_CTRL_DHCP_DISCOVER;
    memcpy(pkt + 1, mac, 6);
    size_t dlen = 7;
    if (has_sk) {
        memcpy(pkt + 7, sk + 32, 32);
        ed25519_sign(pkt + 7 + 32, pkt, 7, sk);
        dlen += 32 + 64;
    }
    sa->dst = dst;
    sa->next_header = IPV69_NEXT_CONTROL;
    if (sendto(fd, pkt, dlen, 0, (struct sockaddr *)sa, sizeof(*sa)) < 0) {
        perror("sendto(DISCOVER)");
        return 1;
    }
    printf("dhcp: DISCOVER enviado\n");

    /* wait OFFER [8][mac][addr 5][lease 4] + pub + sig */
    for (;;) {
        n = recvfrom(fd, buf, sizeof(buf), 0,
                     (struct sockaddr *)&from, &flen);
        if (n < 0) {
            perror("recvfrom(OFFER): timeout?");
            return 1;
        }
        if (n < 16 + (ssize_t)SIGSZ || (uint8_t)buf[0] != IPV69_CTRL_DHCP_OFFER)
            continue;
        if (memcmp(buf + 1, mac, 6))
            continue;               /* offer for another client */
        if (has_server_pub) {
            const uint8_t *spub = (const uint8_t *)buf + 16;
            const uint8_t *ssig = spub + 32;
            if (memcmp(spub, server_pub, 32) ||
                ed25519_verify((const uint8_t *)buf, 16, ssig, server_pub) != 0) {
                printf("dhcp: OFFER assinatura invalida\n");
                return 1;
            }
        }
        addr = ((uint64_t)buf[7] << 32) | ((uint64_t)buf[8] << 24) |
               ((uint64_t)buf[9] << 16) | ((uint64_t)buf[10] << 8) | buf[11];
        lease = ((uint32_t)buf[12] << 24) | ((uint32_t)buf[13] << 16) |
                ((uint32_t)buf[14] << 8) | buf[15];
        printf("dhcp: OFFER %016llx lease %us\n",
               (unsigned long long)addr, lease);
        break;
    }

    /* REQUEST [9][mac][addr 5] + pub + sig */
    pkt[0] = IPV69_CTRL_DHCP_REQUEST;
    memcpy(pkt + 1, mac, 6);
    pkt[7] = (addr >> 32) & 0xff; pkt[8] = (addr >> 24) & 0xff;
    pkt[9] = (addr >> 16) & 0xff; pkt[10] = (addr >> 8) & 0xff; pkt[11] = addr & 0xff;
    size_t rlen = 12;
    if (has_sk) {
        memcpy(pkt + 12, sk + 32, 32);
        ed25519_sign(pkt + 12 + 32, pkt, 12, sk);
        rlen += 32 + 64;
    }
    if (sendto(fd, pkt, rlen, 0, (struct sockaddr *)sa, sizeof(*sa)) < 0) {
        perror("sendto(REQUEST)");
        return 1;
    }
    printf("dhcp: REQUEST %016llx\n", (unsigned long long)addr);

    /* wait ACK [10][mac][addr 5][lease 4] + pub + sig */
    for (;;) {
        n = recvfrom(fd, buf, sizeof(buf), 0,
                     (struct sockaddr *)&from, &flen);
        if (n < 0) {
            perror("recvfrom(ACK): timeout?");
            return 1;
        }
        if (n < 16 + (ssize_t)SIGSZ || (uint8_t)buf[0] != IPV69_CTRL_DHCP_ACK)
            continue;
        if (memcmp(buf + 1, mac, 6))
            continue;
        if (has_server_pub) {
            const uint8_t *spub = (const uint8_t *)buf + 16;
            const uint8_t *ssig = spub + 32;
            if (memcmp(spub, server_pub, 32) ||
                ed25519_verify((const uint8_t *)buf, 16, ssig, server_pub) != 0) {
                printf("dhcp: ACK assinatura invalida\n");
                return 1;
            }
        }
        printf("dhcp: ACK %016llx lease %us — configurado!\n",
               (unsigned long long)addr, lease);
        break;
    }

    /* bind the leased address and echo what we get for a few seconds */
    sa->src = addr;
    if (bind(fd, (struct sockaddr *)sa, sizeof(*sa)) < 0) {
        perror("bind(leased addr)");
        return 1;
    }
    printf("dhcp: bound src=%016llx, ouvindo...\n", (unsigned long long)addr);
    tv.tv_sec = 5;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    for (;;) {
        n = recvfrom(fd, buf, sizeof(buf), 0,
                     (struct sockaddr *)&from, &flen);
        if (n < 0)
            break;
        printf("frame: src=%016llx dst=%016llx nh=%u payload(%zd)=",
               (unsigned long long)from.src, (unsigned long long)from.dst,
               from.next_header, n);
        for (ssize_t i = 0; i < n; i++)
            putchar((buf[i] >= 0x20 && buf[i] <= 0x7e) ? buf[i] : '.');
        putchar('\n');
    }
    return 0;
}

static const char *ctrl_name(uint8_t t)
{
    switch (t) {
    case IPV69_CTRL_ND_REQUEST:    return "nd-request";
    case IPV69_CTRL_ND_REPLY:      return "nd-reply";
    case IPV69_CTRL_ECHO_REQUEST:  return "echo-request";
    case IPV69_CTRL_ECHO_REPLY:    return "echo-reply";
    case IPV69_CTRL_UNREACHABLE:   return "unreachable";
    case IPV69_CTRL_TIME_EXCEEDED: return "time-exceeded";
    default:                       return "?";
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s recv [ifindex] [src_addr] [src_port]\n"
            "       %s send [ifindex] <dst> <src_port> <dst_port> [payload]\n"
            "       %s ping [ifindex] <dst> [payload]\n"
            "       %s dhcp <ifindex|ifname>\n"
            "  ifindex 0 or omitted = auto-detect (pure L2)\n"
            "  src_addr: local 40-bit address to bind (ff.ff.ff.ff.ff or raw hex);\n"
            "            omitted = promiscuous (receives everything)\n"
            "  src_port: local port filter (hex); omitted = any port\n"
            "  dst: 40-bit address as ff.ff.ff.ff.ff or raw hex\n"
            "  dhcp: lease an address from the DHCP69 server\n",
            prog, prog, prog, prog);
}

int cmd_test(int argc, char **argv)
{
    struct sockaddr_69 sa;
    int fd;

    setvbuf(stdout, NULL, _IONBF, 0);   /* real-time log (timeout kills lose buffers) */

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_family = AF_69;
    if (argc > 2)
        sa.ifindex = (uint16_t)atoi(argv[2]);

    fd = socket(AF_69, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket(AF_69)");
        return 1;
    }

    if (!strcmp(argv[1], "recv")) {
        if (argc > 3 && parse_ipv69_addr_port(argv[3], &sa.src, &sa.dst_port) < 0) {
            fprintf(stderr, "invalid src_addr[:porta_hex]: %s\n", argv[3]);
            return 1;
        }
        if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("bind");
            return 1;
        }
        printf("listening on ifindex %u src=%016llx port=%04x\n",
               sa.ifindex, (unsigned long long)sa.src, sa.dst_port);
        for (;;) {
            struct sockaddr_69 from;
            socklen_t flen = sizeof(from);
            char buf[1500];
            ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&from, &flen);
            if (n < 0) {
                perror("recvfrom");
                return 1;
            }
            printf("frame: src=%016llx dst=%016llx if=%u nh=%u",
                   (unsigned long long)from.src, (unsigned long long)from.dst,
                   from.ifindex, from.next_header);
            if (from.next_header == IPV69_NEXT_DGRAM)
                printf(" ports=%u/%u", from.src_port, from.dst_port);
            else
                printf(" ctrl=%s(%u)", ctrl_name((uint8_t)buf[0]),
                       (uint8_t)buf[0]);
            printf(" payload(%zd)=", n);
            for (ssize_t i = 0; i < n; i++)
                putchar((buf[i] >= 0x20 && buf[i] <= 0x7e) ? buf[i] : '.');
            putchar('\n');
        }
    }

    if (!strcmp(argv[1], "send")) {
        if (argc < 5) {
            usage(argv[0]);
            return 1;
        }
        if (parse_ipv69_addr_port(argv[3], &sa.dst, &sa.dst_port) < 0) {
            fprintf(stderr, "invalid dst address: %s\n", argv[3]);
            return 1;
        }
        sa.src_port = (uint16_t)strtoul(argv[4], NULL, 16);
        sa.next_header = IPV69_NEXT_DGRAM;
        const char *payload = argc > 5 ? argv[5] : "hello af69";
        if (argc > 6)
            sa.hop_limit = (uint8_t)atoi(argv[6]);
        if (sendto(fd, payload, strlen(payload), 0,
                   (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("sendto(AF_69)");
            return 1;
        }
        printf("sent %zu bytes\n", strlen(payload));
        return 0;
    }

    if (!strcmp(argv[1], "ping")) {
        if (argc < 4) {
            usage(argv[0]);
            return 1;
        }
        if (parse_ipv69_addr(argv[3], &sa.dst) < 0) {
            fprintf(stderr, "invalid dst address: %s\n", argv[3]);
            return 1;
        }
        /* bind a local address so replies are addressed to us (otherwise
           the socket is promiscuous and may pick up our own request) */
        sa.src = 1;
        sa.dst_port = 7;
        if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("bind(ping)");
            return 1;
        }
        const char *data = argc > 4 ? argv[4] : "ping";
        char req[1 + 512], rsp[1 + 512];
        size_t dlen = strlen(data);
        struct timeval tv = { 1, 0 };
        struct sockaddr_69 from;
        socklen_t flen = sizeof(from);

        req[0] = IPV69_CTRL_ECHO_REQUEST;
        memcpy(req + 1, data, dlen);
        sa.next_header = IPV69_NEXT_CONTROL;
        sa.src_port = 1;
        sa.dst_port = 7;
        if (argc > 5)
            sa.hop_limit = (uint8_t)atoi(argv[5]);
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (sendto(fd, req, 1 + dlen, 0, (struct sockaddr *)&sa,
                   sizeof(sa)) < 0) {
            perror("sendto(echo request)");
            return 1;
        }
        /* wait for the echo reply, skipping anything else (e.g. our own
           ND request looping back on the same link) */
        for (;;) {
            ssize_t n = recvfrom(fd, rsp, sizeof(rsp), 0,
                                 (struct sockaddr *)&from, &flen);
            if (n < 0) {
                perror("recvfrom(echo reply): timeout?");
                return 1;
            }
            if (n > 0 && rsp[0] == IPV69_CTRL_ECHO_REPLY) {
                printf("reply from %016llx: ctrl=%s(%u) payload(%zd)=",
                       (unsigned long long)from.src, ctrl_name((uint8_t)rsp[0]),
                       (uint8_t)rsp[0], n - 1);
                for (ssize_t i = 1; i < n; i++)
                    putchar((rsp[i] >= 0x20 && rsp[i] <= 0x7e) ? rsp[i] : '.');
                putchar('\n');
                return 0;
            }
        }
    }

    if (!strcmp(argv[1], "dhcp")) {
        if (argc < 3) {
            usage(argv[0]);
            return 1;
        }
        sa.ifindex = (uint16_t)atoi(argv[2]);
        if (!sa.ifindex)
            sa.ifindex = (uint16_t)if_nametoindex(argv[2]);
        if (!sa.ifindex) {
            fprintf(stderr, "iface invalida: %s\n", argv[2]);
            return 1;
        }
        uint8_t sk[64], server_pub[32];
        int has_sk = 0, has_server_pub = 0;
        for (int i = 3; i + 1 < argc; i++) {
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
            }
        }
        if (!has_sk) {
            /* auto: load ~/.ipv69/key or generate + register it.
               NOTE: separate buffer for our own pub — server_pub still
               holds the server key from --server-pub. */
            char kpath[256];
            uint8_t my_pub[32];
            ed25519_keyfile_default_path(kpath, sizeof(kpath));
            if (ed25519_keyfile_load_or_create(kpath, sk, my_pub) < 0) {
                fprintf(stderr, "dhcp: nao foi possivel carregar/criar chave em %s\n", kpath);
                return 1;
            }
            has_sk = 1;
        }
        return dhcp_client(fd, &sa, 0xFFFFFFFFFFULL, sk, has_sk,
                           server_pub, has_server_pub);
    }

    usage(argv[0]);
    return 1;
}
