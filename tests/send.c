#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include "IPv69/header.h"
#include "IPv69/iface.h"

int main(int argc, char **argv) {
    fprintf(stderr,
            "Usage: ./ipv69_send [interface] [dest_hex] [src_port] [dst_port] [payload] [next_header]\n"
            "  interface: se omitida ou '-', usa a interface L2 ativa (auto-detect)\n"
            "  dest_hex: endereco 64-bit em hex (padrao 2)\n"
            "  src/dst_port: portas do datagrama 253 em hex (padrao 1)\n"
            "  payload: dados do datagrama (padrao \"hello from ipv69\")\n"
            "  next_header: 253 dgram (padrao), 254 stream cru, 0 sem payload\n");

    char ifname[IFNAMSIZ];
    if (argc > 1 && strcmp(argv[1], "-") != 0)
        snprintf(ifname, sizeof(ifname), "%s", argv[1]);
    else if (ipv69_default_iface(ifname, sizeof(ifname)) < 0) {
        fprintf(stderr, "no interface found\n");
        return 1;
    }

    uint64_t dest = 2;
    uint16_t src_port = 1, dst_port = 1;
    const char *payload = "hello from ipv69";
    uint8_t nh = IPV69_NEXT_DGRAM;
    if (argc > 2)
        dest = strtoull(argv[2], NULL, 16);
    if (argc > 3)
        src_port = (uint16_t)strtoul(argv[3], NULL, 16);
    if (argc > 4)
        dst_port = (uint16_t)strtoul(argv[4], NULL, 16);
    if (argc > 5)
        payload = argv[5];
    if (argc > 6)
        nh = (uint8_t)strtoul(argv[6], NULL, 0);
    if (nh != 0 && nh != IPV69_NEXT_DGRAM && nh != IPV69_NEXT_STREAM) {
        fprintf(stderr, "next_header invalido: %u\n", nh);
        return 1;
    }
    size_t plen = strlen(payload);
    if (plen > 1400)
        plen = 1400;
    printf("using interface %s\n", ifname);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_IPV69));
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        return 1;
    }

    /* if_nametoindex em vez de SIOCGIFINDEX: o ioctl do MAC reescreve a
       union do ifreq e corromperia o ifindex lido depois */
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETHERTYPE_IPV69);
    sll.sll_ifindex = ifindex;
    sll.sll_hatype = ARPHRD_ETHER;
    sll.sll_halen = 6;
    memset(sll.sll_addr, 0xff, 6);   /* dst broadcast */

    uint8_t frame[1514];
    memset(frame, 0, sizeof(frame));

    memset(frame, 0xff, 6);                          /* dst MAC broadcast */
    memcpy(frame + 6, ifr.ifr_hwaddr.sa_data, 6);    /* src MAC da interface */
    frame[12] = ETHERTYPE_IPV69 >> 8;
    frame[13] = ETHERTYPE_IPV69 & 0xff;

    struct ipv69_header *h = (void *)(frame + sizeof(struct ethernet_header));
    h->ver_traffic = (IPV69_VERSION << 4) | IPV69_TRAFFIC_CLASS;
    h->dscp_ecn = 0;
    wr_be16(&h->flow_id, 1);
    h->next_header = nh;
    h->hop_limit = 64;
    h->flags = IPV69_FLAG_NOFRAG;
    h->reserved = 0;
    wr_be16(&h->reserved2, 0);
    wr_be32(&h->sequence, 1);
    wr_be64(&h->source, 1);
    wr_be64(&h->dest, dest);

    uint8_t *dgram = frame + sizeof(struct ethernet_header) + IPV69_HEADER_LEN;
    size_t dlen;
    if (nh == IPV69_NEXT_DGRAM) {
        wr_be16(dgram, src_port);
        wr_be16(dgram + 2, dst_port);
        memcpy(dgram + 4, payload, plen);
        dlen = 4 + plen;
    } else if (nh == IPV69_NEXT_STREAM) {
        memcpy(dgram, payload, plen);
        dlen = plen;
    } else {
        dlen = 0;
    }
    wr_be16(&h->payload_len, dlen);

    size_t flen = sizeof(struct ethernet_header) + IPV69_HEADER_LEN + dlen;
    if (flen < 60)
        flen = 60;   /* minimo do frame ethernet */

    if (sendto(fd, frame, flen, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("sendto");
        return 1;
    }
    printf("sent %zu bytes\n", flen);
    return 0;
}
