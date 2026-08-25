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
#include "header.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
                "Usage: sudo ./ipv69_send <interface> [dest_hex] [src_port] [dst_port] [payload]\n"
                "  dest_hex: endereco 64-bit em hex (padrao 2)\n"
                "  src/dst_port: portas do datagrama 253 em hex (padrao 1)\n"
                "  payload: dados do datagrama (padrao \"hello from ipv69\")\n");
        return 1;
    }

    uint64_t dest = 2;
    uint16_t src_port = 1, dst_port = 1;
    const char *payload = "hello from ipv69";
    if (argc > 2)
        dest = strtoull(argv[2], NULL, 16);
    if (argc > 3)
        src_port = (uint16_t)strtoul(argv[3], NULL, 16);
    if (argc > 4)
        dst_port = (uint16_t)strtoul(argv[4], NULL, 16);
    if (argc > 5)
        payload = argv[5];
    size_t plen = strlen(payload);
    if (plen > 1400)
        plen = 1400;

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_IPV69));
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        return 1;
    }
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        return 1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETHERTYPE_IPV69);
    sll.sll_ifindex = ifr.ifr_ifindex;
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
    wr_be16(&h->payload_len, 4 + plen);
    wr_be16(&h->flow_id, 1);
    h->next_header = IPV69_NEXT_DGRAM;
    h->hop_limit = 64;
    h->flags = IPV69_FLAG_NOFRAG;
    h->reserved = 0;
    wr_be16(&h->reserved2, 0);
    wr_be32(&h->sequence, 1);
    wr_be64(&h->source, 1);
    wr_be64(&h->dest, dest);

    uint8_t *dgram = frame + sizeof(struct ethernet_header) + IPV69_HEADER_LEN;
    wr_be16(dgram, src_port);
    wr_be16(dgram + 2, dst_port);
    memcpy(dgram + 4, payload, plen);

    size_t flen = sizeof(struct ethernet_header) + IPV69_HEADER_LEN + 4 + plen;
    if (flen < 60)
        flen = 60;   /* minimo do frame ethernet */

    if (sendto(fd, frame, flen, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("sendto");
        return 1;
    }
    printf("sent %zu bytes\n", flen);
    return 0;
}
