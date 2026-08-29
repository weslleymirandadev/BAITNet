#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include "IPv69/header.h"
#include "IPv69/parse.h"
#include "IPv69/iface.h"

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);   /* log em tempo real */

    char ifname[IFNAMSIZ];
    if (argc > 1)
        snprintf(ifname, sizeof(ifname), "%s", argv[1]);
    else if (ipv69_default_iface(ifname, sizeof(ifname)) < 0) {
        fprintf(stderr, "no interface found\n");
        return 1;
    }
    printf("listening on %s\n", ifname);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        return 1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifr.ifr_ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        return 1;
    }

    static uint8_t buf[65536];
    for (;;) {
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
        if (n < 0) {
            perror("recvfrom");
            break;
        }

        /* ETH_P_ALL pega tudo: descarta nao-IPv69 em silencio */
        if (rd_be16(buf + offsetof(struct ethernet_header, ethertype)) != ETHERTYPE_IPV69)
            continue;

        int rc = parse_ipv69_frame(buf, (size_t)n);
        if (rc) {
            printf("invalid IPv69 frame (code=%d)\n", rc);
            continue;
        }

        printf("IPv69 frame received!\n");
        const struct ipv69_header *h = (const void *)(buf + sizeof(struct ethernet_header));
        print_ipv69_fields(h);

        if (h->next_header == IPV69_NEXT_DGRAM) {
            size_t plen = rd_be16(&h->payload_len);
            if (plen)
                print_dgram253(buf + sizeof(struct ethernet_header) + IPV69_HEADER_LEN, plen);
        } else {
            size_t plen = rd_be16(&h->payload_len);
            if (plen)
                print_payload(buf + sizeof(struct ethernet_header) + IPV69_HEADER_LEN, plen);
        }
        putchar('\n');
    }
    return 0;
}
