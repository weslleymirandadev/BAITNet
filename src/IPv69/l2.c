/* l2.c - shared L2 plumbing: Ethernet + 32B IPv69 header over AF_PACKET.
 * Implementation of the l2.h API (no tunnel mode; the gateway does its
 * own UDP handling). Byte order via endian.h.
 */
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include "IPv69/header.h"
#include "IPv69/l2.h"

int hex_decode(const char *hex, uint8_t *out, size_t max)
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

size_t build_frame(uint8_t *frame, const uint8_t *dst_mac,
                   const uint8_t src_mac[6], uint64_t src, uint64_t dst,
                   uint8_t next_header, uint8_t hop_limit,
                   uint16_t src_port, uint16_t dst_port,
                   const uint8_t *payload, size_t plen)
{
    struct ethernet_header *eth = (struct ethernet_header *)frame;
    struct ipv69_header *h = (struct ipv69_header *)(frame + 14);

    memcpy(eth->dst_mac, dst_mac, 6);
    memcpy(eth->src_mac, src_mac, 6);
    eth->ethertype = htons(ETHERTYPE_IPV69);
    memset(h, 0, IPV69_HEADER_LEN);
    h->ver_traffic = (IPV69_VERSION << 4) | IPV69_TRAFFIC_CLASS;
    ipv69_put_be16(&h->payload_len, plen);
    ipv69_put_be16(&h->flow_id, 1);
    h->next_header = next_header;
    h->hop_limit = hop_limit ? hop_limit : 64;
    h->flags = IPV69_FLAG_NOFRAG;
    ipv69_put_be16(&h->src_port, src_port);
    ipv69_put_be16(&h->dst_port, dst_port);
    ipv69_addr_put(h->source, src);
    ipv69_addr_put(h->dest, dst);
    memcpy(frame + 14 + IPV69_HEADER_LEN, payload, plen);
    return 14 + IPV69_HEADER_LEN + plen;
}

int raw_socket(const char *ifname, int *ifindex, uint8_t *src_mac)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_IPV69));
    struct ifreq ifr;

    if (fd < 0) { perror("socket(AF_PACKET)"); return -1; }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); return -1; }
    *ifindex = ifr.ifr_ifindex;
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { perror("SIOCGIFHWADDR"); return -1; }
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);
    struct sockaddr_ll sll = {
        .sll_family = AF_PACKET, .sll_protocol = htons(ETHERTYPE_IPV69),
        .sll_ifindex = *ifindex,
    };
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind(AF_PACKET)");
        return -1;
    }
    return fd;
}

int send_frame(int fd, int ifindex, const uint8_t *dst_mac,
               const uint8_t *frame, size_t len)
{
    struct sockaddr_ll sll = {
        .sll_family = AF_PACKET, .sll_protocol = htons(ETHERTYPE_IPV69),
        .sll_ifindex = ifindex, .sll_halen = 6,
    };
    memcpy(sll.sll_addr, dst_mac, 6);
    return sendto(fd, frame, len, 0, (struct sockaddr *)&sll, sizeof(sll));
}

/* --- portable L2 backend (POSIX: AF_PACKET + poll/recv) --- */

int l2_open(const char *ifname, l2_handle *h, int *ifindex,
            uint8_t src_mac[6])
{
    int fd = raw_socket(ifname, ifindex, src_mac);
    if (fd < 0)
        return -1;
    *h = fd;
    return 0;
}

int l2_send(l2_handle h, int ifindex, const uint8_t *dst_mac,
            const uint8_t *frame, size_t len)
{
    return send_frame((int)h, ifindex, dst_mac, frame, len) < 0 ? -1 : 0;
}

ssize_t l2_recv(l2_handle h, uint8_t *frame, size_t maxlen, int timeout_ms)
{
    int fd = (int)h;

    if (timeout_ms > 0) {
        struct pollfd pfd = { fd, POLLIN, 0 };
        int r = poll(&pfd, 1, timeout_ms);
        if (r < 0) {
            if (errno == EINTR)
                return 0;               /* treat as timeout */
            return -1;
        }
        if (r == 0 || !(pfd.revents & POLLIN))
            return 0;                   /* timeout */
    }
    ssize_t n = recv(fd, frame, maxlen, 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return 0;
    return n;
}

void l2_close(l2_handle h)
{
    if ((int)h >= 0)
        close((int)h);
}
