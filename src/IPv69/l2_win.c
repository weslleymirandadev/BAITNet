/* l2_win.c - Windows L2 backend via Npcap (libpcap): raw Ethernet
 * TX/RX without AF_PACKET. Implements the same l2.h API as the
 * POSIX l2.c. Adapter is matched by substring of the friendly name
 * ("Realtek", "vEthernet (WSL)", ...); the interface MAC comes from
 * GetAdaptersAddresses; a BPF filter keeps only EtherType 0x6969.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <pcap.h>
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

/* frame builder (pure, no OS deps) — same as l2.c */
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

/* interface MAC by description substring (GetAdaptersInfo, ANSI) */
static int adapter_mac(const char *ifname, uint8_t mac[6])
{
    ULONG buflen = 0;
    PIP_ADAPTER_INFO ai, p;
    int found = -1;

    GetAdaptersInfo(NULL, &buflen);
    if (buflen == 0)
        return -1;
    ai = (PIP_ADAPTER_INFO)malloc(buflen);
    if (!ai)
        return -1;
    if (GetAdaptersInfo(ai, &buflen) == NO_ERROR) {
        for (p = ai; p; p = p->Next) {
            if (strstr(p->Description, ifname)) {
                memcpy(mac, p->Address, 6);
                found = 0;
                break;
            }
        }
    }
    free(ai);
    return found;
}

static int find_pcap_dev(const char *ifname, pcap_if_t **out)
{
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) < 0)
        return -1;
    for (d = alldevs; d; d = d->next) {
        if ((d->name && strstr(d->name, ifname)) ||
            (d->description && strstr(d->description, ifname))) {
            *out = d;
            return 0;
        }
    }
    pcap_freealldevs(alldevs);
    return -1;
}

int l2_open(const char *ifname, l2_handle *h, int *ifindex,
            uint8_t src_mac[6])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *dev;
    struct bpf_program fp;
    char resolved[256];

    if (!ifname || !strcmp(ifname, "auto")) {
        /* no interface given: use the default-route one */
        if (l2_default_ifname(resolved, sizeof(resolved)) < 0) {
            fprintf(stderr, "l2: no default-route adapter found\n");
            return -1;
        }
        ifname = resolved;
        printf("l2: auto adapter = %s\n", resolved);
    }
    if (find_pcap_dev(ifname, &dev) < 0) {
        fprintf(stderr, "l2: adapter '%s' not found in Npcap\n",
                ifname);
        return -1;
    }
    pcap_t *p = pcap_open_live(dev->name, 65536, 1 /*promisc*/,
                               100 /*read timeout ms*/, errbuf);
    if (!p) {
        fprintf(stderr, "l2: pcap_open_live: %s\n", errbuf);
        return -1;
    }
    if (pcap_compile(p, &fp, "ether proto 0x6969", 1,
                     PCAP_NETMASK_UNKNOWN) == 0) {
        if (pcap_setfilter(p, &fp) < 0)
            fprintf(stderr, "l2: warning: BPF failed, filtering in userspace\n");
        pcap_freecode(&fp);
    }
    if (adapter_mac(ifname, src_mac) < 0) {
        fprintf(stderr, "l2: MAC of adapter '%s' not found\n", ifname);
        pcap_close(p);
        return -1;
    }
    *ifindex = 0;
    *h = p;
    return 0;
}

int l2_send(l2_handle h, int ifindex, const uint8_t *dst_mac,
            const uint8_t *frame, size_t len)
{
    (void)ifindex;
    (void)dst_mac;
    return pcap_sendpacket((pcap_t *)h, frame, (int)len) == 0 ? 0 : -1;
}

ssize_t l2_recv(l2_handle h, uint8_t *frame, size_t maxlen, int timeout_ms)
{
    pcap_t *p = (pcap_t *)h;
    struct pcap_pkthdr *hdr;
    const u_char *pkt;
    ULONGLONG deadline = timeout_ms > 0 ? GetTickCount64() + timeout_ms : 0;

    for (;;) {
        int r = pcap_next_ex(p, &hdr, &pkt);
        if (r == 1) {
            size_t n = hdr->caplen < maxlen ? hdr->caplen : maxlen;
            memcpy(frame, pkt, n);
            return (ssize_t)n;
        }
        if (r == 0) {           /* read-timeout tick (100ms) */
            if (timeout_ms > 0 && GetTickCount64() >= deadline)
                return 0;
            continue;
        }
        return -1;              /* pcap error */
    }
}

void l2_close(l2_handle h)
{
    if (h)
        pcap_close((pcap_t *)h);
}

/* name of the adapter Windows uses for the default route (the one a
 * datagram to the internet leaves on): GetBestInterface gives its
 * ifindex, GetAdaptersInfo maps it back to the adapter. The name is a
 * substring of the Npcap device (find_pcap_dev matches by substring),
 * so the full Description is returned. */
int l2_default_ifname(char *out, size_t sz)
{
    DWORD idx;
    if (GetBestInterface(inet_addr("8.8.8.8"), &idx) != NO_ERROR)
        return -1;
    ULONG buflen = 0;
    GetAdaptersInfo(NULL, &buflen);
    if (buflen == 0)
        return -1;
    PIP_ADAPTER_INFO ai = (PIP_ADAPTER_INFO)malloc(buflen);
    if (!ai)
        return -1;
    int found = -1;
    if (GetAdaptersInfo(ai, &buflen) == NO_ERROR) {
        for (PIP_ADAPTER_INFO p = ai; p; p = p->Next) {
            if (p->Index == idx) {
                snprintf(out, sz, "%s", p->Description);
                found = 0;
                break;
            }
        }
    }
    free(ai);
    return found;
}
