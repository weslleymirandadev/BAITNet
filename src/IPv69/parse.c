#include <stdio.h>
#include "IPv69/parse.h"

#define ERR_SHORT     1
#define ERR_ETHERTYPE 2
#define ERR_VERSION   4
#define ERR_LEN       5
#define ERR_NEXTHDR   6

int parse_ipv69_frame(const uint8_t *frame, size_t len) {
    if (len < sizeof(struct ethernet_header) + IPV69_HEADER_LEN)
        return ERR_SHORT;

    if (rd_be16(frame + offsetof(struct ethernet_header, ethertype)) != ETHERTYPE_IPV69)
        return ERR_ETHERTYPE;

    const struct ipv69_header *h = (const void *)(frame + sizeof(struct ethernet_header));

    if ((h->ver_traffic >> 4) != IPV69_VERSION)
        return ERR_VERSION;

    /* payload_len <= frame - 46 (padding de ethernet permitido) */
    if (rd_be16(&h->payload_len) > len - sizeof(struct ethernet_header) - IPV69_HEADER_LEN)
        return ERR_LEN;

    uint8_t nh = h->next_header;
    if (nh != 0 && nh != IPV69_NEXT_DGRAM && nh != IPV69_NEXT_STREAM)
        return ERR_NEXTHDR;

    return 0;
}

struct field {
    const char *name;
    size_t off;
    size_t nbytes;
};

static const struct field fields[] = {
    { "ver_traffic", offsetof(struct ipv69_header, ver_traffic), 1 },
    { "dscp_ecn",    offsetof(struct ipv69_header, dscp_ecn),    1 },
    { "payload_len", offsetof(struct ipv69_header, payload_len), 2 },
    { "flow_id",     offsetof(struct ipv69_header, flow_id),     2 },
    { "next_header", offsetof(struct ipv69_header, next_header), 1 },
    { "hop_limit",   offsetof(struct ipv69_header, hop_limit),   1 },
    { "flags",       offsetof(struct ipv69_header, flags),       1 },
    { "sequence",    offsetof(struct ipv69_header, sequence),    4 },
    { "source",      offsetof(struct ipv69_header, source),      8 },
    { "dest",        offsetof(struct ipv69_header, dest),        8 },
};

void print_ipv69_fields(const struct ipv69_header *h) {
    const uint8_t *base = (const uint8_t *)h;
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        const struct field *f = &fields[i];
        uint64_t v;
        if (f->nbytes == 1)
            v = base[f->off];
        else if (f->nbytes == 2)
            v = rd_be16(base + f->off);
        else if (f->nbytes == 4)
            v = rd_be32(base + f->off);
        else
            v = rd_be64(base + f->off);
        printf("%s = %0*lx\n", f->name, (int)(f->nbytes * 2), v);
    }
}

void print_payload(const uint8_t *payload, size_t len) {
    printf("payload (%zu bytes) = ", len);
    for (size_t i = 0; i < len; i++) {
        uint8_t c = payload[i];
        putchar((c >= 0x20 && c <= 0x7e) ? c : '.');
    }
    putchar('\n');
    printf("hex = ");
    for (size_t i = 0; i < len; i++)
        printf("%02x", payload[i]);
    putchar('\n');
}

void print_dgram253(const uint8_t *payload, size_t len) {
    if (len < 4)
        return;
    printf("src_port = %04x\n", rd_be16(payload));
    printf("dst_port = %04x\n", rd_be16(payload + 2));
    printf("payload = ");
    for (size_t i = 4; i < len; i++) {
        uint8_t c = payload[i];
        putchar((c >= 0x20 && c <= 0x7e) ? c : '.');
    }
    putchar('\n');
}
