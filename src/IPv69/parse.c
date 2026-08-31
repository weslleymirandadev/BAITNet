#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "IPv69/parse.h"
#include "ed25519.h"

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

    /* payload_len must fit in the frame (ethernet padding allowed) */
    if (rd_be16(&h->payload_len) > len - sizeof(struct ethernet_header) - IPV69_HEADER_LEN)
        return ERR_LEN;

    uint8_t nh = h->next_header;
    if (nh != IPV69_NEXT_CONTROL && nh != IPV69_NEXT_DGRAM &&
        nh != IPV69_NEXT_STREAM)
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
    { "src_port",    offsetof(struct ipv69_header, src_port),    2 },
    { "dst_port",    offsetof(struct ipv69_header, dst_port),    2 },
    { "sequence",    offsetof(struct ipv69_header, sequence),    4 },
    { "source",      offsetof(struct ipv69_header, source),      5 },
    { "dest",        offsetof(struct ipv69_header, dest),        5 },
};

void print_ipv69_fields(const struct ipv69_header *h) {
    const uint8_t *base = (const uint8_t *)h;
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        const struct field *f = &fields[i];
        uint64_t v;
        if (f->nbytes == 5) {
            const uint8_t *b = base + f->off;
            printf("%s = %02x.%02x.%02x.%02x.%02x\n",
                   f->name, b[0], b[1], b[2], b[3], b[4]);
            continue;
        }
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

/* "ff.ff.ff.ff.ff" (5 hex octets) or raw hex; returns 0 or -1 */
int parse_ipv69_addr(const char *s, uint64_t *out) {
    char *end;
    if (strchr(s, '.')) {
        uint64_t v = 0;
        for (int i = 0; i < 5; i++) {
            unsigned long o = strtoul(s, &end, 16);
            if (end == s || o > 0xff)
                return -1;
            if ((i < 4 && *end != '.') || (i == 4 && *end != '\0'))
                return -1;
            v = (v << 8) | o;
            s = end + 1;
        }
        *out = v;
        return 0;
    }
    unsigned long long v = strtoull(s, &end, 16);
    if (end == s || *end != '\0')
        return -1;
    *out = v;
    return 0;
}

/* "ff.ff.ff.ff.ff[:porta_hex]" or raw hex[:porta_hex]; splits the
   optional :porta (hex, like the CLI convention). Returns 0 or -1. */
int parse_ipv69_addr_port(const char *s, uint64_t *addr, uint16_t *port)
{
    char buf[64];
    const char *colon = strrchr(s, ':');

    if (colon) {
        size_t alen = (size_t)(colon - s);
        unsigned long p;
        char *end;
        if (alen >= sizeof(buf))
            return -1;
        memcpy(buf, s, alen);
        buf[alen] = 0;
        if (parse_ipv69_addr(buf, addr) < 0)
            return -1;
        p = strtoul(colon + 1, &end, 16);
        if (end == colon + 1 || *end != '\0' || p > 0xffff)
            return -1;
        *port = (uint16_t)p;
        return 0;
    }
    if (parse_ipv69_addr(s, addr) < 0)
        return -1;
    *port = 0;
    return 0;
}

void ipv69_addr_derive(uint8_t out[5], const uint8_t pub[32], char cls)
{
    uint8_t d[64];
    uint8_t b;
    ed25519_sha512(d, pub, 32);
    switch (cls) {
    case 'A': b = 0x00 | (d[0] & 0x3f); break;
    case 'B': b = 0x40 | (d[0] & 0x3f); break;
    case 'D': b = 0xc0 | (d[0] & 0x1f); break;
    case 'E': b = 0xe0 | (d[0] & 0x1f); break;
    case 'C':
    default:  b = 0x80 | (d[0] & 0x3f); break;
    }
    out[0] = b;
    memcpy(out + 1, d + 1, 4);
}

char ipv69_addr_class(uint64_t addr)
{
    uint8_t b = (uint8_t)(addr >> 32);

    if ((b & 0xc0) == 0x00)      return 'A';      /* 00xxxxxx */
    if ((b & 0xc0) == 0x40)      return 'B';      /* 01xxxxxx */
    if ((b & 0xc0) == 0x80)      return 'C';      /* 10xxxxxx */
    if ((b & 0xe0) == 0xc0)      return 'D';      /* 110xxxxx */
    return 'E';                                    /* 111xxxxx */
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
