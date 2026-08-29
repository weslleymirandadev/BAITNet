#ifndef IPV69_HEADER_H
#define IPV69_HEADER_H

#include <stddef.h>
#include <stdint.h>

#define ETHERTYPE_IPV69      0x6969
#define IPV69_VERSION        6
#define IPV69_TRAFFIC_CLASS  9
#define IPV69_HEADER_LEN     32

#define IPV69_NEXT_DGRAM     253
#define IPV69_NEXT_STREAM    254

#define IPV69_FLAG_NOFRAG    (1 << 0)
#define IPV69_FLAG_JUMBO     (1 << 1)

/* fields in wire order, no padding (multi-byte at natural alignment) */
struct ethernet_header {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;     /* offset 12 */
};

/* IPv69 address: 40 bits (5 octets), textual form ff.ff.ff.ff.ff;
   3 reserved bytes per field in the header (future 64-bit expansion) */
struct ipv69_header {
    uint8_t  ver_traffic;   /* 0  */
    uint8_t  dscp_ecn;      /* 1  */
    uint16_t payload_len;   /* 2  */
    uint16_t flow_id;       /* 4  */
    uint8_t  next_header;   /* 6  */
    uint8_t  hop_limit;     /* 7  */
    uint8_t  flags;         /* 8  */
    uint8_t  reserved;      /* 9  */
    uint16_t reserved2;     /* 10 */
    uint32_t sequence;      /* 12 */
    uint8_t  source[5];     /* 16 */
    uint8_t  source_res[3]; /* 21 */
    uint8_t  dest[5];       /* 24 */
    uint8_t  dest_res[3];   /* 29 */
};                          /* 32 */

_Static_assert(sizeof(struct ethernet_header) == 14, "ethernet header must be 14 bytes");
_Static_assert(sizeof(struct ipv69_header) == 32, "ipv69 header must be 32 bytes");

/* big-endian (network order) read/write, architecture independent */
static inline uint16_t rd_be16(const void *p) {
    const uint8_t *b = p;
    return (uint16_t)((b[0] << 8) | b[1]);
}
static inline uint32_t rd_be32(const void *p) {
    const uint8_t *b = p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | b[3];
}
static inline uint64_t rd_be64(const void *p) {
    const uint8_t *b = p;
    return ((uint64_t)rd_be32(b) << 32) | rd_be32(b + 4);
}
/* IPv69 address (40 bits, 5 octets) */
static inline uint64_t rd_be40(const void *p) {
    const uint8_t *b = p;
    return ((uint64_t)b[0] << 32) | ((uint64_t)b[1] << 24) |
           ((uint64_t)b[2] << 16) | ((uint64_t)b[3] << 8) | b[4];
}
static inline void wr_be16(void *p, uint16_t v) {
    uint8_t *b = p;
    b[0] = v >> 8;
    b[1] = v;
}
static inline void wr_be32(void *p, uint32_t v) {
    uint8_t *b = p;
    b[0] = v >> 24;
    b[1] = v >> 16;
    b[2] = v >> 8;
    b[3] = v;
}
static inline void wr_be64(void *p, uint64_t v) {
    uint8_t *b = p;
    wr_be32(b, v >> 32);
    wr_be32(b + 4, v);
}
static inline void wr_be40(void *p, uint64_t v) {
    uint8_t *b = p;
    b[0] = (v >> 32) & 0xff;
    b[1] = (v >> 24) & 0xff;
    b[2] = (v >> 16) & 0xff;
    b[3] = (v >> 8) & 0xff;
    b[4] = v & 0xff;
}

#endif
