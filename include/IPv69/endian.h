/* endian.h - big-endian (network order) accessors, shared by every
 * IPv69/ICSP component.
 *
 * Byte-wise implementation: correct on ANY host endianness by
 * construction (no #if __BYTE_ORDER__ branches). The wire format of
 * IPv69 is big-endian; these helpers are the single place that knows.
 *
 * Aliases:
 *   ipv69_addr_get(p) / ipv69_addr_put(p, v)  — 40-bit IPv69 address
 *   ipv69_get_be16/32/64 / ipv69_put_be16/32/64 — scalar fields
 */
#ifndef IPV69_ENDIAN_H
#define IPV69_ENDIAN_H

#include <stdint.h>
#include <stddef.h>

static inline uint16_t ipv69_get_be16(const void *p)
{
    const uint8_t *b = p;
    return (uint16_t)((b[0] << 8) | b[1]);
}
static inline uint32_t ipv69_get_be32(const void *p)
{
    const uint8_t *b = p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | b[3];
}
static inline uint64_t ipv69_get_be64(const void *p)
{
    const uint8_t *b = p;
    return ((uint64_t)ipv69_get_be32(b) << 32) | ipv69_get_be32(b + 4);
}
/* IPv69 address: 40 bits, 5 octets (ff.ff.ff.ff.ff) */
static inline uint64_t ipv69_addr_get(const void *p)
{
    const uint8_t *b = p;
    return ((uint64_t)b[0] << 32) | ((uint64_t)b[1] << 24) |
           ((uint64_t)b[2] << 16) | ((uint64_t)b[3] << 8) | b[4];
}
static inline void ipv69_put_be16(void *p, uint16_t v)
{
    uint8_t *b = p;
    b[0] = (uint8_t)(v >> 8);
    b[1] = (uint8_t)v;
}
static inline void ipv69_put_be32(void *p, uint32_t v)
{
    uint8_t *b = p;
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
}
static inline void ipv69_put_be64(void *p, uint64_t v)
{
    uint8_t *b = p;
    ipv69_put_be32(b, (uint32_t)(v >> 32));
    ipv69_put_be32(b + 4, (uint32_t)v);
}
static inline void ipv69_addr_put(void *p, uint64_t v)
{
    uint8_t *b = p;
    b[0] = (uint8_t)(v >> 32);
    b[1] = (uint8_t)(v >> 24);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 8);
    b[4] = (uint8_t)v;
}

/* short legacy aliases (still used by tests/kernel-facing code) */
#define rd_be16 ipv69_get_be16
#define rd_be32 ipv69_get_be32
#define rd_be64 ipv69_get_be64
#define rd_be40 ipv69_addr_get
#define wr_be16 ipv69_put_be16
#define wr_be32 ipv69_put_be32
#define wr_be64 ipv69_put_be64
#define wr_be40 ipv69_addr_put
#define get_be32 ipv69_get_be32
#define put_be16 ipv69_put_be16
#define put_be32 ipv69_put_be32
#define get_addr40 ipv69_addr_get
#define put_addr40 ipv69_addr_put

#endif
