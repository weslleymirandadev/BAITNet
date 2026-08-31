#ifndef IPV69_HEADER_H
#define IPV69_HEADER_H

#include <stddef.h>
#include <stdint.h>
#include "endian.h"

#define ETHERTYPE_IPV69      0x6969
#define IPV69_VERSION        6
#define IPV69_TRAFFIC_CLASS  9
#define IPV69_HEADER_LEN     32

#define IPV69_NEXT_CONTROL   0
#define IPV69_NEXT_DGRAM     1
#define IPV69_NEXT_STREAM    2       /* reserved (future SCTP-derived transport) */

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
    uint16_t src_port;      /* 10 */
    uint16_t dst_port;      /* 12 */
    uint8_t  sequence[4];   /* 14 */
    uint8_t  source[5];     /* 18 */
    uint8_t  source_res[2]; /* 23 */
    uint8_t  dest[5];       /* 25 */
    uint8_t  dest_res[2];   /* 30 */
};                          /* 32 */

_Static_assert(sizeof(struct ethernet_header) == 14, "ethernet header must be 14 bytes");
_Static_assert(sizeof(struct ipv69_header) == 32, "ipv69 header must be 32 bytes");

/* byte order helpers live in endian.h (ipv69_addr_get/put, be16/32/64) */

#endif
