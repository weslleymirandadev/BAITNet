#ifndef IPV69_AF_H
#define IPV69_AF_H

#include <stdint.h>

/* AF_69: IPv69 socket address family.
 *
 * Requires a kernel built with the af69-kernel.patch (AF_69=69, AF_MAX=70);
 * the plain WSL/distro kernel rejects families >= AF_MAX (~46). */
#ifndef AF_69
#define AF_69 69
#endif
#ifndef PF_69
#define PF_69 AF_69
#endif

/* next_header values (protocol of the payload) */
#define IPV69_NEXT_CONTROL   0
#define IPV69_NEXT_DGRAM     1
#define IPV69_NEXT_STREAM    2       /* reserved (future SCTP-derived transport) */

/* control payload[0] types (next_header 255) */
#define IPV69_CTRL_ND_REQUEST    1
#define IPV69_CTRL_ND_REPLY      2
#define IPV69_CTRL_ECHO_REQUEST  3
#define IPV69_CTRL_ECHO_REPLY    4
#define IPV69_CTRL_UNREACHABLE   5
#define IPV69_CTRL_TIME_EXCEEDED 6

/* AF_69 sockaddr: 40-bit addresses (5 octets, ff.ff.ff.ff.ff) + native
 * header ports (src/dst). ifindex 0 = auto-detect the interface on send
 * (pure layer 2). next_header selects the payload protocol: 1 dgram
 * (default), 0 control, 2 stream (reserved). hop_limit 0 = kernel
 * default (64). Keep in sync with kernel/af69/af69.c. */
struct sockaddr_69 {
    uint16_t sa_family;
    uint16_t ifindex;
    uint64_t src;
    uint64_t dst;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t next_header;   /* 0/253 dgram, 255 control; 254 reserved */
    uint8_t  hop_limit;     /* 0 = default (64) */
    uint8_t  reserved;
};

#endif
