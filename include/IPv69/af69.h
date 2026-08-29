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

/* AF_69 sockaddr: 40-bit addresses (5 octets, ff.ff.ff.ff.ff) + 253-datagram
 * ports. ifindex 0 = auto-detect the interface on send (pure layer 2). */
struct sockaddr_69 {
    uint16_t sa_family;
    uint16_t ifindex;
    uint64_t src;
    uint64_t dst;
    uint16_t src_port;
    uint16_t dst_port;
};

#endif
