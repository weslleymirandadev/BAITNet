#ifndef AF69_H
#define AF69_H

#include <stdint.h>
#include <sys/socket.h>

/* mesmo numero do modulo kernel (slot livre; vira 69 com AF_MAX patchado) */
#ifndef AF_IPV69
#define AF_IPV69 21
#endif

struct sockaddr_ipv69 {
    sa_family_t     family;
    int             ifindex;
    uint8_t         dst_mac[6];
    uint64_t        dest;
};

#endif
