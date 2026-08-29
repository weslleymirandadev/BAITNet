#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/if_arp.h>
#include <ifaddrs.h>
#include "IPv69/iface.h"

int ipv69_default_iface(char *out, size_t outsz) {
    struct ifaddrs *ifa0 = NULL;
    if (getifaddrs(&ifa0) < 0)
        return -1;

    /* L2 puro: sem IPv4/IPv6 — nada de /proc/net/route, sem endereco IP.
       Preferencia: primeira Ethernet (ARPHRD_ETHER) up com carrier
       (IFF_RUNNING). Fallback: qualquer interface up nao-loopback com
       endereco L2 (sll_halen > 0). */
    for (struct ifaddrs *a = ifa0; a; a = a->ifa_next) {
        if (!a->ifa_addr || a->ifa_addr->sa_family != AF_PACKET)
            continue;
        if ((a->ifa_flags & IFF_LOOPBACK) || !(a->ifa_flags & IFF_UP))
            continue;
        const struct sockaddr_ll *sll = (const struct sockaddr_ll *)a->ifa_addr;
        if (sll->sll_hatype == ARPHRD_ETHER && (a->ifa_flags & IFF_RUNNING)) {
            snprintf(out, outsz, "%s", a->ifa_name);
            freeifaddrs(ifa0);
            return 0;
        }
    }
    for (struct ifaddrs *a = ifa0; a; a = a->ifa_next) {
        if (!a->ifa_addr || a->ifa_addr->sa_family != AF_PACKET)
            continue;
        if ((a->ifa_flags & IFF_LOOPBACK) || !(a->ifa_flags & IFF_UP))
            continue;
        const struct sockaddr_ll *sll = (const struct sockaddr_ll *)a->ifa_addr;
        if (sll->sll_halen > 0) {
            snprintf(out, outsz, "%s", a->ifa_name);
            freeifaddrs(ifa0);
            return 0;
        }
    }
    freeifaddrs(ifa0);
    return -1;
}
