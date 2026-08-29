#ifndef IPV69_IFACE_H
#define IPV69_IFACE_H

#include <stddef.h>

/* Active L2 interface: first Ethernet (ARPHRD_ETHER) up with carrier,
   or fallback any up non-loopback interface with an L2 address.
   Pure layer 2 — no IPv4/IPv6 or IP address dependency.
   Returns 0 and fills out, or -1. */
int ipv69_default_iface(char *out, size_t outsz);

#endif
