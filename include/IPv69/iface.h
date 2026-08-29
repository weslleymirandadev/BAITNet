#ifndef IPV69_IFACE_H
#define IPV69_IFACE_H

#include <stddef.h>

/* Interface L2 ativa: primeira Ethernet (ARPHRD_ETHER) up com carrier,
   ou fallback qualquer interface up nao-loopback com endereco L2.
   Puramente camada 2 — nao depende de IPv4/IPv6 nem de endereco IP.
   Retorna 0 e preenche out, ou -1. */
int ipv69_default_iface(char *out, size_t outsz);

#endif
