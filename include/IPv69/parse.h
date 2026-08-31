#ifndef IPV69_PARSE_H
#define IPV69_PARSE_H

#include <stddef.h>
#include <stdint.h>
#include "header.h"

/* returns 0 if valid, or an error code:
   1 short frame, 2 wrong ethertype, 4 wrong version,
   5 inconsistent payload_len, 6 unknown next_header */
int parse_ipv69_frame(const uint8_t *frame, size_t len);

/* prints header fields in hex, one per line */
void print_ipv69_fields(const struct ipv69_header *h);

/* prints src_port, dst_port and the datagram 253 data as text */
void print_dgram253(const uint8_t *payload, size_t len);

/* prints a generic payload: text (non-printable bytes become '.') + hex */
void print_payload(const uint8_t *payload, size_t len);

/* parses "ff.ff.ff.ff.ff" (5 hex octets) or raw hex into a 40-bit address;
   returns 0 on success, -1 on error */
int parse_ipv69_addr(const char *s, uint64_t *out);

/* parses "ff.ff.ff.ff.ff[:porta]" (or raw hex[:porta]); the optional
   :porta is DECIMAL (:16 = port 16, no leading zeros needed). */
int parse_ipv69_addr_port(const char *s, uint64_t *addr, uint16_t *port);

/* identity-derived address (SLAAC-style): 4 bytes of SHA-512(pubkey)
   prefixed with the class byte -> 40-bit address. Deterministic: same
   key, same address, forever. No DHCP needed.
   cls: 'A' private local / 'B' private extended / 'C' public
        'D' multicast / 'E' reserved (broadcast). */
void ipv69_addr_derive(uint8_t out[5], const uint8_t pub[32], char cls);

/* address class (IPv4-style, first bits of byte 0):
   A 00.x, B 01.x, C 10.x, D 110.x, E 111.x (broadcast ff.ff.ff.ff.ff) */
char ipv69_addr_class(uint64_t addr);

#endif
