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

/* identity-derived address (SLAAC-style): first 5 bytes of
   SHA-512(pubkey) -> 40-bit address. Deterministic: same key, same
   address, forever. No DHCP needed. */
void ipv69_addr_derive(uint8_t out[5], const uint8_t pub[32]);

#endif
