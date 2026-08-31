/* l2.h - shared L2 helpers for IPv69 tools (frame build, raw socket).
 * Extracted from af69_raw.c so ICSP (and future tools) reuse the same
 * wire plumbing: Ethernet + 32B IPv69 header over AF_PACKET.
 */
#ifndef IPV69_L2_H
#define IPV69_L2_H

#include <stdint.h>
#include <stddef.h>

#define IPV69_BCAST_ADDR 0xFFFFFFFFFFULL

void put_addr40(uint8_t *d, uint64_t v);
uint64_t get_addr40(const uint8_t *s);
uint32_t get_be32(const uint8_t *s);

int hex_decode(const char *hex, uint8_t *out, size_t max);

/* build a full Ethernet+IPv69 frame (L2, 14B eth + 32B header + payload).
 * dst_mac = target MAC (broadcast for discovery). nh = next_header. */
size_t build_frame(uint8_t *frame, const uint8_t *dst_mac,
                   const uint8_t src_mac[6], uint64_t src, uint64_t dst,
                   uint8_t next_header, uint8_t hop_limit,
                   uint16_t src_port, uint16_t dst_port,
                   const uint8_t *payload, size_t plen);

/* open an AF_PACKET socket bound to ifname, ethertype 0x6969.
 * Returns fd, sets *ifindex and *src_mac; -1 on error. */
int raw_socket(const char *ifname, int *ifindex, uint8_t *src_mac);

/* transmit `len` bytes of `frame` on the interface. 0 on success. */
int send_frame(int fd, int ifindex, const uint8_t *dst_mac,
               const uint8_t *frame, size_t len);

#endif
