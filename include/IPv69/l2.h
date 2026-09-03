/* l2.h - shared L2 helpers for IPv69 tools (frame build, raw socket).
 * The l2_* API is the portable backend: POSIX uses AF_PACKET (l2.c),
 * Windows uses Npcap/libpcap (l2_win.c). Byte-order helpers
 * (ipv69_addr_get/put, be16/32/64) come from endian.h (via header.h)
 * — no local copies needed.
 */
#ifndef IPV69_L2_H
#define IPV69_L2_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include "endian.h"

#define IPV69_BCAST_ADDR 0xFFFFFFFFFFULL

/* L2 backend handle: AF_PACKET fd on POSIX, pcap_t* on Windows */
#ifdef _WIN32
typedef void *l2_handle;
#else
typedef int l2_handle;
#endif

int hex_decode(const char *hex, uint8_t *out, size_t max);

/* build a full Ethernet+IPv69 frame (L2, 14B eth + 32B header + payload).
 * dst_mac = target MAC (broadcast for discovery). nh = next_header. */
size_t build_frame(uint8_t *frame, const uint8_t *dst_mac,
                   const uint8_t src_mac[6], uint64_t src, uint64_t dst,
                   uint8_t next_header, uint8_t hop_limit,
                   uint16_t src_port, uint16_t dst_port,
                   const uint8_t *payload, size_t plen);

/* --- portable L2 backend --- */

/* open a raw L2 endpoint on `ifname` (substring match on Windows).
 * Fills the handle, *ifindex (0 on Windows) and the interface MAC.
 * Returns 0, -1 on error. */
int l2_open(const char *ifname, l2_handle *h, int *ifindex,
            uint8_t src_mac[6]);

/* transmit one complete Ethernet frame. 0 on success, -1. */
int l2_send(l2_handle h, int ifindex, const uint8_t *dst_mac,
            const uint8_t *frame, size_t len);

/* receive one frame, waiting up to timeout_ms (0 = forever).
 * Returns the frame length, 0 on timeout, -1 on error. */
ssize_t l2_recv(l2_handle h, uint8_t *frame, size_t maxlen, int timeout_ms);

void l2_close(l2_handle h);

/* name of the interface the system currently uses to reach the
 * internet (the default-route interface): "eth0"/"wlan0" on Linux,
 * the Npcap-friendly adapter substring on Windows. Fills out[0..sz)
 * and returns 0; -1 when no default route exists. */
int l2_default_ifname(char *out, size_t sz);

/* --- legacy POSIX AF_PACKET API (dgram tools, Linux only) --- */

/* open an AF_PACKET socket bound to ifname, ethertype 0x6969.
 * Returns fd, sets *ifindex and *src_mac; -1 on error. */
int raw_socket(const char *ifname, int *ifindex, uint8_t *src_mac);

/* transmit `len` bytes of `frame` on the interface. 0 on success. */
int send_frame(int fd, int ifindex, const uint8_t *dst_mac,
               const uint8_t *frame, size_t len);

#endif
