/* mac1.h - WireGuard-style cheap pre-auth filter.
 *
 * mac1 is a keyed MAC over a control packet that the SERVER verifies
 * before any asymmetric crypto (signature verify / ECDH), so garbage is
 * dropped in microseconds instead of ~1.7 ms of Ed25519 work.
 *
 * The key is derived from the server's own identity the client already
 * knows (its 40-bit address): HASH("ipv69-mac1" || addr40). This is
 * public — mac1 is NOT authentication, it is a liveness/format filter
 * that raises the cost of a CPU-exhaustion attempt to "must know the
 * protocol and pass the per-sender rate limit" (ratelimit.h). Real
 * authentication stays in the signature/cookie layers, exactly like
 * WireGuard's mac1 (HMAC of the responder pubkey) vs the signature.
 */
#ifndef IPV69_MAC1_H
#define IPV69_MAC1_H

#include <stdint.h>
#include <stddef.h>

#define MAC1_LEN 16

/* key = SHA-512("ipv69-mac1" || addr40_be)[0..31] */
void mac1_key(uint64_t server_addr, uint8_t key[32]);

/* tag = Poly1305(key, msg) — append to the packet, verify on receive */
void mac1_compute(const uint8_t key[32], const uint8_t *msg, size_t n,
                  uint8_t out[MAC1_LEN]);
int mac1_verify(const uint8_t key[32], const uint8_t *msg, size_t n,
                const uint8_t tag[MAC1_LEN]);

#endif
