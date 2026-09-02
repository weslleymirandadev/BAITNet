/* ratelimit.h - per-sender token bucket, fixed table, WG-style.
 *
 * WireGuard rate-limits handshakes per peer (once per REKEY_TIMEOUT)
 * so a single source cannot exhaust the server CPU. Here the bucket id
 * is the sender MAC (L2) or UDP endpoint; the table is small and fixed
 * (no allocation under attack), with LRU-ish eviction.
 */
#ifndef IPV69_RATELIMIT_H
#define IPV69_RATELIMIT_H

#include <stdint.h>
#include <stddef.h>

#define RATE_SLOTS 64

struct rate_bucket {
    uint8_t  id[8];             /* sender id (MAC or endpoint hash) */
    uint8_t  used;
    uint32_t tokens;            /* current token count (fixed point) */
    uint32_t last_ms;           /* last refill timestamp */
};

/* global table (one per process) */
extern struct rate_bucket g_rate[RATE_SLOTS];

/* allow `cost` tokens for sender `id` at rate rate_per_s, burst
 * capacity. Returns 1 if allowed (tokens deducted), 0 if throttled. */
int rate_allow(const uint8_t id[8], int rate_per_s, int burst, int cost);

/* monotonic millisecond clock (portable) */
uint32_t rate_now_ms(void);

#endif
