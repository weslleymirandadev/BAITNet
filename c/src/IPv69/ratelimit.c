/* ratelimit.c - per-sender token bucket (see ratelimit.h). */
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif
#include "IPv69/ratelimit.h"

struct rate_bucket g_rate[RATE_SLOTS];

uint32_t rate_now_ms(void)
{
#ifdef _WIN32
    return (uint32_t)GetTickCount();
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint32_t)((uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000);
#endif
}

int rate_allow(const uint8_t id[8], int rate_per_s, int burst, int cost)
{
    uint32_t now = rate_now_ms();
    struct rate_bucket *b = NULL, *oldest = &g_rate[0];
    uint32_t oldest_ts = 0xFFFFFFFFu;

    for (int i = 0; i < RATE_SLOTS; i++) {
        struct rate_bucket *c = &g_rate[i];
        if (c->used && !memcmp(c->id, id, 8)) {
            b = c;
            break;
        }
        if (!c->used) {
            oldest = c;         /* first free slot */
            break;
        }
        if (c->last_ms < oldest_ts) {
            oldest_ts = c->last_ms;
            oldest = c;
        }
    }
    if (!b) {
        b = oldest;
        memcpy(b->id, id, 8);
        b->used = 1;
        b->tokens = (uint32_t)burst;
        b->last_ms = now;
    }
    /* refill: rate_per_s tokens per second (fixed point x1000) */
    uint32_t elapsed = now - b->last_ms;
    if (elapsed > 0) {
        uint64_t gain = (uint64_t)rate_per_s * elapsed / 1000;
        b->tokens = (uint32_t)(b->tokens + gain);
        if (b->tokens > (uint32_t)burst)
            b->tokens = (uint32_t)burst;
        b->last_ms = now;
    }
    if (b->tokens < (uint32_t)cost) {
        b->tokens = 0;
        return 0;
    }
    b->tokens -= (uint32_t)cost;
    return 1;
}
