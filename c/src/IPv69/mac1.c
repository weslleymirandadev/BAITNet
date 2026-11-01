/* mac1.c - WireGuard-style cheap pre-auth filter (see mac1.h). */
#include <string.h>
#include "ed25519.h"
#include "IPv69/mac1.h"

void mac1_key(uint64_t server_addr, uint8_t key[32])
{
    uint8_t buf[10 + 5];    /* "ipv69-mac1" + addr40 BE */
    uint8_t h[64];

    memcpy(buf, "ipv69-mac1", 10);
    buf[10] = (uint8_t)(server_addr >> 32);
    buf[11] = (uint8_t)(server_addr >> 24);
    buf[12] = (uint8_t)(server_addr >> 16);
    buf[13] = (uint8_t)(server_addr >> 8);
    buf[14] = (uint8_t)server_addr;
    ed25519_sha512(h, buf, sizeof(buf));
    memcpy(key, h, 32);
}

void mac1_compute(const uint8_t key[32], const uint8_t *msg, size_t n,
                  uint8_t out[MAC1_LEN])
{
    ed25519_poly1305(out, msg, n, key);
}

int mac1_verify(const uint8_t key[32], const uint8_t *msg, size_t n,
                const uint8_t tag[MAC1_LEN])
{
    return ed25519_poly1305_verify(tag, msg, n, key);
}
