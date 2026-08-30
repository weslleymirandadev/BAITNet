/* hmac.c - HMAC-SHA256 (RFC 2104 + FIPS 180-4), compact standalone impl.
 * Public domain style; used for the DHCP69 shared-secret auth token.
 */
#include <string.h>
#include "IPv69/hmac.h"

typedef uint32_t u32;

static const u32 K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static u32 rotr(u32 x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_block(u32 h[8], const uint8_t *p)
{
    u32 w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((u32)p[i * 4] << 24) | ((u32)p[i * 4 + 1] << 16) |
               ((u32)p[i * 4 + 2] << 8) | p[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
        u32 s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        u32 s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    u32 a = h[0], b = h[1], c = h[2], d = h[3];
    u32 e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        u32 S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        u32 ch = (e & f) ^ (~e & g);
        u32 t1 = hh + S1 + ch + K[i] + w[i];
        u32 S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        u32 maj = (a & b) ^ (a & c) ^ (b & c);
        u32 t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

/* one-shot SHA-256 (msg_len < 2^61 for our use) */
static void sha256(const uint8_t *msg, size_t len, uint8_t out[32])
{
    u32 h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    uint8_t block[64];
    size_t i = 0;

    while (len - i >= 64) {
        sha256_block(h, msg + i);
        i += 64;
    }
    memset(block, 0, sizeof(block));
    memcpy(block, msg + i, len - i);
    block[len - i] = 0x80;
    if (len - i >= 56) {          /* pad overflows into a 2nd block */
        sha256_block(h, block);
        memset(block, 0, sizeof(block));
    }
    uint64_t bits = (uint64_t)len * 8;
    for (int j = 0; j < 8; j++)
        block[63 - j] = (bits >> (8 * j)) & 0xff;
    sha256_block(h, block);
    for (int j = 0; j < 8; j++) {
        out[j * 4] = h[j] >> 24; out[j * 4 + 1] = h[j] >> 16;
        out[j * 4 + 2] = h[j] >> 8; out[j * 4 + 3] = h[j];
    }
}

void ipv69_hmac(const uint8_t *key, size_t key_len,
                const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    uint8_t k[64], ipad[64], opad[64], inner[64 + 32], outer[64 + 32];

    memset(k, 0, sizeof(k));
    if (key_len > 64) {
        sha256(key, key_len, k);
    } else {
        memcpy(k, key, key_len);
    }
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    memcpy(inner, ipad, 64);
    memcpy(inner + 64, msg, msg_len);
    sha256(inner, 64 + msg_len, inner + 64);   /* reuse tail as digest buf */
    memcpy(outer, opad, 64);
    memcpy(outer + 64, inner + 64, 32);
    sha256(outer, 64 + 32, out);
}
