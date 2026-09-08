/* baitname.c - .bait names: labels derived from Ed25519 keys.
 *
 * See baitname.h and docs/bait-names-spec.md. Lives in its own tree
 * (src/BITE) like ICSP; only depends on lib/ed25519 (SHA-512 +
 * keypair), so it is reusable from the static lib and from BITE tools
 * without the rest of the IPv69 CLI.
 */
#include <string.h>
#include "ed25519.h"
#include "BITE/baitname.h"

static const char B32A[] = BAIT_ALPHABET;

/* base32 char -> value (0..31), -1 if not in the alphabet.
 * Both cases are accepted; the canonical form is lowercase. */
static int b32v(char c)
{
    if (c >= 'a' && c <= 'z')
        return c - 'a';
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= '2' && c <= '7')
        return c - '2' + 26;
    return -1;
}

void bait_label_from_pub(char label[BAIT_LABEL_LEN + 1], const uint8_t pub[32])
{
    uint8_t d[64];
    uint32_t acc = 0;
    int nbits = 0, o = 0;

    ed25519_sha512(d, pub, 32);
    /* 20 digest bytes = 160 bits = 32 base32 chars exactly */
    for (int i = 0; i < 20; i++) {
        acc = (acc << 8) | d[i];
        nbits += 8;
        while (nbits >= 5) {
            nbits -= 5;
            label[o++] = B32A[(acc >> nbits) & 0x1f];
        }
    }
    label[o] = 0;
}

int bait_label_valid(const char *label)
{
    if (!label || strlen(label) != BAIT_LABEL_LEN)
        return 0;
    for (int i = 0; i < BAIT_LABEL_LEN; i++)
        if (b32v(label[i]) < 0)
            return 0;
    return 1;
}

int bait_label_to_addr(uint8_t addr[5], const char label[BAIT_LABEL_LEN + 1])
{
    uint8_t d[5];
    uint32_t acc = 0;
    int nbits = 0, o = 0;

    /* 8 label chars = 40 bits = the first 5 digest bytes = the addr */
    for (int i = 0; i < 8; i++) {
        int v = b32v(label[i]);
        if (v < 0)
            return -1;
        acc = (acc << 5) | (uint32_t)v;
        nbits += 5;
        while (nbits >= 8) {
            nbits -= 8;
            if (o < 5)
                d[o] = (uint8_t)((acc >> nbits) & 0xff);
            o++;
        }
    }
    if (o < 5)
        return -1;
    addr[0] = (uint8_t)(0x80 | (d[0] & 0x3f));   /* class C, parse.c */
    addr[1] = d[1];
    addr[2] = d[2];
    addr[3] = d[3];
    addr[4] = d[4];
    return 0;
}

int bait_grind(const char *prefix, uint8_t sk[64], uint8_t pk[32],
               char label[BAIT_LABEL_LEN + 1], uint64_t *tries,
               bait_progress_fn progress, void *arg)
{
    size_t plen;
    char l[BAIT_LABEL_LEN + 1];
    char best[BAIT_LABEL_LEN + 1];
    int bestlen = 0;
    uint64_t n = 0;

    if (!prefix || !*prefix)
        return -1;
    plen = strlen(prefix);
    if (plen > BAIT_LABEL_LEN)
        return -1;
    for (size_t i = 0; i < plen; i++)
        if (b32v(prefix[i]) < 0)
            return -1;
    best[0] = 0;
    for (;;) {
        if (ed25519_keypair(sk, pk) < 0)
            return -1;
        bait_label_from_pub(l, pk);
        n++;
        if (!memcmp(l, prefix, plen)) {
            memcpy(label, l, BAIT_LABEL_LEN + 1);
            if (tries)
                *tries = n;
            return 0;
        }
        if (progress && bestlen < (int)plen) {
            int m = 0;
            while (m < (int)plen && l[m] == prefix[m])
                m++;
            if (m > bestlen) {
                bestlen = m;
                memcpy(best, l, BAIT_LABEL_LEN + 1);
            }
            if ((n & 0xffff) == 0)
                progress(n, best[0] ? best : NULL, bestlen, arg);
        }
    }
}
