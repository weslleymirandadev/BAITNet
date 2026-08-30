/* randombytes.c - getrandom() backend for TweetNaCl (Linux + Android). */
#include <stdint.h>
#include <sys/random.h>
#include "IPv69/tweetnacl.h"

void randombytes(uint8_t *buf, uint64_t n)
{
    while (n > 0) {
        ssize_t r = getrandom(buf, n, 0);
        if (r <= 0)
            continue;
        buf += r;
        n -= (uint64_t)r;
    }
}
