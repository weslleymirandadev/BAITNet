/* randombytes.c - secure RNG backend for TweetNaCl.
 * POSIX: getrandom(); Windows: BCryptGenRandom. Same interface.
 */
#include <stdint.h>
#include "tweetnacl.h"

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>

void randombytes(uint8_t *buf, uint64_t n)
{
    while (n > 0) {
        ULONG chunk = (ULONG)(n > 0xFFFFFFFFULL ? 0xFFFFFFFFULL : n);
        if (BCryptGenRandom(NULL, buf, chunk,
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
            continue;
        buf += chunk;
        n -= chunk;
    }
}
#else
#include <sys/random.h>

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
#endif
