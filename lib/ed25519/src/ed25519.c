/* ed25519.c - standalone Ed25519 wrapper over TweetNaCl.
 *
 * The TweetNaCl crypto_sign API is awkward to use directly: it writes
 * [sig 64][msg] concatenated and crypto_sign_open mutates its input
 * buffer. This wrapper exposes the natural sign/verify split (sig and
 * msg kept separate), so callers never touch TweetNaCl internals.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "ed25519.h"
#include "tweetnacl.h"

int ed25519_keypair(uint8_t sk[ED25519_SK_LEN], uint8_t pub[ED25519_PUB_LEN])
{
    return crypto_sign_keypair(pub, sk);
}

int ed25519_seed_to_pub(uint8_t pub[ED25519_PUB_LEN],
                        const uint8_t seed[ED25519_SEED_LEN])
{
    return crypto_sign_seed_to_pk(pub, seed);
}

int ed25519_sign(uint8_t sig[ED25519_SIG_LEN], const uint8_t *msg, size_t n,
                 const uint8_t sk[ED25519_SK_LEN])
{
    uint8_t full_sk[ED25519_SK_LEN];
    uint8_t *sm = malloc(ED25519_SIG_LEN + n);
    unsigned long long smlen;

    if (!sm)
        return -1;
    /* TweetNaCl needs sk[64] = seed || pub (pub enters the hash); derive
       it here so callers only need to keep the 32-byte seed */
    memcpy(full_sk, sk, ED25519_SEED_LEN);
    ed25519_seed_to_pub(full_sk + ED25519_SEED_LEN, sk);
    crypto_sign(sm, &smlen, msg, n, full_sk);
    memcpy(sig, sm, ED25519_SIG_LEN);
    free(sm);
    return 0;
}

int ed25519_verify(const uint8_t *msg, size_t n,
                   const uint8_t sig[ED25519_SIG_LEN],
                   const uint8_t pub[ED25519_PUB_LEN])
{
    uint8_t *sm = malloc(ED25519_SIG_LEN + n);
    uint8_t *m = malloc(ED25519_SIG_LEN + n);
    unsigned long long mlen;
    int rc;

    if (!sm || !m) {
        free(sm);
        free(m);
        return -1;
    }
    memcpy(sm, sig, ED25519_SIG_LEN);
    memcpy(sm + ED25519_SIG_LEN, msg, n);
    rc = crypto_sign_open(m, &mlen, sm, ED25519_SIG_LEN + n, pub);
    free(sm);
    free(m);
    return rc == 0 ? 0 : -1;
}

int ed25519_keyfile_load_or_create(const char *path,
                                   uint8_t sk[ED25519_SK_LEN],
                                   uint8_t pub[ED25519_PUB_LEN])
{
    char seedhex[65], line[80];
    FILE *f;

    f = fopen(path, "r");
    if (f) {
        if (!fgets(line, sizeof(line), f)) {
            fclose(f);
            return -1;
        }
        fclose(f);
        line[strcspn(line, "\n")] = 0;
        if (strlen(line) != 64)
            return -1;
        for (int i = 0; i < ED25519_SEED_LEN; i++) {
            unsigned v;
            if (sscanf(line + 2 * i, "%2x", &v) != 1)
                return -1;
            sk[i] = (uint8_t)v;
        }
        ed25519_seed_to_pub(sk + 32, sk);
        memcpy(pub, sk + 32, ED25519_PUB_LEN);
        return 0;
    }

    /* first run: generate and persist */
    if (ed25519_keypair(sk, pub) != 0)
        return -1;
    for (int i = 0; i < ED25519_SEED_LEN; i++)
        snprintf(seedhex + 2 * i, 3, "%02x", sk[i]);
    seedhex[64] = 0;
    char dir[256];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = 0;
        mkdir(dir, 0700);
    }
    f = fopen(path, "w");
    if (!f)
        return -1;
    fchmod(fileno(f), 0600);
    fprintf(f, "%s\n", seedhex);
    fclose(f);
    printf("ipv69: chave gerada em %s\n", path);
    printf("ipv69: registre esta PUBKEY no servidor (--peer ou --peer-file):\n");
    for (int i = 0; i < ED25519_PUB_LEN; i++)
        printf("%02x", pub[i]);
    printf("\n");
    return 0;
}

void ed25519_keyfile_default_path(char *out, size_t outsz)
{
    const char *home = getenv("HOME");

    if (!home || !*home)
        home = "/root";
    snprintf(out, outsz, "%s/.ipv69/key", home);
}

void ed25519_sha512(uint8_t out[64], const uint8_t *msg, size_t n)
{
    crypto_hash(out, msg, n);
}
