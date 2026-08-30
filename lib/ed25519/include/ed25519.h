/* ed25519.h - standalone Ed25519 (RFC 8032) + persistent key store.
 *
 * Thin, dependency-free wrapper over TweetNaCl (public domain). The IPv69
 * stack uses it to sign DHCP69 messages; the future IPv69 stream transport
 * (next_header 2, "own HTTPS") can reuse this same library for its
 * handshake without depending on IPv69 code.
 *
 * Keys: the private key is a 32-byte seed; sk[64] = seed || pub
 * (TweetNaCl layout). The seed never leaves the device.
 */
#ifndef ED25519_H
#define ED25519_H

#include <stdint.h>
#include <stddef.h>

#define ED25519_SEED_LEN 32
#define ED25519_PUB_LEN  32
#define ED25519_SIG_LEN  64
#define ED25519_SK_LEN   64

/* Generate a new keypair. sk[0..31] = seed, sk[32..63] = pub.
 * Returns 0 on success, -1 on error. */
int ed25519_keypair(uint8_t sk[ED25519_SK_LEN], uint8_t pub[ED25519_PUB_LEN]);

/* Derive the public key from a fixed 32-byte seed (RFC 8032). */
int ed25519_seed_to_pub(uint8_t pub[ED25519_PUB_LEN],
                        const uint8_t seed[ED25519_SEED_LEN]);

/* Sign `n` bytes of `msg`; writes the 64-byte signature to `sig`.
 * Only the first 32 bytes of `sk` (the seed) are used; the public key
 * is derived internally. Returns 0 on success, -1 on error. */
int ed25519_sign(uint8_t sig[ED25519_SIG_LEN], const uint8_t *msg, size_t n,
                 const uint8_t sk[ED25519_SK_LEN]);

/* Verify `sig` over `n` bytes of `msg`. Returns 0 if valid, -1 if not. */
int ed25519_verify(const uint8_t *msg, size_t n,
                   const uint8_t sig[ED25519_SIG_LEN],
                   const uint8_t pub[ED25519_PUB_LEN]);

/* Load the device key from `path`, or generate + persist it on first run
 * (seed hex, mode 0600). On creation prints the public key so it can be
 * registered elsewhere. Returns 0 on success, -1 on error. */
int ed25519_keyfile_load_or_create(const char *path,
                                   uint8_t sk[ED25519_SK_LEN],
                                   uint8_t pub[ED25519_PUB_LEN]);

/* Default key path: $HOME/.ipv69/key (fallback /root/.ipv69/key). */
void ed25519_keyfile_default_path(char *out, size_t outsz);

#endif
