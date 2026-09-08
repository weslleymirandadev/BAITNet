/* baitname.h - .bait names: labels derived from Ed25519 keys.
 *
 * Part of the BITE web stack (docs/bait-names-spec.md), kept in its
 * own tree (src/BITE, include/BITE) like ICSP: it is the
 * self-authenticating identity of a BITE site, the onion-service
 * model over IPv69. The label is the first 160 bits of SHA-512(pub),
 * base32 (RFC 4648, lowercase, no padding) = exactly 32 chars; the
 * fqdn is "<label>.bait". The first 5 digest bytes are the very
 * bytes ipv69_addr_derive uses for the 40-bit class-C address, so
 * the address of a site is computable from its name alone:
 * resolution is a pure local decode (no DNS, no DHT, the network
 * never sees the name).
 *
 * Vanity (closest possible to *choosing* a name): grind keypairs
 * until the label starts with the wanted prefix, like Tor .onion
 * vanity addresses. base32 = 5 bits/char, so every extra character
 * multiplies the expected work by 32.
 */
#ifndef BITE_BAITNAME_H
#define BITE_BAITNAME_H

#include <stdint.h>
#include <stddef.h>

#define BAIT_LABEL_LEN 32           /* chars (160 bits / 5 per char) */
#define BAIT_ALPHABET  "abcdefghijklmnopqrstuvwxyz234567"

/* .bait label of an Ed25519 pubkey: base32_lower_nopad(SHA-512(pub)[0..19]).
 * Writes exactly BAIT_LABEL_LEN chars + NUL into label[33]. */
void bait_label_from_pub(char label[BAIT_LABEL_LEN + 1], const uint8_t pub[32]);

/* true if `label` is a well-formed derived label: 32 chars of base32
 * (both cases accepted; the canonical form is lowercase). */
int bait_label_valid(const char *label);

/* Decode the label back to the 5-byte class-C address it names. The
 * first 8 label chars hold the first 40 digest bits, masked exactly
 * like ipv69_addr_derive (0x80 | d[0]&0x3f, then d[1..4]) - so the
 * address is derived from the name alone, with no key lookup.
 * Returns 0 on success, -1 if the label is not valid base32. */
int bait_label_to_addr(uint8_t addr[5], const char label[BAIT_LABEL_LEN + 1]);

/* progress callback for bait_grind: called periodically with the try
 * count and the best partial label found so far (first best_chars of
 * best_label match the prefix). best_label == NULL when nothing
 * matched yet. */
typedef void (*bait_progress_fn)(uint64_t tries, const char *best_label,
                                 int best_chars, void *arg);

/* Vanity grind: generate keypairs until the .bait label starts with
 * `prefix` (chars must be in BAIT_ALPHABET, 1..32 long). On success
 * stores the winning keypair (sk[64] seed||pub, pk[32]) and its label
 * and the number of tries; returns 0. Returns -1 on an invalid prefix
 * or key generation failure. Offline and interruptible: Ctrl-C aborts
 * and nothing is saved (the keypair only exists in memory until the
 * caller persists it). */
int bait_grind(const char *prefix, uint8_t sk[64], uint8_t pk[32],
               char label[BAIT_LABEL_LEN + 1], uint64_t *tries,
               bait_progress_fn progress, void *arg);

#endif
