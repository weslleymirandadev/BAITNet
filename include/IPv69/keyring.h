/* keyring.h - SSH-style key storage for IPv69 (~/.hosts69/).
 *
 * Layout (like ~/.ssh):
 *   ~/.hosts69/key       private seed (32B hex), optionally encrypted
 *                        with a passphrase (secretbox, "H69E1" magic)
 *   ~/.hosts69/key.pub   public key + comment: "<hex> <name>"
 *
 * A key with a passphrase is decrypted on load: the passphrase comes
 * from IPV69_PASSPHRASE or is prompted on the tty (like ssh).
 */
#ifndef IPV69_KEYRING_H
#define IPV69_KEYRING_H

#include <stdint.h>
#include <stddef.h>

/* fill `dir`, `key` and `pub` with the default paths under $HOME/.hosts69 */
void keyring_paths(char *dir, size_t dirsz, char *key, size_t keysz,
                   char *pub, size_t pubsz);

/* load the private seed + public key + comment from `key`/`key.pub`.
 * If the key does not exist, generate one (no passphrase) and persist
 * it. Returns 0 on success (sk[0..31]=seed, sk[32..63]=pub), -1 on
 * error. Prints the pubkey on first generation. */
int keyring_load_or_create(const char *key, const char *pub,
                           uint8_t sk[64], uint8_t pubkey[32],
                           char *comment, size_t commentsz);

/* generate a keypair and save it (encrypted with passphrase if
 * non-empty). Writes key (0600) + key.pub. Returns 0 / -1. */
int keyring_create(const char *key, const char *pub,
                   const char *passphrase, const char *comment);

/* ssh-keygen style passphrase prompt: reads from /dev/tty with echo
   OFF, asks twice, retries until they match. Returns 0 with `out`
   filled (empty string = no passphrase), -1 on error/EOF. */
int keyring_prompt_passphrase(char *out, size_t outsz);

#endif
