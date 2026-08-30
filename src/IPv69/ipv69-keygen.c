/* ipv69-keygen - generate an Ed25519 keypair for DHCP69 auth.
 *
 * Usage: ipv69-keygen [count]
 * Prints one keypair per line: <privkey_hex> <pubkey_hex>
 *
 * The private key stays on the device that owns it. Register the PUBLIC
 * key on the DHCP server (af69d --peer). Nobody else ever needs the
 * private key; a leaked/revoked key only affects that one device.
 */
#include <stdio.h>
#include "IPv69/tweetnacl.h"

static void print_hex(const unsigned char *b, int n)
{
    for (int i = 0; i < n; i++)
        printf("%02x", b[i]);
}

int main(int argc, char **argv)
{
    int count = argc > 1 ? atoi(argv[1]) : 1;

    if (count < 1 || count > 100) {
        fprintf(stderr, "Usage: %s [count 1-100]\n", argv[0]);
        return 1;
    }
    for (int i = 0; i < count; i++) {
        unsigned char pk[32], sk[64];
        crypto_sign_keypair(pk, sk);
        print_hex(sk, 32);
        putchar(' ');
        print_hex(pk, 32);
        putchar('\n');
    }
    return 0;
}
