/* ipv69-keygen - generate an Ed25519 keypair for DHCP69 auth.
 *
 * Usage (ssh-keygen style):
 *   ipv69 keygen [-f PATH] [-C COMMENT] [-N PASSPHRASE] [count]
 *
 *   -f PATH      private key file (default ~/.hosts69/key); the public
 *                key goes to PATH.pub
 *   -C COMMENT   comment/name stored in key.pub (default: hostname)
 *   -N PASSPHRASE encrypt the private key with this passphrase
 *   count        when -f is not given: print N keypairs to stdout
 *
 * The private key stays on the device that owns it. Register the PUBLIC
 * key on the DHCP server (ipv69 dhcpd --peer). Nobody else ever needs
 * the private key.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ed25519.h"
#include <sys/stat.h>
#include "IPv69/keyring.h"

static void print_hex(const unsigned char *b, int n)
{
    for (int i = 0; i < n; i++)
        printf("%02x", b[i]);
}

int cmd_keygen(int argc, char **argv)
{
    const char *fpath = NULL;
    const char *comment_arg = NULL;
    const char *pass_arg = NULL;
    char comment[128];
    char pass[256];
    int count = 1;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-f") && i + 1 < argc)
            fpath = argv[++i];
        else if (!strcmp(argv[i], "-C") && i + 1 < argc)
            comment_arg = argv[++i];
        else if (!strcmp(argv[i], "-N") && i + 1 < argc)
            pass_arg = argv[++i];
        else
            count = atoi(argv[i]);
    }
    if (comment_arg) {
        snprintf(comment, sizeof(comment), "%s", comment_arg);
    } else {
        char hn[64];
        gethostname(hn, sizeof(hn));
        hn[sizeof(hn) - 1] = 0;
        snprintf(comment, sizeof(comment), "%s", hn);
    }
    pass[0] = 0;
    if (pass_arg) {
        snprintf(pass, sizeof(pass), "%s", pass_arg);
    } else if (fpath) {
        /* ssh-keygen style: prompt twice, no echo, until they match.
           Without a tty (scripts) an empty passphrase is used. */
        if (keyring_prompt_passphrase(pass, sizeof(pass)) < 0)
            pass[0] = 0;
    }

    /* plain stdout mode: N keypairs, one per line */
    if (!fpath) {
        if (count < 1 || count > 100) {
            fprintf(stderr, "Usage: %s [-f PATH] [-C COMMENT] [-N PASS] [count]\n",
                    argv[0]);
            return 1;
        }
        for (int i = 0; i < count; i++) {
            unsigned char pk[32], sk[64];
            ed25519_keypair(sk, pk);
            print_hex(sk, 32);
            putchar(' ');
            print_hex(pk, 32);
            putchar('\n');
        }
        return 0;
    }

    /* file mode: ~/.hosts69/key + key.pub */
    char key[1024], pub[1024];
    if (fpath[0] == '~') {
        /* expand ~ */
        const char *home = getenv("HOME");
        char buf[1024];
        if (!home)
            home = "/root";
        snprintf(buf, sizeof(buf), "%s%s", home, fpath + 1);
        fpath = buf;
    }
    snprintf(key, sizeof(key), "%s", fpath);
    snprintf(pub, sizeof(pub), "%s", fpath);
    strncat(pub, ".pub", sizeof(pub) - strlen(pub) - 1);
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s", fpath);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = 0;
        if (*dir)
            mkdir(dir, 0700);
    }
    if (keyring_create(key, pub, pass, comment) < 0) {
        fprintf(stderr, "keygen: nao foi possivel salvar a chave em %s\n", key);
        return 1;
    }
    /* show the pubkey so it can be registered */
    uint8_t pk[32], sk[64];
    char cbuf[128];
    snprintf(cbuf, sizeof(cbuf), "%s", comment);
    if (keyring_load_or_create(key, pub, sk, pk, cbuf, sizeof(cbuf)) == 0) {
        printf("Your identification has been saved in %s\n", key);
        printf("Your public key has been saved in %s\n", pub);
        printf("PUBKEY (register on the server): ");
        print_hex(pk, 32);
        printf(" %s\n", comment);
    }
    return 0;
}
