/* ipv69-keygen - generate an Ed25519 keypair for DHCP69 auth.
 *
 * Usage (ssh-keygen style):
 *   ipv69 keygen [-f PATH | --key-file PATH] [-C COMMENT] [-N PASSPHRASE]
 *                [count]
 *
 *   -f PATH / --key-file PATH
 *                private key file (default ~/.hosts69/key); a bare name
 *                (no '/') resolves inside ~/.hosts69/, so named keys
 *                live side by side; the public key goes to PATH.pub
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
#ifdef _WIN32
#include <winsock2.h>   /* gethostname for the key comment */
#include <direct.h>     /* _mkdir */
#else
#include <unistd.h>
#endif
#include <sys/stat.h>
#include "ed25519.h"
#include "IPv69/keyring.h"
#include "IPv69/plat.h"     /* plat_setenv/unsetenv (pubkey display) */

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
    int count = 0;                  /* explicit count arg -> stdout mode */
    int force = 0;

    for (int i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-f") || !strcmp(argv[i], "--key-file")) &&
            i + 1 < argc)
            fpath = argv[++i];
        else if (!strcmp(argv[i], "-C") && i + 1 < argc)
            comment_arg = argv[++i];
        else if (!strcmp(argv[i], "-N") && i + 1 < argc)
            pass_arg = argv[++i];
        else if (!strcmp(argv[i], "--force"))
            force = 1;
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

    /* plain stdout mode: N keypairs, one per line (only with an
       explicit count argument; no -f means the default keyring path) */
    if (!fpath && count > 0) {
        if (count > 100) {
            fprintf(stderr, "Usage: %s [-f PATH|--key-file PATH] [-C COMMENT] [-N PASS] [count]\n",
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

    /* file mode: <key> + <key>.pub. No -f: the default keyring
       (~/.hosts69/key, IPV69_KEYFILE env honored). Bare names (no '/')
       resolve inside the keyring dir, like ssh-keygen -f id_rsa; a
       leading ~/ expands; anything else is a path as given. */
    char key[1024], pub[1024], dir[1024];
    const char *home = getenv("HOME");
    if (!home)
        home = "/root";
    if (!fpath) {
        char kdir[256], kpub[512];
        keyring_paths(kdir, sizeof(kdir), key, sizeof(key), kpub,
                      sizeof(kpub));
    } else if (fpath[0] == '~' && fpath[1] == '/') {
        snprintf(key, sizeof(key), "%s%s", home, fpath + 1);
    } else if (strchr(fpath, '/')) {
        snprintf(key, sizeof(key), "%s", fpath);
    } else {
        snprintf(key, sizeof(key), "%s/.hosts69/%s", home, fpath);
    }
    snprintf(pub, sizeof(pub), "%s.pub", key);
    snprintf(dir, sizeof(dir), "%s", key);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) {
        *slash = 0;
        if (*dir)
#ifdef _WIN32
            _mkdir(dir);
#else
            mkdir(dir, 0700);
#endif
    }
    /* never clobber an existing key without explicit approval
       (ssh-keygen style: prompt y/N). */
    if (access(key, F_OK) == 0) {
        fprintf(stderr, "keygen: %s already exists\n", key);
        if (!force) {
            fprintf(stderr, "overwrite? (y/N) ");
            fflush(stderr);
            char ans[8] = { 0 };
            if (!fgets(ans, sizeof(ans), stdin))
                return 1;
            if (ans[0] != 'y' && ans[0] != 'Y') {
                fprintf(stderr, "keygen: aborted (nothing was changed)\n");
                return 1;
            }
        }
    }
    if (keyring_create(key, pub, pass, comment) < 0) {
        fprintf(stderr, "keygen: could not save the key to %s\n", key);
        return 1;
    }
    /* show the pubkey so it can be registered. When the file is
       passphrase-protected, make the passphrase we just used visible to
       the loader - no second prompt, and scripts using -N stay
       non-interactive (the env is restored afterwards). */
    uint8_t pk[32], sk[64];
    char cbuf[128];
    snprintf(cbuf, sizeof(cbuf), "%s", comment);
    {
        char saved[256];
        int had = 0, changed = 0;
        const char *old = getenv("IPV69_PASSPHRASE");
        if (old) {
            had = 1;
            snprintf(saved, sizeof(saved), "%s", old);
        }
        if (*pass && (!had || strcmp(saved, pass))) {
            plat_setenv("IPV69_PASSPHRASE", pass);
            changed = 1;
        }
        int loaded = keyring_load_or_create(key, pub, sk, pk, cbuf,
                                            sizeof(cbuf)) == 0;
        if (changed) {
            if (had)
                plat_setenv("IPV69_PASSPHRASE", saved);
            else
                plat_unsetenv("IPV69_PASSPHRASE");
        }
        if (!loaded)
            return 0;       /* key was created; the pubkey print is a bonus */
        printf("Your identification has been saved in %s\n", key);
        printf("Your public key has been saved in %s\n", pub);
        printf("PUBKEY (register on the server): ");
        print_hex(pk, 32);
        printf(" %s\n", comment);
    }
    return 0;
}
