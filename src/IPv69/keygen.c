/* ipv69-keygen - generate an Ed25519 keypair for DHCP69 auth.
 *
 * Usage (ssh-keygen style):
 *   ipv69 keygen [-f PATH | --key-file PATH] [-C COMMENT] [-N PASSPHRASE]
 *                [count]
  *   ipv69 keygen --vanity PREFIX [-f PATH] [-N PASSPHRASE]
  *                (.bait vanity: grind a keypair whose label starts
  *                 with PREFIX; see docs/bait-names-spec.md)
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
#include <io.h>         /* _isatty/_fileno (interactive prompt) */
#else
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <time.h>           /* clock(): vanity progress rate */
#include "ed25519.h"
#include "IPv69/keyring.h"
#include "IPv69/plat.h"     /* plat_setenv/unsetenv (pubkey display) */
#include "BITE/baitname.h"  /* .bait labels + vanity grind */

static void print_hex(const unsigned char *b, int n)
{
    for (int i = 0; i < n; i++)
        printf("%02x", b[i]);
}

struct vanity_prog {
    double last;            /* last progress line (clock(), seconds) */
    size_t want;            /* prefix length */
};

/* periodic bait_grind callback: one stderr line every ~2s with the
 * try count, the rate and the best partial prefix found so far. */
static void vanity_progress(uint64_t tries, const char *best_label,
                            int best_chars, void *arg)
{
    struct vanity_prog *vp = (struct vanity_prog *)arg;
    double now = (double)clock() / CLOCKS_PER_SEC;

    if (now - vp->last < 2.0)
        return;
    vp->last = now;
    fprintf(stderr, "keygen: vanity %llu tries (%.0f/s), best %d/%zu chars: %.*s\n",
            (unsigned long long)tries, (double)tries / now,
            best_chars, vp->want,
            best_chars, best_label ? best_label : "");
}

/* 1 when stdin is an interactive terminal (a human at the keyboard) —
 * the ssh-keygen-style file prompt only makes sense then. */
static int stdin_is_tty(void)
{
#ifdef _WIN32
    return _isatty(_fileno(stdin));
#else
    return isatty(0);
#endif
}

int cmd_keygen(int argc, char **argv)
{
    const char *fpath = NULL;
    const char *comment_arg = NULL;
    const char *pass_arg = NULL;
    const char *vanity = NULL;
    size_t vanity_len = 0;
    char comment[128];
    char pass[256];
    char named[512];        /* ssh-keygen: typed key file name */
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
        else if (!strcmp(argv[i], "--vanity") && i + 1 < argc)
            vanity = argv[++i];
        else if (!strcmp(argv[i], "--force"))
            force = 1;
        else
            count = atoi(argv[i]);
    }
    /* validate the vanity prefix up front: fail before prompting or
       grinding anything (chars must be valid base32, 1..32 long). */
    if (vanity) {
        if (count > 0) {
            fprintf(stderr, "keygen: --vanity cannot be combined with a batch count\n");
            return 1;
        }
        vanity_len = strlen(vanity);
        if (!vanity_len || vanity_len > BAIT_LABEL_LEN) {
            fprintf(stderr, "keygen: vanity prefix must be 1..%d base32 chars (a-z2-7)\n",
                    BAIT_LABEL_LEN);
            return 1;
        }
        for (size_t i = 0; i < vanity_len; i++)
            if (!strchr(BAIT_ALPHABET, vanity[i])) {
                fprintf(stderr, "keygen: vanity prefix has an invalid char '%c' (use a-z2-7)\n",
                        vanity[i]);
                return 1;
            }
    }
    /* ssh-keygen style: without -f (and outside the stdout batch
       mode) ask where to save the NEW key when stdin is a tty — the
       default path is only a suggestion, the user may name the key
       (bare names resolve inside ~/.hosts69/). Enter = the default.
       Off a tty (scripts, auto-key) — or when IPV69_KEYFILE already
       chose the file (a leading --key-file was stripped by the
       dispatcher) — the default is used silently, exactly as before. */
    const char *kfenv = getenv("IPV69_KEYFILE");
    if (!fpath && count == 0 && !(kfenv && *kfenv) && stdin_is_tty()) {
        char ddir[1024], dkey[1024], dpub[1024];
        keyring_paths(ddir, sizeof(ddir), dkey, sizeof(dkey), dpub,
                      sizeof(dpub));
        fprintf(stderr, "Enter file in which to save the key (%s): ",
                dkey);
        fflush(stderr);
        if (fgets(named, sizeof(named), stdin)) {
            named[strcspn(named, "\r\n")] = 0;
            if (named[0])
                fpath = named;
        }
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
    } else if (fpath || vanity || (!count && stdin_is_tty())) {
        /* ssh-keygen style: prompt twice, no echo, until they match.
           Interactive runs always ask — even when the default key file
           was accepted (Enter) — so a new key is never silently
           saved without the chance to protect it. Without a tty
           (scripts) an empty passphrase is used. */
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
       leading ~/ expands; anything else is a path as given.
       Resolution loops: when the destination exists and the user
       refuses the overwrite, a NEW file name is asked and the
       resolution restarts with it — the keygen never aborts on "n"
       while a human is at the keyboard. */
    char key[1024], pub[1024], dir[1024], newname[512];
    const char *home = getenv("HOME");
    if (!home)
        home = "/root";
    for (;;) {
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
        if (access(key, F_OK) != 0)
            break;                      /* free destination */
        fprintf(stderr, "keygen: %s already exists\n", key);
        if (force)
            break;                      /* --force: silent overwrite */
        fprintf(stderr, "overwrite? (y/N) ");
        fflush(stderr);
        char ans[8] = { 0 };
        if (!fgets(ans, sizeof(ans), stdin)) {
            fprintf(stderr, "keygen: aborted (nothing was changed)\n");
            return 1;                   /* EOF: give up */
        }
        if (ans[0] == 'y' || ans[0] == 'Y')
            break;                      /* overwrite approved */
        if (!stdin_is_tty()) {
            fprintf(stderr, "keygen: aborted (nothing was changed)\n");
            return 1;                   /* no human to ask a new name */
        }
        fprintf(stderr, "Enter a new file in which to save the key: ");
        fflush(stderr);
        if (!fgets(newname, sizeof(newname), stdin)) {
            fprintf(stderr, "keygen: aborted (nothing was changed)\n");
            return 1;
        }
        newname[strcspn(newname, "\r\n")] = 0;
        if (!newname[0]) {
            fprintf(stderr, "keygen: aborted (nothing was changed)\n");
            return 1;
        }
        fpath = newname;                /* resolve again with this name */
    }
    if (vanity) {
        /* grind until the .bait label starts with the prefix, then
           persist the winning keypair (keyring_save). The overwrite
           prompt above already ran, so a long grind is never wasted
           on a destination the user would refuse. */
        uint8_t vsk[64], vpk[32];
        char vlabel[BAIT_LABEL_LEN + 1];
        uint64_t vtries = 0;
        struct vanity_prog vp;
        vp.last = 0.0;
        vp.want = vanity_len;
        fprintf(stderr, "keygen: grinding for a .bait label starting with \"%s\" "
                        "(Ctrl-C aborts, nothing is saved)...\n", vanity);
        if (bait_grind(vanity, vsk, vpk, vlabel, &vtries,
                       vanity_progress, &vp) < 0) {
            fprintf(stderr, "keygen: vanity grind failed\n");
            return 1;
        }
        fprintf(stderr, "keygen: label %s.bait found after %llu tries\n",
                vlabel, (unsigned long long)vtries);
        if (keyring_save(key, pub, pass, comment, vsk, vpk) < 0) {
            fprintf(stderr, "keygen: could not save the key to %s\n", key);
            return 1;
        }
    } else if (keyring_create(key, pub, pass, comment) < 0) {
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
        {
            char blabel[BAIT_LABEL_LEN + 1];
            bait_label_from_pub(blabel, pk);
            printf("bait name (docs/bait-names-spec.md): %s.bait\n", blabel);
        }
    }
    return 0;
}
