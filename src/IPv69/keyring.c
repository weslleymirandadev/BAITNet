/* keyring.c - SSH-style key storage for IPv69 (~/.hosts69/).
 * See keyring.h for the layout. Passphrase-protected keys use
 * XSalsa20-Poly1305 (secretbox) with a key derived from
 * SHA-512(salt || passphrase).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "ed25519.h"
#include "IPv69/keyring.h"

#define KEY_MAGIC "H69E1"
#define SALT_LEN 16
#define NONCE_LEN 24

static void hex_encode(char *out, const uint8_t *in, size_t n)
{
    for (size_t i = 0; i < n; i++)
        sprintf(out + 2 * i, "%02x", in[i]);
    out[2 * n] = 0;
}

static int hex_decode(const char *hex, uint8_t *out, size_t max)
{
    size_t hl = strlen(hex);

    if (hl % 2 || hl / 2 > max)
        return -1;
    for (size_t j = 0; j < hl / 2; j++) {
        unsigned v;
        if (sscanf(hex + 2 * j, "%2x", &v) != 1)
            return -1;
        out[j] = (uint8_t)v;
    }
    return (int)(hl / 2);
}

void keyring_paths(char *dir, size_t dirsz, char *key, size_t keysz,
                   char *pub, size_t pubsz)
{
    const char *home = getenv("HOME");

    if (!home || !*home)
        home = "/root";
    snprintf(dir, dirsz, "%s/.hosts69", home);
    snprintf(key, keysz, "%s/.hosts69/key", home);
    snprintf(pub, pubsz, "%s/.hosts69/key.pub", home);
}

static int read_line(FILE *f, char *buf, size_t bufsz)
{
    if (!fgets(buf, (int)bufsz, f))
        return -1;
    size_t l = strlen(buf);
    while (l && (buf[l - 1] == '\n' || buf[l - 1] == '\r'))
        buf[--l] = 0;
    return (int)l;
}

static int write_file(const char *path, const char *data, size_t len)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    fchmod(fileno(f), 0600);
    size_t w = fwrite(data, 1, len, f);
    fclose(f);
    return w == len ? 0 : -1;
}

/* read one line from /dev/tty with echo disabled */
static int read_noecho(const char *prompt, char *out, size_t outsz)
{
    FILE *tty = fopen("/dev/tty", "r");
    struct termios old, noecho;

    if (!tty)
        return -1;
    if (tcgetattr(fileno(tty), &old) < 0) {
        fclose(tty);
        return -1;
    }
    noecho = old;
    noecho.c_lflag &= ~ECHO;
    tcsetattr(fileno(tty), TCSAFLUSH, &noecho);
    fprintf(stderr, "%s", prompt);
    fflush(stderr);
    if (!fgets(out, (int)outsz, tty)) {
        tcsetattr(fileno(tty), TCSAFLUSH, &old);
        fclose(tty);
        return -1;
    }
    tcsetattr(fileno(tty), TCSAFLUSH, &old);
    fclose(tty);
    out[outsz - 1] = 0;
    size_t l = strlen(out);
    while (l && (out[l - 1] == '\n' || out[l - 1] == '\r'))
        out[--l] = 0;
    fprintf(stderr, "\n");
    return 0;
}

int keyring_prompt_passphrase(char *out, size_t outsz)
{
    char a[256], b[256];

    for (;;) {
        if (read_noecho("Enter passphrase (empty for no passphrase): ",
                        a, sizeof(a)) < 0)
            return -1;
        if (read_noecho("Enter same passphrase again: ", b, sizeof(b)) < 0)
            return -1;
        if (!strcmp(a, b)) {
            snprintf(out, outsz, "%s", a);
            return 0;
        }
        fprintf(stderr, "Passphrases do not match. Try again.\n");
    }
}

static int read_whole(const char *path, char *buf, size_t bufsz)
{
    FILE *f = fopen(path, "r");
    size_t n;

    if (!f)
        return -1;
    n = fread(buf, 1, bufsz - 1, f);
    fclose(f);
    buf[n] = 0;
    return (int)n;
}

static void derive_key(uint8_t key[32], const uint8_t *salt, size_t saltlen,
                       const char *pass)
{
    uint8_t d[64];
    uint8_t tmp[64];

    ed25519_sha512(d, salt, saltlen);
    ed25519_sha512(tmp, (const uint8_t *)pass, strlen(pass));
    for (int i = 0; i < 32; i++)
        key[i] = d[i] ^ tmp[i];
}

int keyring_create(const char *key, const char *pub,
                   const char *passphrase, const char *comment)
{
    uint8_t sk[64], pk[32];
    char buf[512], hex[256];
    size_t n;

    if (ed25519_keypair(sk, pk) < 0)
        return -1;
    /* private key: seed only */
    hex_encode(hex, sk, 32);
    n = snprintf(buf, sizeof(buf), "%s\n", hex);
    if (*passphrase) {
        uint8_t salt[SALT_LEN], nonce[NONCE_LEN], k[32];
        uint8_t box[32 + 32];           /* n+32: TweetNaCl padding */
        FILE *ur = fopen("/dev/urandom", "r");
        if (!ur)
            return -1;
        if (fread(salt, 1, SALT_LEN, ur) != SALT_LEN ||
            fread(nonce, 1, NONCE_LEN, ur) != NONCE_LEN) {
            fclose(ur);
            return -1;
        }
        fclose(ur);
        derive_key(k, salt, SALT_LEN, passphrase);
        ed25519_secretbox(box, sk, 32, nonce, k);
        char salt_h[33], nonce_h[49], box_h[129];
        hex_encode(salt_h, salt, SALT_LEN);
        hex_encode(nonce_h, nonce, NONCE_LEN);
        hex_encode(box_h, box, 64);
        n = snprintf(buf, sizeof(buf), "%s\n%s\n%s\n%s\n", KEY_MAGIC,
                     salt_h, nonce_h, box_h);
    }
    if (write_file(key, buf, n) < 0)
        return -1;
    /* public key: "<hex> <comment>" */
    hex_encode(hex, pk, 32);
    n = snprintf(buf, sizeof(buf), "%s %s\n", hex, comment);
    if (write_file(pub, buf, n) < 0)
        return -1;
    return 0;
}

static int load_encrypted(const char *path, uint8_t sk[64],
                          uint8_t pubkey[32])
{
    FILE *f = fopen(path, "r");
    char salt_h[64], nonce_h[64], box_h[160];
    uint8_t salt[SALT_LEN], nonce[NONCE_LEN], boxed[64], k[32];
    const char *pass = getenv("IPV69_PASSPHRASE");
    int tries = 0;

    if (!f)
        return -1;
    char magic[16];
    if (read_line(f, magic, sizeof(magic)) < 0 ||
        read_line(f, salt_h, sizeof(salt_h)) < 0 ||
        read_line(f, nonce_h, sizeof(nonce_h)) < 0 ||
        read_line(f, box_h, sizeof(box_h)) < 0) {
        fclose(f);
        return -1;
    }
    fclose(f);
    if (hex_decode(salt_h, salt, SALT_LEN) != SALT_LEN ||
        hex_decode(nonce_h, nonce, NONCE_LEN) != NONCE_LEN ||
        hex_decode(box_h, boxed, 64) != 64)
        return -1;
    for (;;) {
        if (!pass) {
            char *p = getpass("Enter passphrase for key: ");
            if (!p)
                return -1;
            pass = p;
        }
        derive_key(k, salt, SALT_LEN, pass);
        if (ed25519_secretbox_open(sk, boxed, 32, nonce, k) == 0) {
            if (ed25519_seed_to_pub(pubkey, sk) == 0)
                memcpy(sk + 32, pubkey, 32);
            return 0;
        }
        if (tries++ >= 2 || getenv("IPV69_PASSPHRASE")) {
            fprintf(stderr, "keyring: passphrase invalida\n");
            return -1;
        }
        pass = NULL;
    }
}

static int load_comment(const char *pub, char *comment, size_t commentsz)
{
    char buf[1024];

    if (comment && commentsz)
        comment[0] = 0;
    if (read_whole(pub, buf, sizeof(buf)) > 0) {
        char *sp = strchr(buf, ' ');
        if (sp) {
            *sp = 0;
            if (comment)
                snprintf(comment, commentsz, "%s", sp + 1);
            char *nl = strchr(comment ? comment : "", '\n');
            if (nl)
                *nl = 0;
            return 0;
        }
    }
    return -1;
}

int keyring_load_or_create(const char *key, const char *pub,
                           uint8_t sk[64], uint8_t pubkey[32],
                           char *comment, size_t commentsz)
{
    char buf[1024];

    /* encrypted key? */
    if (read_whole(key, buf, sizeof(buf)) > 0 &&
        !strncmp(buf, KEY_MAGIC, 5)) {
        int r = load_encrypted(key, sk, pubkey);
        if (r == 0)
            load_comment(pub, comment, commentsz);
        return r;
    }
    /* plain seed? */
    if (read_whole(key, buf, sizeof(buf)) > 0) {
        char *nl = strchr(buf, '\n');
        if (nl)
            *nl = 0;
        if (hex_decode(buf, sk, 32) == 32) {
            if (ed25519_seed_to_pub(pubkey, sk) < 0)
                return -1;
            memcpy(sk + 32, pubkey, 32);
            load_comment(pub, comment, commentsz);
            return 0;
        }
    }
    /* generate */
    char name[64];
    gethostname(name, sizeof(name));
    name[sizeof(name) - 1] = 0;
    if (keyring_create(key, pub, "", name) < 0)
        return -1;
    if (keyring_load_or_create(key, pub, sk, pubkey, comment, commentsz) < 0)
        return -1;
    printf("ipv69: chave gerada em %s\n", key);
    printf("ipv69: registre esta PUBKEY no servidor (--peer ou --peer-file):\n");
    for (int i = 0; i < 32; i++)
        printf("%02x", pubkey[i]);
    printf("\n");
    return 0;
}
