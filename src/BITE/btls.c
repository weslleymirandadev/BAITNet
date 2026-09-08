/* btls.c - bTLS: the BITE security layer.
 *
 * See btls.h and docs/btls-spec.md. TLS 1.3-flavored handshake:
 *
 *   C -> S: ClientHello (random, eph X25519 pub)          [plaintext]
 *   S -> C: ServerHello (random, eph X25519 pub)          [plaintext]
 *   S -> C: Certificate + CertificateVerify + Finished    [encrypted]
 *   C -> S: Finished                                      [encrypted]
 *
 * Key schedule (HMAC-SHA512, repo style): ECDH shared ->
 * prk = HMAC("btls-v1", shared); per-direction keys =
 * HMAC(prk, label || transcript || 0x01)[0..31]. Handshake traffic
 * keys bind CH+SH; application traffic keys bind the whole transcript
 * (both Finished included). Transcript = SHA-512 over the
 * concatenated handshake frames.
 *
 * Records: plaintext only for the two hellos (fresh ephemeral pubs);
 * everything after is an AEAD record [1][len][secretbox 32+n] with an
 * inner type byte. The server certificate is its raw Ed25519 pub; a
 * client that dialed label.bait verifies base32(SHA-512(cert)[0..19])
 * == label at the Certificate — the name is the pin, no CA.
 */
#include <string.h>
#include "ed25519.h"
#include "BITE/baitname.h"
#include "BITE/btls.h"

/* ---- transcript -------------------------------------------------- */

static void th_append(struct btls *t, const uint8_t *frame, size_t flen)
{
    if (t->thlen + flen <= sizeof(t->thbuf)) {
        memcpy(t->thbuf + t->thlen, frame, flen);
        t->thlen += flen;
    }
}

/* digest = SHA-512("btls/1.0-cert-verify" || transcript) — the message
 * CertificateVerify signs. Domain-separated so a signature made here
 * can never validate anywhere else. */
static void cert_digest(const struct btls *t, uint8_t out[64])
{
    static const char ctx[] = "btls/1.0-cert-verify";
    uint8_t buf[sizeof(ctx) - 1 + sizeof(t->thbuf)];

    memcpy(buf, ctx, sizeof(ctx) - 1);
    memcpy(buf + sizeof(ctx) - 1, t->thbuf, t->thlen);
    ed25519_sha512(out, buf, sizeof(ctx) - 1 + t->thlen);
}

/* ---- key schedule ------------------------------------------------ */

static void derive_key(const struct btls *t, const char *label,
                       uint8_t out[32])
{
    uint8_t info[24 + sizeof(t->thbuf)];
    uint8_t okm[64];
    size_t l = strlen(label);

    /* info = label || transcript || 0x01 (one-shot expand, repo style) */
    memcpy(info, label, l);
    memcpy(info + l, t->thbuf, t->thlen);
    info[l + t->thlen] = 1;
    ed25519_hmac_sha512(okm, info, l + t->thlen + 1, t->prk, 64);
    memcpy(out, okm, 32);
    memset(okm, 0, sizeof(okm));
}

/* prk = HMAC-SHA512(salt "btls-v1", ikm = X25519(eph_priv, peer_eph)) */
static int ecdh_prk(struct btls *t)
{
    uint8_t shared[32];

    if (ed25519_scalarmult(shared, t->eph_priv, t->peer_eph) != 0)
        return -1;
    ed25519_hmac_sha512(t->prk, shared, 32,
                        (const uint8_t *)"btls-v1", 7);
    memset(shared, 0, sizeof(shared));
    return 0;
}

/* install the two directional keys of an epoch from the CURRENT
 * transcript. The client sends with the c2s key, the server with s2c
 * — the two directions never share a key/nonce space. Counters reset
 * per epoch (keys change, nonces restart). */
static void install_epoch(struct btls *t, const char *l_c2s,
                          const char *l_s2c)
{
    uint8_t c2s[32], s2c[32];

    derive_key(t, l_c2s, c2s);
    derive_key(t, l_s2c, s2c);
    memset(t->send_key, 0, sizeof(t->send_key));
    memset(t->recv_key, 0, sizeof(t->recv_key));
    if (t->role == BTLS_CLIENT) {
        memcpy(t->send_key, c2s, 32);
        memcpy(t->recv_key, s2c, 32);
    } else {
        memcpy(t->send_key, s2c, 32);
        memcpy(t->recv_key, c2s, 32);
    }
    memset(c2s, 0, sizeof(c2s));
    memset(s2c, 0, sizeof(s2c));
    t->send_seq = 0;
    t->recv_seq = 0;
}

/* Finished verify_data = HMAC(prk, label || transcript || 0x01)[0..32]
 * over the transcript up to (not including) the Finished itself. */
static void finished_mac(const struct btls *t, const char *label,
                         uint8_t out[32])
{
    derive_key(t, label, out);
}

/* ---- records ----------------------------------------------------- */

/* nonce = [seq 8B BE][zeros 16B]: unique per (key, direction, seq) */
static void rec_nonce(uint8_t nonce[24], uint64_t seq)
{
    memset(nonce, 0, 24);
    for (int i = 7; i >= 0; i--) {
        nonce[i] = (uint8_t)(seq & 0xff);
        seq >>= 8;
    }
}

/* seal one payload into an AEAD application-type record. The box blob
 * is secretbox's 32 + n bytes (16 pad + 16 MAC + ciphertext). */
static int seal_rec(struct btls *t, uint8_t itype, const uint8_t *pl,
                    size_t plen, uint8_t *rec, size_t *reclen)
{
    uint8_t inner[1 + BTLS_MAX_PAYLOAD];
    uint8_t box[33 + BTLS_MAX_PAYLOAD];
    uint8_t nonce[24];
    size_t ilen = 1 + plen;
    size_t blen = 32 + ilen;

    if (plen > BTLS_MAX_PAYLOAD)
        return -1;
    inner[0] = itype;
    if (plen)
        memcpy(inner + 1, pl, plen);
    rec_nonce(nonce, t->send_seq);
    t->send_seq++;
    ed25519_secretbox(box, inner, ilen, nonce, t->send_key);
    rec[0] = BTLS_RT_APPLICATION;
    rec[1] = (uint8_t)(blen >> 8);
    rec[2] = (uint8_t)blen;
    memcpy(rec + 3, box, blen);
    *reclen = 3 + blen;
    return 0;
}

/* open an AEAD record; inner plaintext (with its type byte) in `inner` */
static int open_rec(struct btls *t, const uint8_t *rec, size_t n,
                    uint8_t *inner, size_t *ilen)
{
    uint8_t nonce[24];
    size_t blen;

    if (n < 3 || rec[0] != BTLS_RT_APPLICATION)
        return -1;
    blen = ((size_t)rec[1] << 8) | rec[2];
    /* inner plaintext = blen - 32 must fit the caller's buffer
       (1 + BTLS_MAX_PAYLOAD): reject anything we never produce */
    if (blen < 33 || blen > 33 + BTLS_MAX_PAYLOAD || n != 3 + blen)
        return -1;
    rec_nonce(nonce, t->recv_seq);
    t->recv_seq++;
    if (ed25519_secretbox_open(inner, rec + 3, blen - 32, nonce,
                               t->recv_key) != 0)
        return -1;
    *ilen = blen - 32;
    return 0;
}

/* handshake frame = [type 1][len 2][body] */
static size_t hs_frame(uint8_t *f, uint8_t type, const uint8_t *body,
                       size_t blen)
{
    f[0] = type;
    f[1] = (uint8_t)(blen >> 8);
    f[2] = (uint8_t)blen;
    if (blen)
        memcpy(f + 3, body, blen);
    return 3 + blen;
}

/* ---- handshake --------------------------------------------------- */

void btls_init(struct btls *t, int role, const uint8_t sk[64],
               const char *expect_label)
{
    memset(t, 0, sizeof(*t));
    t->role = role;
    if (sk)
        memcpy(t->sk, sk, 64);
    randombytes(t->eph_priv, 32);
    ed25519_scalarmult_base(t->eph_pub, t->eph_priv);
    if (role == BTLS_CLIENT && expect_label &&
        strlen(expect_label) == BAIT_LABEL_LEN)
        memcpy(t->expect_label, expect_label, BAIT_LABEL_LEN);
}

int btls_client_start(struct btls *t, uint8_t *rec, size_t *reclen)
{
    uint8_t body[64];
    uint8_t frame[3 + 64];
    size_t flen;

    if (!t || t->role != BTLS_CLIENT || t->state != BTLS_ST_INIT)
        return -1;
    randombytes(t->random, 32);
    memcpy(body, t->random, 32);
    memcpy(body + 32, t->eph_pub, 32);
    flen = hs_frame(frame, BTLS_HS_CLIENT_HELLO, body, 64);
    th_append(t, frame, flen);
    rec[0] = BTLS_RT_HANDSHAKE;
    rec[1] = (uint8_t)(flen >> 8);
    rec[2] = (uint8_t)flen;
    memcpy(rec + 3, frame, flen);
    *reclen = 3 + flen;
    t->state = BTLS_ST_CH_SENT;
    t->want_hs = BTLS_HS_SERVER_HELLO;
    return 0;
}

/* consume one encrypted handshake frame (epoch >= 1). Returns 1 when
 * the server just completed the handshake (client FINISHED ok), 0 on
 * progress, -1 on failure. */
static int feed_hs(struct btls *t, const uint8_t *p, size_t len)
{
    uint8_t m[32];

    if (len < 3)
        return -1;
    uint8_t type = p[0];
    size_t blen = ((size_t)p[1] << 8) | p[2];
    const uint8_t *b = p + 3;

    if (3 + blen > len)
        return -1;

    if (t->role == BTLS_SERVER) {
        /* only the client FINISHED arrives after our flight */
        if (t->state != BTLS_ST_WAIT_FIN || type != BTLS_HS_FINISHED ||
            blen != 32)
            return -1;
        finished_mac(t, "btls-fin-c", m);
        if (memcmp(m, b, 32) != 0)
            return -1;
        th_append(t, p, 3 + blen);
        install_epoch(t, "btls-app-c2s", "btls-app-s2c");
        t->epoch = 2;
        t->state = BTLS_ST_DONE;
        return 1;
    }

    /* client: Certificate -> CertificateVerify -> server Finished */
    switch (t->want_hs) {
    case BTLS_HS_CERTIFICATE: {
        char lbl[BAIT_LABEL_LEN + 1];
        if (type != BTLS_HS_CERTIFICATE || blen != 32)
            return -1;
        memcpy(t->cert_pub, b, 32);
        if (t->expect_label[0]) {
            /* the name IS the pin: base32(SHA-512(cert)[0..19]) */
            bait_label_from_pub(lbl, t->cert_pub);
            if (memcmp(lbl, t->expect_label, BAIT_LABEL_LEN) != 0)
                return -1;
        }
        th_append(t, p, 3 + blen);
        t->want_hs = BTLS_HS_CERTIFICATE_VERIFY;
        return 0;
    }
    case BTLS_HS_CERTIFICATE_VERIFY: {
        uint8_t d[64];
        if (type != BTLS_HS_CERTIFICATE_VERIFY || blen != 64)
            return -1;
        cert_digest(t, d);
        if (ed25519_verify(d, 64, b, t->cert_pub) != 0)
            return -1;
        th_append(t, p, 3 + blen);
        t->want_hs = BTLS_HS_FINISHED;
        return 0;
    }
    case BTLS_HS_FINISHED:
        if (type != BTLS_HS_FINISHED || blen != 32)
            return -1;
        finished_mac(t, "btls-fin-s", m);
        if (memcmp(m, b, 32) != 0)
            return -1;
        th_append(t, p, 3 + blen);
        t->want_hs = 0;     /* client emits its own Finished via pump */
        return 0;
    }
    return -1;
}

int btls_feed(struct btls *t, const uint8_t *rec, size_t n)
{
    size_t blen;

    if (!t || !rec || n < 3)
        return -1;
    blen = ((size_t)rec[1] << 8) | rec[2];
    if (blen > BTLS_MAX_REC - 3 || n != 3 + blen)
        return -1;
    const uint8_t *p = rec + 3;

    if (t->epoch == 0) {
        /* plaintext handshake: the two hellos only */
        uint8_t type, hl;
        if (rec[0] != BTLS_RT_HANDSHAKE || blen < 3)
            return -1;
        type = p[0];
        hl = p[2];
        if (t->role == BTLS_SERVER && t->state == BTLS_ST_INIT) {
            if (type != BTLS_HS_CLIENT_HELLO || blen != 3 + 64 || hl != 64)
                return -1;
            memcpy(t->peer_eph, p + 3 + 32, 32);
            th_append(t, p, blen);
            t->state = BTLS_ST_HS;
            t->want_hs = BTLS_HS_SERVER_HELLO;   /* flight stage */
            return 0;
        }
        if (t->role == BTLS_CLIENT && t->state == BTLS_ST_CH_SENT &&
            t->want_hs == BTLS_HS_SERVER_HELLO) {
            if (type != BTLS_HS_SERVER_HELLO || blen != 3 + 64 || hl != 64)
                return -1;
            memcpy(t->peer_eph, p + 3 + 32, 32);
            th_append(t, p, blen);
            if (ecdh_prk(t) < 0)
                return -1;
            install_epoch(t, "btls-hs-c2s", "btls-hs-s2c");
            t->epoch = 1;
            t->state = BTLS_ST_HS;
            t->want_hs = BTLS_HS_CERTIFICATE;
            return 0;
        }
        return -1;
    }

    /* epoch >= 1: everything is inside AEAD records */
    {
        uint8_t inner[1 + BTLS_MAX_PAYLOAD];
        size_t ilen = 0;
        if (open_rec(t, rec, n, inner, &ilen) < 0 || ilen < 1)
            return -1;
        if (inner[0] != BTLS_RT_HANDSHAKE)
            return -1;              /* app records go to btls_recv_app */
        return feed_hs(t, inner + 1, ilen - 1);
    }
}

int btls_pump(struct btls *t, uint8_t *out, size_t outsz, size_t *outlen)
{
    uint8_t frame[3 + 64];
    size_t flen;

    (void)outsz;
    if (!t || !out || !outlen)
        return -1;
    *outlen = 0;

    if (t->role == BTLS_SERVER && t->state == BTLS_ST_HS) {
        /* the server flight after ClientHello: SH -> CERT -> CV -> FIN */
        switch (t->want_hs) {
        case BTLS_HS_SERVER_HELLO: {
            uint8_t body[64];
            randombytes(t->random, 32);
            memcpy(body, t->random, 32);
            memcpy(body + 32, t->eph_pub, 32);
            flen = hs_frame(frame, BTLS_HS_SERVER_HELLO, body, 64);
            th_append(t, frame, flen);
            if (ecdh_prk(t) < 0)
                return -1;
            install_epoch(t, "btls-hs-c2s", "btls-hs-s2c");
            t->epoch = 1;
            t->want_hs = BTLS_HS_CERTIFICATE;
            out[0] = BTLS_RT_HANDSHAKE;     /* still plaintext (epoch 0) */
            out[1] = (uint8_t)(flen >> 8);
            out[2] = (uint8_t)flen;
            memcpy(out + 3, frame, flen);
            *outlen = 3 + flen;
            return 1;
        }
        case BTLS_HS_CERTIFICATE:
            /* our raw Ed25519 pub IS the certificate */
            flen = hs_frame(frame, BTLS_HS_CERTIFICATE, t->sk + 32, 32);
            th_append(t, frame, flen);
            t->want_hs = BTLS_HS_CERTIFICATE_VERIFY;
            return seal_rec(t, BTLS_RT_HANDSHAKE, frame, flen, out,
                            outlen) < 0 ? -1 : 1;
        case BTLS_HS_CERTIFICATE_VERIFY: {
            uint8_t d[64], sig[64];
            cert_digest(t, d);
            if (ed25519_sign(sig, d, 64, t->sk) < 0)
                return -1;
            flen = hs_frame(frame, BTLS_HS_CERTIFICATE_VERIFY, sig, 64);
            th_append(t, frame, flen);
            t->want_hs = BTLS_HS_FINISHED;
            return seal_rec(t, BTLS_RT_HANDSHAKE, frame, flen, out,
                            outlen) < 0 ? -1 : 1;
        }
        case BTLS_HS_FINISHED: {
            uint8_t m[32];
            finished_mac(t, "btls-fin-s", m);
            flen = hs_frame(frame, BTLS_HS_FINISHED, m, 32);
            th_append(t, frame, flen);
            t->want_hs = BTLS_HS_FINISHED;  /* now: inbound client FIN */
            t->state = BTLS_ST_WAIT_FIN;
            return seal_rec(t, BTLS_RT_HANDSHAKE, frame, flen, out,
                            outlen) < 0 ? -1 : 1;
        }
        }
        return 0;
    }

    if (t->role == BTLS_CLIENT && t->state == BTLS_ST_HS &&
        t->want_hs == 0) {
        /* server Finished verified: send ours (hs key), then app keys */
        uint8_t m[32];
        finished_mac(t, "btls-fin-c", m);
        flen = hs_frame(frame, BTLS_HS_FINISHED, m, 32);
        th_append(t, frame, flen);
        if (seal_rec(t, BTLS_RT_HANDSHAKE, frame, flen, out, outlen) < 0)
            return -1;
        install_epoch(t, "btls-app-c2s", "btls-app-s2c");
        t->epoch = 2;
        t->state = BTLS_ST_DONE;
        return 1;
    }
    return 0;
}

/* ---- application phase ------------------------------------------- */

int btls_send_app(struct btls *t, const uint8_t *msg, size_t len,
                  uint8_t *rec, size_t *reclen)
{
    if (!t || !rec || !reclen || t->state != BTLS_ST_DONE ||
        t->epoch != 2)
        return -1;
    if (seal_rec(t, BTLS_RT_APPLICATION, msg, len, rec, reclen) < 0)
        return -1;
    return (int)*reclen;
}

int btls_recv_app(struct btls *t, const uint8_t *rec, size_t n,
                  uint8_t *msg, size_t *msglen)
{
    uint8_t inner[1 + BTLS_MAX_PAYLOAD];
    size_t ilen = 0;

    if (!t || !rec || !msg || !msglen || t->state != BTLS_ST_DONE ||
        t->epoch != 2)
        return -1;
    if (open_rec(t, rec, n, inner, &ilen) < 0 || ilen < 1)
        return -1;
    if (inner[0] != BTLS_RT_APPLICATION)
        return -1;
    *msglen = ilen - 1;
    if (*msglen)
        memcpy(msg, inner + 1, *msglen);
    return 0;
}
