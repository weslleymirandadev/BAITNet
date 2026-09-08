/* btls.h - bTLS: the BITE security layer (docs/bait-names-spec.md §4).
 *
 * TLS 1.3-flavored handshake + AEAD record layer, built only on
 * lib/ed25519: X25519 ECDHE (PFS), Ed25519 identities, HMAC-SHA512
 * key schedule, XSalsa20-Poly1305 secretbox. The server's
 * "certificate" is its raw Ed25519 public key — a client that dialed
 * name.bait checks base32(SHA-512(cert)[0..19]) == the label, so the
 * name IS the pin: no CA, no PKI, no TOFU (docs/btls-spec.md for the
 * full wire layout).
 *
 * Transport-agnostic: the layer consumes and produces complete
 * records; the caller moves them over any reliable ordered message
 * carrier (an ICSP stream in IPv69, a TCP bridge later). Records are
 * encrypted from the first byte after the two hellos; application
 * payloads are NEVER plaintext on the carrier.
 *
 * v1 scope: server-only authentication (the client verifies the
 * server certificate; client certificates are future work). One fixed
 * cipher suite — there is nothing to negotiate or downgrade.
 */
#ifndef BITE_BTLS_H
#define BITE_BTLS_H

#include <stdint.h>
#include <stddef.h>

/* wire record types */
enum {
    BTLS_RT_HANDSHAKE   = 0,   /* plaintext handshake: only the hellos */
    BTLS_RT_APPLICATION = 1,   /* AEAD record; inner = [type 1][payload] */
    BTLS_RT_ALERT       = 2    /* reserved (v1: fatal = close, no alert) */
};

/* handshake message types */
enum {
    BTLS_HS_CLIENT_HELLO       = 1,  /* body: random[32] eph_pub[32] */
    BTLS_HS_SERVER_HELLO       = 2,  /* body: random[32] eph_pub[32] */
    BTLS_HS_CERTIFICATE        = 11, /* body: server ed25519 pub[32] */
    BTLS_HS_CERTIFICATE_VERIFY = 15, /* body: ed25519 sig[64] */
    BTLS_HS_FINISHED           = 20  /* body: verify[32] (transcript MAC) */
};

/* one record fits one ICSP DATA message (1400B); the inner plaintext
 * of an application record is record - header(3) - box(32) - type(1) */
#define BTLS_MAX_REC    1400
#define BTLS_MAX_PAYLOAD 1360

/* Application payloads are MESSAGES, not single records: a message up
 * to BTLS_MAX_MSG is fragmented into BTLS_MAX_PAYLOAD-sized AEAD
 * records, each flagged BTLS_FRAG_MORE when more fragments of the same
 * message follow. The receiver reassembles (the carrier is ordered).
 * The carrier therefore only ever sees records <= 1400 B — no ICSP
 * cap leaks into the protocol. */
#define BTLS_FRAG_MORE  0x01
#define BTLS_MAX_MSG    (256 * 1024)

#define BTLS_CLIENT 0
#define BTLS_SERVER 1

/* association states (state field; harnesses read it to know when the
 * application phase starts) */
enum {
    BTLS_ST_INIT = 0,   /* fresh */
    BTLS_ST_CH_SENT,    /* client sent ClientHello */
    BTLS_ST_HS,         /* mid-handshake (want_hs = next expected msg) */
    BTLS_ST_WAIT_FIN,   /* server sent its flight, awaits client FINISHED */
    BTLS_ST_DONE        /* handshake complete: app keys installed */
};

/* one bTLS session. Struct is data-public (repo style): the caller
 * zeroes it and calls btls_init(). */
struct btls {
    int   role;             /* BTLS_CLIENT / BTLS_SERVER */
    int   state;
    int   epoch;            /* 0 none, 1 handshake keys, 2 app keys */
    uint8_t want_hs;        /* next inbound handshake msg type */

    uint8_t random[32];     /* our hello random */
    uint8_t eph_priv[32];   /* our ephemeral X25519 */
    uint8_t eph_pub[32];
    uint8_t peer_eph[32];   /* peer ephemeral X25519 (from its hello) */
    uint8_t cert_pub[32];   /* server certificate as received */

    uint8_t sk[64];         /* our identity seed||pub (server signs CV) */
    char    expect_label[33]; /* client: label the cert must match (""=off) */

    uint8_t thbuf[512];     /* concatenated handshake frames (transcript) */
    size_t  thlen;
    uint8_t prk[64];        /* HMAC("btls-v1", ECDH shared) */

    uint8_t send_key[32], recv_key[32];
    uint64_t send_seq, recv_seq;    /* per-epoch, per-direction */

    /* app-phase message (de)composition over the record layer */
    const uint8_t *tx_msg;          /* outbound message being fragmented */
    size_t tx_len, tx_off;
    size_t rx_len;                  /* inbound message accumulated so far */
};

/* init a session: role, our identity (sk = seed||pub; the server's pub
 * is the certificate it presents), and — for a client — the .bait
 * label it dialed ("" or NULL skips the name check). Generates the
 * ephemeral X25519 keypair. */
void btls_init(struct btls *t, int role, const uint8_t sk[64],
               const char *expect_label);

/* client: build the ClientHello record (plaintext). Returns record
 * length into *reclen (buffer >= BTLS_MAX_REC), -1 on error. */
int btls_client_start(struct btls *t, uint8_t *rec, size_t *reclen);

/* consume ONE inbound record. Returns:
 *   1  handshake complete on this side (state == BTLS_ST_DONE)
 *   0  progress — call btls_pump() to flush any outbound records
 *  -1  protocol/auth failure (caller closes the carrier)
 */
int btls_feed(struct btls *t, const uint8_t *rec, size_t n);

/* produce the next outbound handshake record, if any (the server's
 * flight after ClientHello; the client's FINISHED after the server's).
 * Returns 1 (record in out, *outlen set — send it), 0 (nothing to
 * send now), -1 on error. */
int btls_pump(struct btls *t, uint8_t *out, size_t outsz, size_t *outlen);

/* application phase (state == BTLS_ST_DONE, epoch == 2).
 *
 * Messages, not records: btls_send_app fragments `len` bytes (<=
 * BTLS_MAX_MSG) into BTLS_MAX_PAYLOAD-sized AEAD records. Returns:
 *   1  `rec` holds a fragment and MORE follow — send it, then call
 *      again with the SAME msg/len (msg must stay valid until 0)
 *   0  `rec` holds the message's LAST fragment — send it, done
 *  -1  error (bad state, len == 0 or > BTLS_MAX_MSG)
 */
int btls_send_app(struct btls *t, const uint8_t *msg, size_t len,
                  uint8_t *rec, size_t *reclen);

/* consume one inbound application record. Returns:
 *   1  a whole message is in `msg`, *msglen = its length
 *   0  a mid-message fragment was buffered (msg accumulates: call
 *      again with the SAME msg/cap; do not touch msg in between)
 *  -1  error (bad MAC, not an app record, message > cap)
 * cap = size of msg (<= BTLS_MAX_MSG). */
int btls_recv_app(struct btls *t, const uint8_t *rec, size_t n,
                  uint8_t *msg, size_t cap, size_t *msglen);

#endif
