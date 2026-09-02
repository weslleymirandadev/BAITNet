/* icsp.c - ICSP core: CRC32c, chunk plumbing, key derivation.
 * See docs/icsp-spec.md. Phase 1: handshake support only.
 */
#include <string.h>
#include "ed25519.h"
#include "IPv69/plat.h"     /* sock_t/sendto for the tunnel transport */
#include "IPv69/header.h"
#include "IPv69/l2.h"
#include "ICSP/icsp.h"

/* --- CRC32c (Castagnoli, polynomial 0x1EDC6F41) --- */
static uint32_t crc_table[256];
static int crc_ready;

static void crc_init(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0x82F63B78u ^ (c >> 1)) : (c >> 1);
        crc_table[i] = c;
    }
    crc_ready = 1;
}

uint32_t icsp_crc32c(const uint8_t *data, size_t len)
{
    uint32_t c = 0xFFFFFFFFu;
    if (!crc_ready)
        crc_init();
    for (size_t i = 0; i < len; i++)
        c = crc_table[(c ^ data[i]) & 0xff] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

/* --- chunk plumbing --- */
size_t icsp_chunk_len(const uint8_t *chunk)
{
    return ICSP_CHUNK_HDR + ((size_t)chunk[2] << 8 | chunk[3]);
}

uint8_t *icsp_chunk_next(uint8_t *chunk)
{
    return chunk + icsp_chunk_len(chunk);
}

/* append a chunk header to `buf`; returns pointer to the data area */
uint8_t *icsp_chunk_put(uint8_t *buf, uint8_t type, size_t datalen)
{
    buf[0] = type;
    buf[1] = 0;
    buf[2] = (uint8_t)(datalen >> 8);
    buf[3] = (uint8_t)(datalen & 0xff);
    return buf + ICSP_CHUNK_HDR;
}

/* --- one ICSP packet = header(12) + chunk(s). Build and send on the
 * association's endpoint. dst_mac = peer when known, else broadcast
 * (handshake starts broadcast; every reply after the first frame goes
 * unicast). */
int icsp_send_pkt(struct icsp_assoc *a, const uint8_t *chunk,
                  size_t chunklen)
{
    const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t pkt[ICSP_MAX_PAYLOAD];
    size_t off = 0;
    uint16_t crc;

    pkt[off++] = (uint8_t)(a->src_port >> 8);
    pkt[off++] = (uint8_t)a->src_port;
    pkt[off++] = (uint8_t)(a->dst_port >> 8);
    pkt[off++] = (uint8_t)a->dst_port;
    pkt[off++] = ICSP_VERSION;
    pkt[off++] = 0;
    pkt[off++] = (uint8_t)(a->assoc_id >> 24);
    pkt[off++] = (uint8_t)(a->assoc_id >> 16);
    pkt[off++] = (uint8_t)(a->assoc_id >> 8);
    pkt[off++] = (uint8_t)a->assoc_id;
    /* crc placeholder at off..off+1, filled after the body */
    off += 2;
    memcpy(pkt + off, chunk, chunklen);
    off += chunklen;
    crc = (uint16_t)icsp_crc32c(pkt + 2, off - 2);  /* over ports..end */
    pkt[10] = (uint8_t)(crc >> 8);
    pkt[11] = (uint8_t)crc;

    uint8_t frame[1600];
    size_t len = build_frame(frame,
                             a->has_peer_mac ? a->peer_mac : bcast,
                             a->src_mac, a->src_addr, a->dst_addr,
                             IPV69_NEXT_STREAM, 64, 0, 0, pkt, off);
    if (a->tunnel)              /* --remote: datagram to the gateway */
        return sendto(a->tfd, (const char *)frame, len, 0,
                      (struct sockaddr *)&a->gw, a->gwlen) >= 0 ? 0 : -1;
    return l2_send(a->fd, a->ifindex,
                   a->has_peer_mac ? a->peer_mac : bcast, frame, len);
}

/* --- session key derivation (spec §5, WireGuard-style) ---
 * shared = X25519(eph_priv, peer_eph_pub)
 * HKDF-like: prk = HMAC-SHA512("icsp-v1", shared), then directional
 * keys send/recv = HMAC(prk, label || 0x01)[0..31]. The initiator uses
 * send_key for TX and recv_key for RX; the responder swaps them, so the
 * two directions never share a key/nonce space. */
int icsp_derive_key(struct icsp_assoc *a, const uint8_t eph_priv[32])
{
    uint8_t shared[32];
    uint8_t prk[64], okm[64];
    uint8_t new_send[32], new_recv[32];
    uint8_t info[16];
    static const uint8_t salt[] = "icsp-v1";
    static const uint8_t l_send[] = "icsp-send";
    static const uint8_t l_recv[] = "icsp-recv";

    if (ed25519_scalarmult(shared, eph_priv, a->peer_eph) != 0)
        return -1;
    /* extract: prk = HMAC(salt, ikm=shared) */
    ed25519_hmac_sha512(prk, shared, 32, salt, sizeof(salt) - 1);

    /* expand: send = HMAC(prk, "icsp-send" || 1) */
    memcpy(info, l_send, sizeof(l_send) - 1);
    info[sizeof(l_send) - 1] = 1;
    ed25519_hmac_sha512(okm, info, sizeof(l_send), prk, 64);
    memcpy(new_send, okm, 32);

    /* expand: recv = HMAC(prk, "icsp-recv" || 1) */
    memcpy(info, l_recv, sizeof(l_recv) - 1);
    info[sizeof(l_recv) - 1] = 1;
    ed25519_hmac_sha512(okm, info, sizeof(l_recv), prk, 64);
    memcpy(new_recv, okm, 32);

    /* responder swaps: our TX uses the peer's "send" slot, so the two
       directions never share a key/nonce space (WG directional keys) */
    if (!a->is_initiator) {
        uint8_t tmp[32];
        memcpy(tmp, new_send, 32);
        memcpy(new_send, new_recv, 32);
        memcpy(new_recv, tmp, 32);
    }

    /* zero the old keys before installing the new ones (WG discipline) */
    if (a->has_key) {
        memset(a->send_key, 0, 32);
        memset(a->recv_key, 0, 32);
    }
    memcpy(a->send_key, new_send, 32);
    memcpy(a->recv_key, new_recv, 32);
    memset(shared, 0, sizeof(shared));
    memset(prk, 0, sizeof(prk));
    a->has_key = 1;
    a->key_ts = time(NULL);
    return 0;
}
