/* icsp.c - ICSP core: CRC32c, chunk plumbing, key derivation.
 * See docs/icsp-spec.md. Phase 1: handshake support only.
 */
#include <string.h>
#include "ed25519.h"
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

/* --- session key derivation (spec §5) ---
 * shared = X25519(eph_priv, peer_eph_pub)
 * session_key = SHA-512(shared || assoc_id_be || "icsp-v1")[0..31] */
int icsp_derive_key(struct icsp_assoc *a, const uint8_t eph_priv[32])
{
    uint8_t shared[32];
    uint8_t h[64];
    uint8_t buf[32 + 4 + 8];

    if (ed25519_scalarmult(shared, eph_priv, a->peer_eph) != 0)
        return -1;
    memcpy(buf, shared, 32);
    buf[32] = (uint8_t)(a->assoc_id >> 24);
    buf[33] = (uint8_t)(a->assoc_id >> 16);
    buf[34] = (uint8_t)(a->assoc_id >> 8);
    buf[35] = (uint8_t)a->assoc_id;
    memcpy(buf + 36, "icsp-v1", 8);
    ed25519_sha512(h, buf, sizeof(buf));
    memcpy(a->session_key, h, 32);
    a->has_key = 1;
    return 0;
}
