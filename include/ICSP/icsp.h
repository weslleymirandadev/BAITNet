/* icsp.h - ICSP: Improved Connection and Streaming Protocol.
 *
 * IPv69 stream transport (next_header 2). An improved SCTP: reliable,
 * ordered, multi-stream, encrypted by default. See docs/icsp-spec.md.
 *
 * This header is the public API + wire constants. Phase 1: infra +
 * authenticated handshake (INIT -> COOKIE-ACK) with Ed25519 identity +
 * ephemeral X25519 -> session key.
 */
#ifndef ICSP_H
#define ICSP_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#define ICSP_VERSION       1
#define ICSP_HEADER_LEN    12
#define ICSP_CHUNK_HDR     4       /* [type 1][flags 1][len 2] */
#define ICSP_MAX_PAYLOAD   1400

/* ICSP header (12B), inside the IPv69 frame payload:
 *   src_port(2) dst_port(2) ver(1) flags(1) assoc_id(4) crc32c(2)
 * Ports: decimal on the CLI, native (host order) here — the IPv69 L2
 * header already carries them for dgrams; ICSP keeps its own copy so an
 * association can live on a fixed port pair regardless of the frame. */
struct icsp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  ver;
    uint8_t  flags;
    uint32_t assoc_id;
    uint16_t crc;               /* CRC32c of the whole ICSP payload */
};

/* Chunk types (clean numbering 0-9) */
enum {
    ICSP_CHUNK_DATA         = 0, /* [tsn 4][stream_id 2][stream_seq 2][payload] */
    ICSP_CHUNK_INIT         = 1, /* [ver][streams_in 2][streams_out 2][eph_pub 32][id_pub 32][sig 64] */
    ICSP_CHUNK_INIT_ACK     = 2, /* [ver][streams][eph_pub 32][id_pub 32][sig 64][cookie] */
    ICSP_CHUNK_COOKIE_ECHO  = 3, /* [cookie][optional 0-RTT data] */
    ICSP_CHUNK_COOKIE_ACK   = 4,
    ICSP_CHUNK_SACK         = 5, /* [cumulative_tsn 4][gaps...] */
    ICSP_CHUNK_HEARTBEAT    = 6,
    ICSP_CHUNK_HEARTBEAT_ACK = 7,
    ICSP_CHUNK_SHUTDOWN     = 8,
    ICSP_CHUNK_STREAM_RESET = 9, /* [stream_id 2][mode 1] */
};

/* association states */
enum {
    ICSP_ST_CLOSED = 0,
    ICSP_ST_COOKIE_WAIT,
    ICSP_ST_ESTABLISHED,
    ICSP_ST_SHUTDOWN,
};

/* one association: the transport-level connection */
#define ICSP_MAX_STREAMS 8
#define ICSP_SENDQ       16
#define ICSP_RCVQ        16

struct icsp_stream {
    uint16_t id;
    uint16_t next_send_seq;   /* next stream_seq to send */
    uint16_t next_recv_seq;   /* next stream_seq expected (ordered) */
};

struct icsp_assoc {
    uint16_t src_port, dst_port;
    uint32_t assoc_id;
    int      state;
    /* identity (Ed25519, same auto-key as DHCP) + ephemeral X25519 */
    uint8_t  id_pub[32];        /* our identity pub */
    uint8_t  eph_pub[32];       /* our ephemeral X25519 pub */
    uint8_t  peer_id[32];       /* peer identity pub (authenticated) */
    uint8_t  peer_eph[32];      /* peer ephemeral X25519 pub */
    uint8_t  session_key[32];   /* secretbox key, derived from ECDH */
    int      has_key;
    uint16_t streams_in, streams_out;

    /* Phase 2: data path */
    int      n_streams;
    struct icsp_stream streams[ICSP_MAX_STREAMS];
    uint32_t next_tsn;          /* next TSN to assign (sender) */
    uint32_t cum_tsn;           /* cumulative TSN received (delivered) */
    struct {
        uint32_t tsn;
        uint16_t stream_id, seq;
        uint8_t  data[ICSP_MAX_PAYLOAD];
        uint16_t len;
        uint8_t  acked;
        time_t   sent_at;
    } sendq[ICSP_SENDQ];
    int n_sendq;
    struct {
        uint32_t tsn;
        uint16_t stream_id, seq;
        uint8_t  data[ICSP_MAX_PAYLOAD];
        uint16_t len;
        uint8_t  valid;
    } rcvq[ICSP_RCVQ];
    int n_rcvq;
};

/* --- public API (Phase 1: handshake) --- */

/* CRC32c (Castagnoli), SCTP-style strong checksum. */
uint32_t icsp_crc32c(const uint8_t *data, size_t len);

/* chunk plumbing: header [type 1][flags 1][len 2] + data */
size_t icsp_chunk_len(const uint8_t *chunk);
uint8_t *icsp_chunk_next(uint8_t *chunk);
uint8_t *icsp_chunk_put(uint8_t *buf, uint8_t type, size_t datalen);

/* derive the session key from the ephemeral ECDH shared secret
 * (X25519(eph_priv, peer_eph) -> SHA-512(shared||assoc_id||"icsp-v1")) */
int icsp_derive_key(struct icsp_assoc *a, const uint8_t eph_priv[32]);

/* Client: open an association with peer at `dst_addr`.
 * fd = AF_PACKET socket (raw_socket), src_mac from it, sk = device
 * seed[32] (+ pub at sk+32). Runs INIT -> INIT-ACK -> COOKIE-ECHO ->
 * COOKIE-ACK. Returns 0 + established assoc (session_key set), -1. */
int icsp_client_handshake(int fd, int ifindex, const uint8_t src_mac[6],
                          uint64_t dst_addr,
                          uint16_t src_port, uint16_t dst_port,
                          const uint8_t sk[64],
                          struct icsp_assoc *a);

/* Server: accept one association. Waits for INIT, answers INIT-ACK
 * (signed, with a secret-protected cookie), validates COOKIE-ECHO.
 * peers = optional allowlist of trusted identity pubs (NULL = anyone
 * with a valid signature, like DHCP --learn). Returns 0 + established
 * assoc, -1. */
int icsp_server_accept(int fd, int ifindex, const uint8_t src_mac[6],
                       uint64_t srv_addr, uint16_t port,
                       const uint8_t sk[64],
                       const uint8_t (*peers)[32], int n_peers,
                       struct icsp_assoc *a);

/* --- Phase 2: data path --- */

/* send one message on a stream (encrypted with the session key).
 * Returns the TSN used, or -1. */
int icsp_data_send(struct icsp_assoc *a, int fd, int ifindex,
                   const uint8_t src_mac[6], const uint8_t *dst_mac,
                   uint64_t dst_addr, uint64_t src_addr,
                   uint16_t stream_id, const uint8_t *data, size_t len);

/* handle one received ICSP payload: DATA chunks are decrypted,
 * validated (TSN window, stream ordering) and queued; SACK chunks mark
 * our sendq acked. Returns the number of bytes of *one* message
 * delivered in order into `out` (0 = none), or -1 on bad MAC. */
int icsp_data_handle(struct icsp_assoc *a, const uint8_t *payload,
                     size_t plen, uint8_t *out, size_t *outlen,
                     uint16_t *out_stream);

/* retransmit unacked sendq entries older than `timeout_s`;
 * returns how many were resent. */
int icsp_data_retransmit(struct icsp_assoc *a, int fd, int ifindex,
                         const uint8_t src_mac[6], const uint8_t *dst_mac,
                         uint64_t dst_addr, uint64_t src_addr,
                         int timeout_s);

/* send a SACK for everything received up to cum_tsn. */
int icsp_sack_send(struct icsp_assoc *a, int fd, int ifindex,
                   const uint8_t src_mac[6], const uint8_t *dst_mac,
                   uint64_t dst_addr, uint64_t src_addr);

/* --- Phase 3: lifecycle --- */

/* liveness probe: send HEARTBEAT / answer with HEARTBEAT-ACK */
int icsp_heartbeat_send(struct icsp_assoc *a, int fd, int ifindex,
                        const uint8_t src_mac[6], const uint8_t *dst_mac,
                        uint64_t dst_addr, uint64_t src_addr);
int icsp_heartbeat_ack(struct icsp_assoc *a, int fd, int ifindex,
                       const uint8_t src_mac[6], const uint8_t *dst_mac,
                       uint64_t dst_addr, uint64_t src_addr);

/* graceful close: send SHUTDOWN, state -> SHUTDOWN */
int icsp_shutdown_send(struct icsp_assoc *a, int fd, int ifindex,
                       const uint8_t src_mac[6], const uint8_t *dst_mac,
                       uint64_t dst_addr, uint64_t src_addr);

/* dynamic stream renegotiation (mode: 0=reset, 1=add, 2=close) */
int icsp_stream_reset(struct icsp_assoc *a, int fd, int ifindex,
                      const uint8_t src_mac[6], const uint8_t *dst_mac,
                      uint64_t dst_addr, uint64_t src_addr,
                      uint16_t stream_id, uint8_t mode);

/* process lifecycle chunks (SHUTDOWN/STREAM-RESET/HEARTBEAT) in a
 * received payload; returns 1 when the association should close. */
int icsp_life_handle(struct icsp_assoc *a, const uint8_t *payload,
                     size_t plen);

#endif
