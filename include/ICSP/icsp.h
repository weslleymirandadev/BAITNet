/* icsp.h - ICSP: Improved Connection and Streaming Protocol.
 *
 * IPv69 stream transport (next_header 2). An improved SCTP: reliable,
 * ordered, multi-stream, encrypted by default. See docs/icsp-spec.md.
 *
 * Two layers:
 *   - transport: association + handshake + DATA/SACK + lifecycle.
 *     Every sender takes ONLY the association: the endpoint context
 *     (fd, ifindex, src_mac, dst_addr) lives in struct icsp_assoc,
 *     filled by icsp_endpoint_open() + the handshake.
 *   - session: icsp_poll()/icsp_handle_frame()/icsp_keepalive_tick()
 *     give an app a ready-made receive loop — no manual frame parsing,
 *     heartbeats are answered and sent automatically.
 */
#ifndef ICSP_H
#define ICSP_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
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
    /* peer MAC from the last received frame: replies go unicast to it
     * (broadcast does not traverse APs reliably wired->wireless) */
    uint8_t  peer_mac[6];
    int      has_peer_mac;

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

    /* --- session layer: endpoint context ---
     * filled by icsp_endpoint_open(); preserved by the handshake. */
#ifdef _WIN32
    void    *fd;                /* pcap_t* (Npcap L2 backend) */
#else
    int      fd;                /* AF_PACKET socket */
#endif
    int      ifindex;
    uint8_t  src_mac[6];
    uint64_t dst_addr;          /* peer address (0 for a server: replies
                                   go unicast to a->peer_mac) */
    uint64_t src_addr;          /* our address in the frame (0 = none) */
    int      rcv_timeout_ms;    /* l2_recv timeout for handshake waits
                                   (0 = block forever) */

    /* keepalive / dead-peer, used by icsp_poll + icsp_keepalive_tick */
    int      hb_interval_s;     /* HEARTBEAT when idle this long (0 = off) */
    int      dead_timeout_s;    /* peer declared dead after this silence
                                   (0 = off) */
    int      sack_loss_pct;     /* fault injection: skip SACK N% (tests) */
    time_t   last_rx;           /* any frame from the peer */
    time_t   last_hb;
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

/* low-level send: one ICSP packet = header(12) + chunk, on the
 * association's endpoint. dst_mac = a->peer_mac when known, else
 * broadcast (handshake starts broadcast, replies go unicast). */
int icsp_send_pkt(struct icsp_assoc *a, const uint8_t *chunk,
                  size_t chunklen);

/* Client: open an association with peer at `dst_addr`. Requires a
 * endpoint opened with icsp_endpoint_open() (fd/ifindex/src_mac set).
 * a->src_port is used when != 0, else an auto port (50000 + pid%1000).
 * Runs INIT -> INIT-ACK -> COOKIE-ECHO -> COOKIE-ACK. sk = device
 * seed[32] (+ pub at sk+32). Returns 0 + established assoc, -1. */
int icsp_client_handshake(struct icsp_assoc *a, uint64_t dst_addr,
                          uint16_t dst_port, const uint8_t sk[64]);

/* Server: accept one association on `port`. Waits for INIT, answers
 * INIT-ACK (signed, with a secret-protected cookie), validates
 * COOKIE-ECHO. peers = optional allowlist of trusted identity pubs
 * (NULL = anyone with a valid signature). timeout_s > 0 = finite wait,
 * <= 0 = block forever. Returns 0 + established assoc, -1. */
int icsp_server_accept(struct icsp_assoc *a, uint16_t port,
                       const uint8_t sk[64],
                       const uint8_t (*peers)[32], int n_peers,
                       int timeout_s);

/* --- Phase 2: data path --- */

/* send one message on a stream (encrypted with the session key).
 * Returns the TSN used, or -1. */
int icsp_data_send(struct icsp_assoc *a, uint16_t stream_id,
                   const uint8_t *data, size_t len);

/* handle one received ICSP payload: DATA chunks are decrypted,
 * validated (TSN window, stream ordering) and queued; SACK chunks mark
 * our sendq acked. Returns the number of bytes of *one* message
 * delivered in order into `out` (0 = none), or -1 on bad MAC. */
int icsp_data_handle(struct icsp_assoc *a, const uint8_t *payload,
                     size_t plen, uint8_t *out, size_t *outlen,
                     uint16_t *out_stream);

/* retransmit unacked sendq entries older than `timeout_s`;
 * returns how many were resent. */
int icsp_data_retransmit(struct icsp_assoc *a, int timeout_s);

/* send a SACK for everything received up to cum_tsn. */
int icsp_sack_send(struct icsp_assoc *a);

/* 1 when every sendq entry is acked (nothing pending retransmission) */
int icsp_all_acked(struct icsp_assoc *a);

/* --- Phase 3: lifecycle --- */

/* liveness probe: send HEARTBEAT / answer with HEARTBEAT-ACK */
int icsp_heartbeat_send(struct icsp_assoc *a);
int icsp_heartbeat_ack(struct icsp_assoc *a);

/* graceful close: send SHUTDOWN, state -> SHUTDOWN */
int icsp_shutdown_send(struct icsp_assoc *a);

/* dynamic stream renegotiation (mode: 0=reset, 1=add, 2=close) */
int icsp_stream_reset(struct icsp_assoc *a, uint16_t stream_id,
                      uint8_t mode);

/* process lifecycle chunks (SHUTDOWN/STREAM-RESET/HEARTBEAT) in a
 * received payload; returns 1 when the association should close. */
int icsp_life_handle(struct icsp_assoc *a, const uint8_t *payload,
                     size_t plen);

/* --- session layer: endpoint, receive, poll --- */

/* poll / handle_frame / keepalive_tick / relay return codes */
#define ICSP_POLL_DATA    1   /* a message was delivered (callback ran) */
#define ICSP_POLL_TIMEOUT 0   /* nothing happened within the timeout */
#define ICSP_POLL_ERR    -1   /* I/O error */
#define ICSP_POLL_DEAD   -2   /* peer silent for dead_timeout_s */
#define ICSP_POLL_CLOSED -3   /* peer sent SHUTDOWN */
#define ICSP_POLL_EOF    -4   /* relay: stdin EOF on a tty (user closed) */

/* one received DATA message */
typedef void (*icsp_data_cb)(struct icsp_assoc *a, uint16_t stream,
                             const uint8_t *data, size_t len, void *ud);

/* open the L2 endpoint for an association: load the ~/.hosts69 identity
 * (creating it if missing) and open the raw socket on `ifname`. Fills
 * a->fd / ifindex / src_mac / id_pub and copies the device seed into
 * sk[64] (needed by the handshake to sign INIT). Returns the fd, -1. */
int icsp_endpoint_open(struct icsp_assoc *a, const char *ifname,
                       uint8_t sk[64]);

/* receive + parse one nh=2 frame on a->fd. Returns the frame length,
 * 0 for noise (short frame / wrong next_header), -1 on recv error.
 * Fills *payload and *plen with the ICSP payload inside the frame and
 * *src_addr with the frame's 40-bit source (may be NULL). Refreshes
 * a->peer_mac/last_rx. */
ssize_t icsp_recv_frame(struct icsp_assoc *a, uint8_t *frame,
                        const uint8_t **payload, size_t *plen,
                        uint64_t *src_addr);

/* dispatch ONE received frame: refresh peer_mac/last_rx, answer
 * HEARTBEAT automatically, process DATA (delivered messages go to
 * on_data) and SACK, send a SACK when cum_tsn advanced (unless
 * a->sack_loss_pct), detect SHUTDOWN. Returns an ICSP_POLL_* code. */
int icsp_handle_frame(struct icsp_assoc *a, const uint8_t *frame, ssize_t n,
                      icsp_data_cb on_data, void *ud);

/* keepalive tick: send a HEARTBEAT when hb_interval_s elapsed, declare
 * the peer dead when dead_timeout_s of silence passed. Returns 1 dead,
 * 0 alive. Call from your own select/poll loop. */
int icsp_keepalive_tick(struct icsp_assoc *a);

/* wait up to timeout_ms on a->fd, dispatch what arrives, run the
 * keepalive tick. Returns an ICSP_POLL_* code. */
int icsp_poll(struct icsp_assoc *a, int timeout_ms,
              icsp_data_cb on_data, void *ud);

/* the netcat primitive: relay stdin (when use_stdin) to `stream_id`
 * and socket DATA to on_data, until peer SHUTDOWN (ICSP_POLL_CLOSED),
 * a dead peer (ICSP_POLL_DEAD), an I/O error (ICSP_POLL_ERR), or stdin
 * EOF on a tty (ICSP_POLL_EOF — graceful close, SHUTDOWN already
 * sent). Non-tty stdin EOF stops reading but keeps relaying (netcat
 * servers survive pipes/daemons). Keepalive (a->hb_interval_s /
 * a->dead_timeout_s) runs; empty lines are skipped. */
int icsp_relay(struct icsp_assoc *a, uint16_t stream_id, int use_stdin,
               icsp_data_cb on_data, void *ud);

#endif
