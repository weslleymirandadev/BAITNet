# ICSP — Improved Connection and Streaming Protocol

IPv69 stream transport (next_header 2, reserved since v0.4).
An improved SCTP: takes everything SCTP does well and fixes the gaps
that kept it from becoming a standard. Runs over IPv69 L2 (40-bit
addresses, addr↔MAC binding in the kernel, existing Ed25519 crypto).

The goal is the "own HTTPS": a reliable, ordered, multi-stream and
**encrypted by default** transport, ready for services built on IPv69.

---

## 1. What to take from SCTP (the good)

| Feature | Why keep it |
|---|---|
| **Multi-streaming** | One association with N independent streams; avoids TCP head-of-line blocking (one slow message does not hold the others) |
| **Message-oriented** | Preserves message boundaries — not a byte-stream like TCP |
| **4-way cookie handshake** | INIT → INIT-ACK(cookie) → COOKIE-ECHO → COOKIE-ACK; the server stays stateless until the cookie comes back (anti connection flood) |
| **Selective SACK + retransmission** | Re-sends only what was lost, not the whole window |
| **Heartbeat** | Detects dead paths and fails over |
| **CRC32c** | Strong per-packet checksum |
| **Multi-homing** | One endpoint with several addresses (transparent failover) |

## 2. SCTP gaps and how ICSP fixes them

| SCTP problem | ICSP solution |
|---|---|
| **No native crypto** — DTLS-over-SCTP is a later patch | Built-in authenticated handshake + encrypted data path: Ed25519 identity (auto-key `~/.ipv69/key`) + ephemeral X25519 (ECDH) + XSalsa20-Poly1305 (secretbox). Mini-Noise style: sign once, derive a symmetric session key |
| **Absurd complexity** — RFC 4960 ≈ 150 pages + dozens of extensions | Essential subset: ~10 chunk types, no optional extensions. States: CLOSED → COOKIE_WAIT → ESTABLISHED → SHUTDOWN. That's it |
| **NAT/middlebox breaks everything** | Does not exist in IPv69: pure L2, 40-bit address global on the network. Gap eliminated by design |
| **Weak / secret-less cookie** | Cookie = ephemeral server secret (rotated) + hash of the parameters; clients cannot forge it |
| **Fixed streams per association** | Native STREAM-RESET (dynamic renegotiation, like RFC 6525) |
| **No reusable session** | Optional 0-RTT: COOKIE-ECHO can carry already-encrypted data when a session is reusable |

## 3. Architecture

```
┌──────────────────────────────────────────────┐
│  Service / app (messages per stream)          │
├──────────────────────────────────────────────┤
│  ICSP (next_header 2)                        │
│  association, streams, TSN/SACK, AEAD crypto │
├──────────────────────────────────────────────┤
│  IPv69 L2 (next_header 0/1/2, 40-bit,        │
│  addr↔MAC binding, Ed25519 for bootstrap)    │
└──────────────────────────────────────────────┘
```

IPv69 delivers **datagrams** (nh=1) and **control** (nh=0). ICSP
consumes the same L2 but with **reliable-flow** semantics: what dgram
does not guarantee (order, delivery, connection) is ICSP's job.

## 4. Wire format (draft)

```
IPv69 frame (nh=2): [header 38B] + ICSP payload

ICSP header (12B):
  src_port (2)  dst_port (2)
  ver      (1)  flags    (1)
  assoc_id (4)
  crc32c   (2)   ← association checksum (strong, like SCTP)

Chunks (all): [type 1][flags 1][len 2][data...]
```

Chunk types (clean numbering 0–9):

```
0  DATA          [tsn 4][stream_id 2][stream_seq 2][payload]
1  INIT          [ver][streams_in 2][streams_out 2][eph_pub 32][id_pub 32][sig 64]
2  INIT-ACK      [ver][streams][eph_pub 32][id_pub 32][sig 64][cookie]
3  COOKIE-ECHO   [cookie][optional 0-RTT data]
4  COOKIE-ACK
5  SACK          [cumulative_tsn 4][gaps...]
6  HEARTBEAT
7  HEARTBEAT-ACK
8  SHUTDOWN
9  STREAM-RESET  [stream_id 2][mode 1]
```

Per-DATA-chunk crypto: `secretbox(tsn|stream|seq|payload)` with nonce
derived from (assoc_id, tsn) — per-packet authenticated, replay
protected by a sliding window.

## 5. Handshake (Phase 1)

1. **Client → INIT**: identity pub (Ed25519, from auto-key) + ephemeral X25519 pub + desired streams, signed.
2. **Server → INIT-ACK**: server pub + ephemeral pub + cookie (server secret + hash) + accepted streams, signed.
3. **Client → COOKIE-ECHO**: returns the cookie (proof the INIT-ACK came from the legitimate server) + signature.
4. **Server → COOKIE-ACK**: validates the cookie, association ESTABLISHED.

Key derivation: `shared = X25519(eph_priv, peer_eph_pub)` →
`session_key = SHA-512(shared || assoc_id || nonces)` → secretbox with
`key[0..31]` and per-packet derived nonces. The Ed25519 identities
authenticate the peer (same pubkey allowlist as DHCP).

## 6. Folder structure

```
include/ICSP/icsp.h          — public API + wire constants (transport + session)
src/ICSP/icsp.c              — core: CRC32c, chunk plumbing, shared packet send
src/ICSP/icsp_handshake.c    — INIT/cookie/key derivation
src/ICSP/icsp_data.c         — streams, TSN, SACK, retransmission
src/ICSP/icsp_life.c         — heartbeat, SHUTDOWN, STREAM-RESET
src/ICSP/icsp_session.c      — session layer: endpoint, recv, poll (netcat-friendly)
tests/icsp_test.c            — test server/client pair (ipv69 icsp)
examples/icsp_chat.c         — standalone chat example (make chat)
docs/icsp-spec.md            — this document
```

## 6.1 Session layer (the "netcat" API)

Tools don't touch frames or chunk dispatch anymore. The endpoint
context (fd, ifindex, src_mac, dst_addr) and keepalive config live in
`struct icsp_assoc`; `icsp_endpoint_open()` fills them in one call:

```c
struct icsp_assoc a;
uint8_t sk[64];
icsp_endpoint_open(&a, "wlan0", sk);        /* keyring identity + raw socket */
icsp_client_handshake(&a, dst, port, sk);   /* or icsp_server_accept(&a, port, ...) */
a.hb_interval_s = 6;                        /* keepalive config (0 = off) */
a.dead_timeout_s = 18;

/* netcat: relay stdin -> stream 1, socket -> on_data, keepalive runs */
int r = icsp_relay(&a, 1, 1, on_data, NULL);
/* or a pure-socket service loop: */
while ((r = icsp_poll(&a, 200, on_data, NULL)) == ICSP_POLL_DATA ||
       r == ICSP_POLL_TIMEOUT)
    ;
/* or multiplex your own fds with poll()/select(): on socket ready,
   icsp_handle_frame(&a, frame, n, on_data, NULL); on idle,
   icsp_keepalive_tick(&a) — what icsp_relay does internally */
```

All senders take only the association: `icsp_data_send(&a, stream, data, len)`,
`icsp_shutdown_send(&a)`, `icsp_heartbeat_send(&a)`, ... Return codes:
`ICSP_POLL_DATA` (a message hit the callback), `ICSP_POLL_TIMEOUT`,
`ICSP_POLL_DEAD` (peer silent for `dead_timeout_s`), `ICSP_POLL_CLOSED`
(peer SHUTDOWN), `ICSP_POLL_EOF` (relay: Ctrl-D on a tty), `ICSP_POLL_ERR`.
`icsp_relay` survives non-tty stdin EOF (pipes/daemons keep receiving).

The `lib/ed25519` library gains exposed wrappers: `nacl_scalarmult`
(X25519) and `nacl_secretbox_*` (AEAD) — already in tweetnacl.c, just
exposed with a clean API.

## 7. Phases (each testable)

| Phase | Scope | Acceptance criteria | Status |
|---|---|---|---|
| **1 — Infra + handshake** | folders, Makefile, header/chunks, authenticated INIT→COOKIE-ACK (Ed25519 + X25519 → session key) | `icsp_test client/server` completes the handshake over veth; derived key identical on both sides; invalid signature = refused | ✅ done |
| **2 — Data** | encrypted DATA, TSN/SACK, retransmission, multiple streams | ordered delivery; synthetic loss is recovered; stream A does not block stream B | ✅ done |
| **3 — Life** | heartbeat, graceful shutdown, STREAM-RESET | path dies → failover; shutdown cleans the association; streams renegotiated at runtime | ✅ done |
| **4 — Host-to-host** | phone ↔ VM, auto-key, binding | same experience as veth, but over the real network (Wi-Fi ↔ bridge) | ✅ done (Wi-Fi real, session key identical both sides) |

## 8. Out of scope (on purpose)

- Complex congestion control (CUBIC etc.) — private L2 network, simple
  window; can evolve later if needed.
- MTU discovery / association fragmentation — IPv69 has the NOFRAG
  flag; payload ≤ 1400.
- Exotic SCTP extensions (ADDIP, PR-SCTP, ASCONF) — only STREAM-RESET.

## 9. Dependencies

None new. Everything ICSP needs already exists in the repo:

- `lib/ed25519` (TweetNaCl + wrapper): sign/verify for the handshake,
  scalarmult for ECDH, secretbox for AEAD (to be exposed).
- IPv69 L2: frame delivery with 40-bit addressing and binding.
- auto-key `~/.ipv69/key`: device identity, same as DHCP.
