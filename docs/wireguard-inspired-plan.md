# WireGuard-inspired architecture plan

Goal: make IPv69 a self-contained network (no IPv4 dependency for the
control plane), scalable to many peers, and resistant to CPU/state DoS
attacks — without per-packet cryptographic verification as a bottleneck.

Source of ideas: WireGuard protocol design
(https://www.wireguard.com/protocol/, whitepaper). WG solved exactly the
problems IPv69 has: handshake DoS, per-packet crypto cost, state
allocation before authentication, and configuration pain.

## Status: P0-P3 IMPLEMENTED (see USAGE.md §12)

- P0 anti-DoS: mac1 pre-auth filter (Poly1305 over the dest addr),
  per-sender token buckets (ICSP INIT / dhcpd / gw broadcast+learn).
- P1 session: HKDF directional keys, time-based rekey + zeroing, INIT
  timestamp anti-replay, 32-TSN sliding replay window, random initial
  TSN.
- P2 cryptokey routing: gw peers = (key, range, endpoint) learned from
  signed INITs/announces only; src validation by range lookup; `--peer
  PUB[/prefix]` allowlist (AllowedIPs); dhcpd O(1) hash allocation +
  range-bounded signed REQUESTs.
- P3 self-containment: `ipv69 net up` (keygen-if-missing + DHCP
  backoff); dgram auth `--auth`/`--peer-file` (Poly1305 over static
  X25519, edwards->montgomery conversion); gateway mesh (GW_ANN
  discovery, GW_Q/GW_R QUERY forwarding, P2P across federated
  gateways).

This document below remains the design rationale + the phase-by-phase
breakdown that was implemented.

---

## 1. Current bottlenecks (measured in the code)

| # | Location | Problem | Cost |
|---|----------|---------|------|
| B1 | `src/ICSP/icsp_handshake.c` server path | Every INIT runs `ed25519_verify` (peer signature) + X25519 + `ed25519_sign` BEFORE any cheap filter. Forged INITs (random key+sig) burn full crypto per packet. | ~1.7 ms CPU per INIT (x64), unbounded |
| B2 | `src/IPv69/af69d.c` `check_msg` | Same for DHCP: every DISCOVER/REQUEST gets an Ed25519 verify before accept/reject. No rate limit, no cheap pre-filter. | ~1.7 ms per packet |
| B3 | `src/IPv69/ipv69gw.c` | Broadcast frames are replicated to ALL peers (up to 256): an authenticated malicious peer amplifies 1→256. No rate limit, no split horizon (tunnel→tunnel replication). | amplification |
| B4 | `src/IPv69/ipv69gw.c` `peer_learn` | Peers are learned from ANY data frame with a class-valid src — unauthenticated. A spoofed src floods the table (256 slots, 300 s) and evicts real peers. | state DoS |
| B5 | `tests/af69_raw.c` dgram path | Datagrams carry NO authentication. With the kernel binding gone (module removed), any node can claim any src address on L2. | spoofing |
| B6 | `src/ICSP/icsp.c` + session | Session key derived once, used forever (no rekey), single key for both directions, SHA-512 label instead of HKDF; no handshake replay protection. | PFS decay, replay |
| B7 | `src/IPv69/af69d.c` | DHCP pool default 0x10–0xfe = 239 addresses. The 40-bit space is unused; the pool is the network size. | scale |
| B8 | CLI/UX | Bring-up is manual: keygen → dhcp → tun/raw, with single-shot DISCOVER (3 s, no retry/backoff). WG is "bring the device up, everything else automatic". | UX |

## 2. WireGuard ideas, mapped to IPv69

### 2.1 DoS: cheap pre-auth filter (mac1) — fixes B1, B2

WG requires authentication in the FIRST message, but the server never
allocates state for unauthenticated traffic and is **silent** to unknown
clients. The trick that makes this cheap: `mac1 = keyed-mac(msg,
HASH("mac1--" || responder_pubkey))`. Any sender can compute it (it uses
the responder's PUBLIC key), but it proves knowledge of the server key
and lets the server drop garbage in microseconds, before any DH/verify.

IPv69: add a 16-byte `mac1` to every control packet (INIT, DISCOVER,
REQUEST, QUERY, cookie messages):

- key = HASH("ipv69-mac1" || server_pub) (Poly1305 — tweetnacl has
  `crypto_onetimeauth`, ~GB/s, or HMAC-SHA512/256)
- server computes mac1 over the frame and compares BEFORE `ed25519_verify`
- under load (token bucket / CPU watermark), packets without a valid
  mac1 are dropped silently (WG: "silent and invisible")

### 2.2 DoS: cookie = proof of ownership + rate limit (mac2) — fixes B1, B2

WG's cookie is `MAC(changing_secret_every_2min, sender_ip)`, delivered
encrypted in a cookie-reply packet; under load the server requires it
(mac2) before processing. This enables proper per-sender rate limiting.

IPv69 (L2 has no IP — the analog is the sender MAC/address):
- cookie = keyed-mac(server_secret_rotated_2min, src_mac || addr40)
- under load, DHCP/ICSP servers reply with a cookie message instead of
  processing; the client must retry with the cookie
- rate limit per MAC/addr in a small SipHash-like table (fixed slots +
  eviction, like WG's per-peer handshake rate limit: once per
  REKEY_TIMEOUT)

The existing ICSP cookie (server secret + INIT params, 5 min TTL) is the
same idea — extend it to be load-triggered and cheap-first (see 2.1).

### 2.3 Cryptokey routing — fixes B4, B5, B7 (the big one)

WG's routing model: the interface's identity IS its public key; peers
are (pubkey, AllowedIPs); a packet is accepted from a peer only if its
src falls inside that peer's allowed range. No per-packet crypto: the
key authenticates at handshake time, the range authenticates every
packet afterwards (hash lookup, microseconds).

IPv69 addresses are already derived from keys (identity → addr, class
C deterministic). Apply the same model:

- **dhcpd**: lease = (mac, key, addr-range). The server registers
  `key → allowed range` (the range derived from the key, or a
  sub-prefix granted at lease time). Every frame's src is validated
  against the lease table (hash lookup) — **no per-packet verify**.
  This replaces the kernel binding (removed with the module) in
  userspace, fixing the spoofing hole (B5).
- **gw**: peers are (pubkey, addr-range, endpoint). Forward only frames
  whose src falls in a learned+authenticated range; learn only from
  frames that authenticate (signed DHCP, or ICSP sessions, or a future
  lightweight dgram MAC — see 2.6). Broadcast replication becomes
  range-bounded: replicate only to peers whose range intersects the
  broadcast class.
- **scale**: allow sub-prefix ranges (e.g. `addr/60` within class C) so
  a gateway/AP can delegate a block to a subnet router; the gw routes by
  longest-prefix over a small trie (40-bit → tiny). The DHCP pool grows
  to a full class (2^32 class-C addresses) instead of 239.

### 2.4 Session hardening — fixes B6

Steal from WG's handshake/transport discipline:

- **HKDF with labels**: replace `SHA-512(X25519 || assoc_id || label)`
  with an HKDF-style chain (`temp = HMAC(ck, eph)`, `ck = HMAC(temp,1)`,
  `key = HMAC(temp, ck||2)`), splitting **sending** and **receiving**
  keys per direction.
- **Time-based rekey**: WG rekeys every REKEY_AFTER_TIME (~2 min) based
  on time, not traffic; handshakes are retried with REKEY_TIMEOUT +
  jitter (0–333 ms) and rate-limited to once per REKEY_TIMEOUT.
  IPv69: rekey the ICSP session on a timer, zero old keys
  (REJECT_AFTER_TIME * 3), retry with jitter/backoff.
- **Anti-replay**: WG includes a TAI64N timestamp (encrypted) in the
  init message; the server drops timestamps ≤ last seen per client
  (handshake replay). Data uses a 64-bit counter + ~2000-entry sliding
  window. IPv69: add an encrypted timestamp to INIT (anti handshake
  replay) and a per-direction counter + sliding window for DATA
  (TSN/SACK already sequences; the window closes the replay gap).
- **Identity hiding**: WG encrypts the initiator's static key with the
  ephemeral↔responder DH. IPv69 INIT currently sends `id_pub` in
  cleartext. Encrypt it (X25519(eph, server_pub) → AEAD) — passive
  observers learn nothing.
- **Zeroing**: wipe ephemeral keys and session keys after rekey/close.

### 2.5 Gateway mesh / self-contained control plane

- GW discovery over IPv69 L2: gateways announce themselves with a
  control message (e.g. ND-style) on the local L2; other gateways learn
  gw↔gw links without any IP configuration. QUERY already exists — make
  it hop across gateways (route the query to the gw whose range contains
  the target).
- Tunnels remain UDP/IPv4+6 as the *last resort* transport (like WG),
  but the control plane (discovery, QUERY, lease) runs on IPv69 itself:
  a LAN with no DHCP/IP works end-to-end; internet joining works through
  any gateway by key, not by fixed IP endpoints.
- Split horizon in the gw (fix B3): never replicate a broadcast back to
  the tunnel/L2 side it arrived from; rate-limit broadcast replication
  with a token bucket per source.

### 2.6 Lightweight dgram authentication (optional, phased)

Full ICSP sessions for every dgram flow are heavy. WG's alternative:
derive a static shared key between keyring pairs (X25519(pub_peer)) and
authenticate each dgram with Poly1305 (~µs). This gives src auth on L2
and lays the base for encryption. Phase 3; cryptokey routing (2.3) is
the prerequisite.

## 3. Target architecture (summary)

```
 identity (Ed25519/X25519 keyring)  =  WG interface key
 dhcpd lease table (key -> range)   =  WG AllowedIPs
 gw peer table (key, range, ep)     =  WG peers + roaming
 mac1 + cookie                      =  WG DoS pre-filter + rate limit
 HKDF + directional keys + rekey    =  WG session discipline
 QUERY/gw mesh over IPv69 L2        =  self-contained control plane
```

No per-packet asymmetric crypto anywhere: signatures only at
lease/handshake time; every data-path check is a hash lookup or a
Poly1305/HMAC (~µs vs ~1.7 ms).

## 4. Phases

### P0 — DoS hardening (small, high impact)
- [ ] `mac1` on INIT/DISCOVER/REQUEST/QUERY + silent drop under load
  (B1, B2)
- [ ] per-MAC/addr rate limiting (token bucket) on dhcpd + ICSP server
- [ ] gw: split horizon + broadcast token bucket (B3)
- [ ] gw: learn peers only from authenticated frames (B4)

### P1 — Session discipline (crypto)
- [ ] HKDF labels + directional keys in `icsp_derive_key` (B6)
- [ ] time-based rekey with jitter/backoff + key zeroing
- [ ] INIT timestamp anti-replay + identity hiding (encrypted id_pub)
- [ ] DATA sliding-window replay protection

### P2 — Cryptokey routing (scale + anti-spoof)
- [ ] dhcpd: `key → addr-range` lease table; userspace src validation
  replacing the kernel binding (B5, B7)
- [ ] gw: prefix routing (longest-prefix over 40-bit), range-bounded
  broadcast (B3, B7)
- [ ] class-C pools (full 2^32) + sub-prefix delegation

### P3 — Self-contained network + UX
- [ ] gateway discovery over L2 + QUERY across gateways (mesh)
- [ ] dgram Poly1305 auth from static X25519 (2.6)
- [ ] `ipv69 net up`: keygen-if-missing → discover dhcpd (retry with
  backoff/jitter) → lease → raw/tun → keepalive loop (B8, WG bring-up)
- [ ] docs: architecture + security model update

## 5. Non-goals

- No kernel module (removed deliberately) — everything in userspace.
- No full Noise handshake rewrite: the existing INIT/cookie exchange
  keeps its shape; we harden it (mac1, timestamp, identity hiding)
  instead of replacing it with Noise_IK wholesale.
- No per-packet asymmetric crypto (the whole point).

## 6. Open questions

- dgram auth: Poly1305 static-key MAC (2.6) vs requiring a lightweight
  session — measure real dgram rates first (phone/AP use case).
- Rate-limit table size for the gw (WG uses per-peer; IPv69 per-MAC
  until a peer is authenticated).
- Whether class C derivation stays the only public source or ranges
  should be grantable (sub-prefix delegation, P2).
