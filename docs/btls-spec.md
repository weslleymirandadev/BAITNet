# bTLS — the BITE security layer (bTLS/1.0)

bTLS is the project's own TLS-flavored secure channel, the layer BITE
sits on (docs/bait-names-spec.md §4). It is TLS 1.3 in spirit — hello
messages, a certificate proving key possession, Finished MACs, AEAD
records with per-direction sequence numbers — implemented with the
primitives the repo already has (`lib/ed25519`): X25519 ECDHE,
Ed25519 identities, HMAC-SHA512 key schedule, XSalsa20-Poly1305
secretbox. No X.509, no CA, no PKI: the server's certificate is its
raw Ed25519 public key, and the client validates it against the .bait
label it dialed.

```
┌─────────────────────────────────────────────┐
│  BITE (HTTP-shaped protocol, next spec)     │
├─────────────────────────────────────────────┤
│  bTLS (this doc): handshake + AEAD records  │
├─────────────────────────────────────────────┤
│  reliable ordered message carrier           │
│  (IPv69: an ICSP association, stream 1;     │
│   future: TCP bridge, PPPoE69 session...)   │
└─────────────────────────────────────────────┘
```

## 1. Properties

- **Encryption by default.** Only the two hellos travel in the clear,
  and they carry only fresh ephemeral X25519 public keys and random
  nonces. Every byte after ServerHello — Certificate, signatures,
  Finished, all application payloads — is inside an AEAD record.
  There is no plaintext variant and no port split to get wrong.
- **Forward secrecy.** Session keys come from ephemeral X25519 ECDH;
  no long-term key ever encrypts data.
- **The name is the pin.** A client that dialed `label.bait` verifies
  `base32_lower_nopad(SHA-512(server_pub)[0..19]) == label` when the
  Certificate arrives, then the signature proves possession. A lying
  endpoint (a gateway answering a QUERY with its own address, a
  relay) cannot produce a valid flight for the expected label.
- **Transport-agnostic.** The layer exchanges complete records; the
  carrier only needs reliable, ordered, message-oriented delivery.
  Over ICSP each record is one DATA message (≤ 1400 B). The crypto
  does not depend on ICSP's own encryption — over a future plaintext
  carrier bTLS alone still guarantees confidentiality and integrity
  (ICSP's AEAD below is then defense in depth, not the only line).
- **One fixed suite, no negotiation**: there is nothing to downgrade
  to. v1 authenticates the server only (client certificates are
  future work — ICSP below can already allowlist clients if wanted).

## 2. Records

Every bTLS message is one record:

```
record   = [type 1][len 2 BE][payload]
type     = 0 HANDSHAKE   (plaintext: ClientHello, ServerHello only)
           1 APPLICATION (AEAD; payload = [inner_type 1][flags 1][data])
           2 ALERT       (reserved; v1 fatal errors just close)

payload (type 1) = secretbox blob: 32 bytes of TweetNaCl padding +
                   MAC (16) + ciphertext, over the inner bytes
                   [inner_type 1][flags 1][data]; boxed with the sender's
                   current-epoch key and a nonce of [seq 8 BE][0 x16],
                   seq = per-direction, per-epoch counter

flags (application records): 0x01 BTLS_FRAG_MORE — more fragments of
the same application MESSAGE follow. Application payloads are
messages, not single records: up to BTLS_MAX_MSG (256 KiB) split into
BTLS_MAX_PAYLOAD-sized (1360 B) records, so no carrier message cap
(ICSP: 1400 B) leaks into the protocol. The receiver reassembles
until a fragment without BTLS_FRAG_MORE arrives; the carrier is
ordered, so fragments never interleave or reorder. Handshake frames
are small and never fragmented (their inner type is HANDSHAKE, with
no flags byte).
```

Handshake frames (inside records, or as the payload of type 0):

```
handshake = [hs_type 1][hs_len 2 BE][body]
1  CLIENT_HELLO        body = random[32] eph_pub[32]     (plaintext)
2  SERVER_HELLO        body = random[32] eph_pub[32]     (plaintext)
11 CERTIFICATE         body = server ed25519 pub[32]
15 CERTIFICATE_VERIFY  body = ed25519 sig[64]
20 FINISHED            body = verify_data[32]
```

Max record: 1400 B (one ICSP DATA message); application payload ≤
`BTLS_MAX_PAYLOAD` (1360 B) per record, messages up to `BTLS_MAX_MSG`
(256 KiB). Larger bodies are future work (see the BITE spec).

## 3. Handshake

```
C -> S: ClientHello                            (plaintext record)
S -> C: ServerHello                            (plaintext record)
        both derive: shared = X25519(eph_priv, peer_eph)
        handshake keys from transcript(CH || SH)
S -> C: Certificate + CertificateVerify + Finished
        (AEAD records, handshake keys)         [the server flight]
C -> S: Finished                               (AEAD record)
        both derive: application keys from transcript(all six msgs)
```

State machine: client `INIT -> CH_SENT -> HS -> DONE`; server
`INIT -> HS (flight via pump) -> WAIT_FIN -> DONE`. Each side emits
records via `btls_pump()` and consumes inbound ones with
`btls_feed()` — the layer never blocks and never does I/O; the caller
moves records over the carrier.

### 3.1 Transcript

`transcript = SHA-512 over the concatenation of the handshake frames,
in order, raw (before encryption)`. Both sides hash exactly the same
six frames: CH, SH, CERT, CV, FIN_s, FIN_c. It is recomputed on
demand over a growing buffer, so every derivation/verification binds
to precisely the messages exchanged so far.

### 3.2 Key schedule (HMAC-SHA512, repo style)

```
prk      = HMAC(key="btls-v1",     msg = shared)             (extract)
key(L,T) = HMAC(key=prk,           msg = L || transcript || 0x01)[0..32]

handshake epoch (transcript = CH || SH):
    hs_c2s = key("btls-hs-c2s", T)     client -> server
    hs_s2c = key("btls-hs-s2c", T)     server -> client
application epoch (transcript = full six messages):
    app_c2s = key("btls-app-c2s", T)
    app_s2c = key("btls-app-s2c", T)

Finished verify_data (transcript up to, not including, the Finished):
    FIN_s = key("btls-fin-s", T)    server -> client
    FIN_c = key("btls-fin-c", T)    client -> server
```

The client sends with c2s keys, the server with s2c keys — the two
directions never share a key or nonce space. Epoch changes zero the
old keys and reset both sequence counters (nonces restart under the
new keys). Everything directional is derived, never copied.

### 3.3 CertificateVerify

Signs the transcript so far (CH, SH, CERT) with a domain separator:

```
digest = SHA-512("btls/1.0-cert-verify" || transcript(CH||SH||CERT))
sig    = Ed25519(sk, digest)
```

The client verifies with the Certificate's pubkey. The separator makes
a signature produced here useless anywhere else (no cross-protocol
signature reuse).

## 4. Name verification (client)

When the Certificate arrives the client computes the .bait label of
the presented pubkey and compares it with the label it dialed:

```
base32_lower_nopad(SHA-512(cert_pub)[0..19])  ==  dialed label
```

Mismatch aborts the handshake before the CertificateVerify is even
checked — the endpoint is not the site the client asked for. This is
the onion-service property: the name and the key are the same object,
verified in-band, no TOFU, no pinning database.

## 5. Security notes

| Property | Mechanism |
|---|---|
| Confidentiality | AEAD records from after ServerHello; keys from ephemeral ECDH |
| Integrity / origin | secretbox MAC per record; CertificateVerify + Finished authenticate the flight |
| Replay / reorder | per-direction sequence numbers (nonces); a duplicate or reordered record fails the MAC (the carrier below already orders) |
| MITM (endpoint lies) | the .bait name check + Ed25519 signature; no CA to compromise |
| Downgrade | one fixed modern suite; nothing to negotiate |
| Client identity | v1 anonymous (server cert only); ICSP allowlist (`--peer`) can admit clients below if wanted |

Deliberate non-goals of v1: client certificates, session resumption /
0-RTT, record fragmentation (> 1400 B), alerts on the wire (fatal
errors close the carrier — the peer notices via ICSP's lifecycle),
and any X.509 interop (that is the future HTTP bridge's problem, not
the layer's).

## 6. Testing (`ipv69 btls`)

The test pair (`tests/btls_test.c`, `cmd_btls`) runs the handshake
over an ICSP association on stream 1:

```
# server (its keyring key is the certificate):
ipv69 btls server eth0 6969

# client — --label = the server key's .bait label (32 chars):
ipv69 addr --bait --key-file serverkey        # prints label
ipv69 btls client wlan0 <addr_server>:6969 ola --label <label32>

# expected (client): "handshake ok — certificate matches <label>.bait"
# expected (server): "handshake ok — peer certificate ..." then the
# app message; the client prints the encrypted ack reply.
```

Negative test: a wrong `--label` fails the handshake on the client
with the certificate-mismatch error — proving the name check runs
before any application data.

## 7. Status

Implemented (M2 + M3 of the BITE plan, 09/2026):
`include/BITE/btls.h` + `src/BITE/btls.c` (transport-agnostic layer,
no I/O, no ICSP includes) + `tests/btls_test.c` (`ipv69 btls
server|client`, also in the Windows build) + `examples/bite.c`
(`make bite` — the BITE web tool: static-file server + fetch client
over bTLS/ICSP).
