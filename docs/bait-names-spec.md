# BITE — .bait names and the web protocol

BITE is the IPv69 application layer: a web protocol that runs over its
own security layer (**bTLS**) on top of ICSP, plus a self-authenticating
name space (`.bait`) derived from Ed25519 public keys. It is the "own
HTTPS" the project always pointed to — the `lib/ed25519` section of
USAGE.md ("your future own HTTPS") and the stated goal of
`docs/icsp-spec.md` ("reliable, ordered, multi-stream and encrypted by
default transport, ready for services built on IPv69").

The premise is that TLS exists to bolt trust onto nameless IPs. IPv69
names *are* keys, so the whole PKI apparatus (CA, certificates,
revocation, TOFU) is replaced by one cryptographic check: the name must
match the key that signed the handshake. What remains of TLS is still
worth building explicitly — a handshake with forward secrecy and a
record layer that guarantees **encryption by default**: no BITE byte,
header or body, ever travels in clear text on any carrier.

```
┌─────────────────────────────────────────────┐
│  BITE (this spec): requests, responses,     │
│  methods, .bait names                       │
├─────────────────────────────────────────────┤
│  bTLS (docs/btls-spec.md): handshake +      │
│  AEAD records, PFS, cert = the site key     │
├─────────────────────────────────────────────┤
│  ICSP (docs/icsp-spec.md): association,     │
│  streams, reliable ordered messages         │
├─────────────────────────────────────────────┤
│  IPv69 L2: 40-bit addresses, raw backend    │
│  (AF_PACKET / Npcap), gateways / mesh       │
└─────────────────────────────────────────────┘
```

## 1. Goals and non-goals

Goals:

1. A site addressable by a name **derived from its public key**, with
   no registrar, no CA and no central database: the `.bait` name is
   born the moment its key is generated (the onion-service model —
   everyone gets a long derived name; vanity is opt-in, section 5).
2. Name resolution that is **fully local and cryptographic** — the
   network never sees the name, only the 40-bit address it already
   knows how to route (QUERY / P2P / relay / mesh).
3. **bTLS, the project's own TLS** — a TLS 1.3-flavored security layer
   (ECDHE handshake + AEAD records) built on the crypto primitives
   already in the repo, with the server's Ed25519 key as its
   certificate. No plaintext BITE traffic on the wire, ever.
4. The closest possible thing to *choosing* a name: vanity grinding of
   the key until the derived name starts with the wanted label, with an
   honest cost model (section 5).
5. A simple, HTTP-shaped protocol over bTLS so existing mental models,
   tools and bridges transfer: methods, status codes and headers follow
   HTTP semantics; only the trust model is new.
6. One key per site (the keyring `~/.hosts69` already supports named
   keys via `keygen --key-file`).

Non-goals (v1):

- Market TLS / X.509 (RFC 8446 wire, ASN.1 certificates, CA chains) —
  bTLS is the project's own TLS-flavored layer with the raw Ed25519
  key as the certificate; interop with browsers is a future bridge,
  not a v1 goal.
- A registry that lets anyone claim an arbitrary short name without
  owning the derived key (see section 9, future work).
- Cookies/sessions/JS — v1 is a document protocol (static + form
  submission), not a browser platform.
- Replacing the DNS you already run: `.bait` never touches DNS; real
  domains keep resolving the way they do today (gwfile/`--remote`).

## 2. The .bait name space

### 2.1 Derivation

Let `pub` be the site's Ed25519 public key (32 bytes, from the keyring)
and `d = SHA-512(pub)` (64 bytes, big-endian). The label is the first
160 bits of `d` encoded with RFC 4648 base32, lowercase, no padding —
exactly 32 characters:

```
label = base32_lower_nopad( d[0..19] )
fqdn  = label + ".bait"
```

Same digest, same code path as the address (`ipv69_addr_derive` in
`src/IPv69/parse.c`): the first 5 bytes of `d` already produce the
40-bit identity address with a class mask on byte 0. The label shares
`d[0..19]`, so the 40-bit address is **computable from the name alone**
(section 3.1) — the name and the address are two views of one digest.

Example (illustrative pub = bytes `00..1f`):

```
pub            = 000102...1f                      (32 bytes)
d = SHA-512    = 3d 94 ee a4 9c 58 0a ef ...      (d[0..4] shown)
addr40 (C)     = bd.94.ee.a4.9c
label          = hwko5je4lafo7aljgv3cxycjkwow2fca  (32 chars)
fqdn           = hwko5je4lafo7aljgv3cxycjkwow2fca.bait
```

Implemented in `src/BITE/baitname.c` (`bait_label_from_pub`,
`bait_label_to_addr`, `bait_label_valid`), kept in its own tree like
ICSP, depending only on lib/ed25519.

### 2.2 Syntax and canonical form

- Charset: `[a-z2-7]` (RFC 4648 base32 alphabet, digits `2-7`, no
  `0/1/8/9`), lowercase only on the wire.
- Length: exactly 32 chars. Any `.bait` name whose leftmost label is
  not 32 chars of `[a-z2-7]` is **not a derived name** (reserved for
  the future claim layer, section 9) and does not resolve in v1.
- Case: URLs and CLI input are lowercased before decode; canonical form
  is lowercase.
- The label is 160 bits of a preimage-resistant digest: two keys
  colliding on a label costs ~2^80 (birthday), so label ownership is
  exclusive by construction. Claiming someone else's label means
  inverting SHA-512.

### 2.3 Address co-derivation

With `d` as above, the address that `.bait` names resolve to is the
class-C address of the same key (the default class of `ipv69 addr`):

```
addr40 = [ 0x80 | (d[0] & 0x3f), d[1], d[2], d[3], d[4] ]
```

Class C = public = the class the gateways route by default (`--private`
only widens it). A `.bait` site is therefore reachable from any island
through the existing gateway machinery. Private-only islands still use
BITE over plain L2 addresses (`addr:port`), just without a `.bait`
name in front.

## 3. Resolution — no DNS, no DHT

### 3.1 Local decode (the resolver is a pure function)

```
fqdn "meusi….bait"  →  strip ".bait", lowercase
    →  base32-decode 32 chars  →  20 bytes = d[0..19]
    →  addr40 = [ 0x80|(d[0]&0x3f), d[1..4] ]
```

No packet is sent to resolve the name; there is no server to ask. The
name *is* the address's encoding (`bait_label_to_addr`).

### 3.2 Endpoint discovery (the existing stack)

Once the client has the 40-bit address, finding the endpoint is
exactly today's problem, solved today:

- same L2 island: ND (the `recv`/`send` announce/learn flow);
- different islands: gateway QUERY → answer with endpoint → GW_CALL →
  hole punching → P2P; relay as fallback (USAGE.md §7);
- federated gateways: GW_ROUTE makes the QUERY a local lookup.

Nothing in the gateway, the mesh or the wire needs to know about
`.bait` or BITE: names are resolved to addresses at the client before
any frame is sent.

### 3.3 Where .bait is recognized

- As a destination in BITE tools/commands (the future `fetch`/server
  and any CLI that takes `addr:port` can accept `name.bait[:port]`).
- `ipv69 addr --bait` prints the label + fqdn of a key; `ipv69 keygen`
  prints the `.bait` name of every key it creates.
- Never in `~/.hosts69/gateways` or `--remote`: those name *gateways*
  (UDP endpoints on the real internet) and keep their real-DNS
  resolution. `.bait` names a *service inside the mesh*; the two layers
  do not mix. If a gateway line ends in `.bait` it is a config error.

### 3.4 Failure modes

- Label not 32 chars / bad charset → "not a derived name" (v1: NXDOMAIN
  equivalent).
- Address unreachable: existing timeout/`ICSP_POLL_DEAD` semantics —
  the site is offline or behind an unreachable NAT.
- A gateway lies about the endpoint (section 4.3): caught by the
  bTLS handshake, never by the resolver.

## 4. Security: bTLS

BITE's security is its own TLS-flavored layer, **bTLS/1.0** (full wire
layout in `docs/btls-spec.md`, written with the implementation). It
sits between BITE and the reliable transport so the same BITE code is
secure over ICSP today and over any future plaintext carrier (a TCP
bridge, a PPPoE69 session) tomorrow — encryption is a property of
BITE, not of the carrier it happens to ride.

### 4.1 Why a TLS layer on top of an encrypted transport

ICSP already authenticates and AEAD-encrypts its DATA chunks. bTLS is
still built, deliberately:

- **Explicitness** — the security contract of a *web* protocol lives in
  its own layer with its own handshake and records, where tools and
  future bridges look for it (TLS is the recognizable shape of HTTPS).
- **Carrier independence** — BITE + bTLS is correct over any reliable
  ordered transport, encrypted or not. ICSP's crypto then becomes a
  second line (defense in depth), not the only one.
- **The name binding** — the `.bait` check happens in the bTLS
  handshake (section 4.2), not in the transport, so it is not tied to
  ICSP's identity model.

### 4.2 Handshake (TLS 1.3-flavored) and name binding

Fixed suite — no negotiation: X25519 ECDHE (PFS), Ed25519 identities
(sign/verify), HKDF-SHA512 key schedule (the same directional-label
construction ICSP uses), XSalsa20-Poly1305 secretbox (AEAD records).

1. C → S: ClientHello — random, client ephemeral X25519 pub.
2. S → C: ServerHello — random, server ephemeral X25519 pub.
3. From here on everything is encrypted with handshake traffic keys
   derived from the ECDH secret + transcript (nothing after the two
   hellos is ever plaintext; the hellos carry only fresh ephemeral
   public keys).
4. S → C: Certificate — the server's Ed25519 pub (32 bytes, the raw
   key as certificate — no X.509).
5. S → C: CertificateVerify — Ed25519 signature over the transcript,
   proving the holder of the private key is speaking.
6. S → C / C → S: Finished — transcript MAC under the handshake keys.
7. Application traffic keys derived from the full transcript.

**Name verification (client side):** after the Certificate, the client
computes `base32_lower_nopad(SHA-512(cert_pub)[0..19])` and compares it
with the label it dialed. Mismatch aborts the handshake before a single
application record. If the endpoint does not hold the private key whose
digest is the label, it cannot produce a valid CertificateVerify at
all. The client needs no allowlist, no pinned key, no TOFU: the name
*is* the pin. This is the onion-service property: name and key are the
same object, and possession is proven in-band.

Client identity: v1 clients are anonymous to the server by default; a
server may require a client Certificate and allowlist its pub (the
`--peer` admission model). bTLS records guarantee the same AEAD
integrity regardless of which side authenticates.

### 4.3 Threat model

| Threat | Outcome |
|---|---|
| Gateway answers a QUERY with its own endpoint | bTLS handshake fails (no valid Certificate for the expected label); the lie is detected, not silently accepted |
| On-path relay replays or mutates data | bTLS record AEAD + sequence numbers; ICSP's AEAD/replay window below is a second line |
| Attacker claims your name ("phishing") | Impossible: the label is a digest of your pub; claiming it requires inverting SHA-512 or stealing the key |
| Key theft | Same as SSH: key file is passphrase-encrypted (`H69E1` secretbox); rotate = new key = new name |
| Downgrade / cipher negotiation | No negotiation — one fixed, modern suite; there is nothing to downgrade to |

There is no CA to compromise and no name to squat: the trust anchor is
the digest math, not an organization.

### 4.4 Encryption by default

Every BITE message travels as one bTLS application record: AEAD
ciphertext with a per-direction sequence number. There is no plaintext
"http" variant of BITE and no port split (80 vs 443) to get wrong —
`bite://` is confidential and integrity-protected end to end, even
through a relay gateway, which only ever sees ciphertext.

## 5. Vanity names — closest possible to choosing

### 5.1 The cost model

The label is a digest, so a chosen name can only be obtained by
grinding: generate keypairs until the label starts with the wanted
prefix. base32 is 5 bits/char, so **each extra character multiplies
the expected work by 32** (uniform distribution). One try = one
Ed25519 keypair + one SHA-512. The repo's TweetNaCl-based ed25519 does
~10³ tries/s per core; a fast ref10-style implementation or a GPU
raises the rate by orders of magnitude, and the grind parallelizes
perfectly (each try is independent):

```
chars  bits   expected tries      single core (TweetNaCl ~10³/s)
  4     20        1,048,576       ~15 min
  5     25       33,554,432       ~9 h
  6     30    1,073,741,824       ~12 days
  7     35   34,359,738,368       ~1 year
```

Divide by the number of cores (or by the speedup of a faster ed25519)
for real expectations: 4–5 chars is the practical band on a normal
machine (4 chars ≈ minutes on 8 cores), 6+ is a deliberate long grind,
7+ is a GPU/weeks project. The design makes vanity a *prefix*
property, so every partial win is already a valid, usable name —
nothing is wasted grinding toward the last char.

### 5.2 Tool: `keygen --vanity`

Implemented (M1):

```
ipv69 keygen --vanity meusi --key-file site     # grind until label
                                                # starts with "meusi"
#   keygen: grinding for a .bait label starting with "meusi" (Ctrl-C
#           aborts, nothing is saved)...
#   keygen: vanity 65536 tries (980/s), best 3/5 chars: mej...
#   keygen: label meusiq2l3fy...bait found after 1002321 tries
#   Your identification has been saved in ~/.hosts69/site
#   ...
#   bait name (docs/bait-names-spec.md): meusiq2l3fy...bait
```

Semantics:

- Grinds offline (no network, no gateway, no registry), printing a
  progress line every ~2s (tries, rate, best partial prefix).
- The overwrite prompt runs BEFORE the grind, so a long grind is never
  wasted on a destination the user would refuse; Ctrl-C aborts with
  nothing saved.
- The winning keypair is saved with the same rules as any key
  (named file, passphrase via `-N`/prompt/`IPV69_PASSPHRASE`) — the
  output key IS the site identity, with the same `addr` derivation.
- Prefix chars must be in `[a-z2-7]`, 1–32 long; validated before any
  work starts. `ipv69 addr --bait` shows the label/fqdn of any key.

### 5.3 What "meusite.bait" really costs

7 characters = 2^35 ≈ 34 billion keygens ≈ a year on one TweetNaCl
core, days–weeks on a tuned multicore/GPU grind. Possible, but a
*project*, not a command — hence the prefix model above.

## 6. BITE wire protocol (v1)

### 6.1 Transport mapping (ICSP + bTLS)

- **One bTLS session = one client connection**, riding one ICSP
  association (the reliable ordered message stream). The full ICSP
  lifecycle applies underneath: heartbeat (`hb_interval_s`), dead-peer
  drop (`dead_timeout_s`), graceful SHUTDOWN.
- **Every BITE message is one bTLS application record** (encrypted,
  section 4.4) carried as one ICSP message. Handshake frames are bTLS
  handshake records on the same association.
- **One request/response pair per ICSP stream.** The client sends the
  request on a fresh stream; the server answers on the same stream and
  closes it (STREAM-RESET) after the response. Streams make concurrent
  requests natural (no head-of-line blocking — the ICSP selling point):
  N parallel requests = N open streams on one session. A client that
  only pipelines sequentially may reuse one stream.
- **Messages, not byte streams.** ICSP is message-oriented with ordered
  per-stream delivery: one request = one message, one response = one
  message. Body framing therefore needs no chunked encoding; lengths
  are implicit (section 6.4 keeps `Content-Length` for validation and
  bridging).
- **Keep-alive** = keep the session; request/response pairs happen over
  its lifetime. Idle handling is the ICSP heartbeat (close on dead
  peer, not on an application timeout).

### 6.2 Addressing and default port

- A BITE service listens on the identity's class-C address
  (section 2.3) on ICSP port **8080** by default (decimal, like every
  IPv69 port).
- URL syntax:

```
bite://<label>.bait[:<port>]/<path>[?<query>]
```

  `<port>` omitted → 8080. In plain-text destinations
  (`fetch meusi….bait/sobre`) the scheme may be omitted.

### 6.3 Message grammar

Text, CRLF line endings, like HTTP/1.1:

```
request:
  <method> SP <target> SP BITE/1.0 CRLF
  *( <header> CRLF )
  CRLF
  [ body ]

response:
  BITE/1.0 SP <status> SP <reason> CRLF
  *( <header> CRLF )
  CRLF
  [ body ]
```

- `<target>` = absolute path starting with `/`, optional `?query`,
  percent-encoded like HTTP. No absolute-URI form in v1 (there is no
  proxy hop that needs it).
- Body = the remainder of the message after the first empty line;
  binary-safe. One message per direction (section 6.1).
- The whole message is one bTLS record: headers and body are never
  visible in clear text (section 4.4). No chunked transfer in v1.

### 6.4 Methods

`BITE` is the protocol name and its own read verb; the rest follow
HTTP semantics so muscle memory and future HTTP bridges transfer:

| Method | Semantics | Body | Idempotent |
|---|---|---|---|
| `BITE` | retrieve the representation of `<target>` (HTTP GET semantics; the canonical read verb) | no | yes |
| `HEAD` | like BITE, no body in the response | no | yes |
| `POST` | submit `<body>` to `<target>` (forms, actions) | yes | no |
| `PUT` | store `<body>` at `<target>` | yes | yes |
| `DELETE` | remove `<target>` | no | yes |

`GET` is accepted as an alias of `BITE` and MUST be treated identically
(bridges, habits and generated links will use it). Servers MUST NOT
require a method they do not implement — unknown method → `405`.

### 6.5 Status codes

HTTP's numeric space, BITE reasons:

| Code | Reason | Notes |
|---|---|---|
| 200 | OK | |
| 201 | Created | after PUT/POST |
| 204 | No Content | |
| 301 | Moved Permanently | `Location` header |
| 304 | Not Modified | if a validator is sent |
| 400 | Bad Request | malformed line/headers |
| 403 | Forbidden | identity rejected (server allowlist) |
| 404 | Not Found | |
| 405 | Method Not Allowed | |
| 413 | Payload Too Large | over the size cap |
| 500 | Internal Error | |
| 503 | Unavailable | shutting down |

### 6.6 Headers (v1 minimal set)

Request (all optional):

- `Content-Type`, `Content-Length` — POST/PUT body (length optional
  for validation; the message boundary is authoritative).
- `Host: <label>.bait[:port]` — reserved for future multi-name sites
  (section 9); a v1 server with one name MAY ignore it.
- `If-Modified-Since` — optional caching validator.

Response:

- `Content-Type` (default `application/octet-stream`),
  `Content-Length` (for validation/bridging),
- `Location` (301),
- `Last-Modified` (304/If-Modified-Since),
- `Server: BITE/1.0` (informational).

Unknown headers are ignored by v1 receivers (extensibility point).
There are no cookies, no auth headers: identity lives in the bTLS
layer (client Certificate + `--peer` allowlist), which is strictly
stronger than header tokens — nothing in BITE can be replayed outside
its session.

### 6.7 Size caps

v1 enforces a maximum message size on both directions (default 16 MiB,
server configurable, advertised by rejecting with `413`). Streaming
transfers (large bodies in many messages) are future work (section 9).

## 7. Example flows

Local island (site and client share an L2 or a gateway):

```
# the site (key "site" generated with a vanity prefix):
ipv69 keygen --vanity meusi --key-file site     # -> meusiq2l3fy....bait
ipv69 addr --bait --key-file site               # addr + label + fqdn
ipv69 bite server --key-file site               # bTLS :8080 on its
                                                # class-C addr, announced
# the client — the name resolves locally to the addr, then everything
# is the normal QUERY/P2P/relay path, then bTLS authenticates:
ipv69 fetch hwko5je4lafo7aljgv3cxycjkwow2fca.bait/sobre
ipv69 fetch meusi….bait                         # vanity label, default path
```

Across islands the site announces through its gateway exactly like an
`icsp server --remote` (or a `~/.hosts69/gateways` entry) does today;
the client needs no configuration beyond its own gateway list. The
name check (section 4.2) runs regardless of how many relays the frames
crossed.

## 8. Implementation status and plan

The BITE stack lives in its own tree, like ICSP: `src/BITE/`,
`include/BITE/` (codec) — the `.bait` name codec is already linked into
the single binary, the Windows build and the static lib
(`make lib`). Docs: this spec; `docs/btls-spec.md` comes with the bTLS
implementation.

| Milestone | Scope | Status |
|---|---|---|
| M0 — codec | `src/BITE/baitname.c`: label⇄pub, label→addr40, validity | ✅ done |
| M1 — vanity | `keygen --vanity PREFIX` (grind + save + progress), `addr --bait` | ✅ done |
| M2 — bTLS | `src/BITE/btls.c` + `include/BITE/btls.h`: handshake (ECDHE + cert + name check), record AEAD, key schedule; test pair over veth; `docs/btls-spec.md` | pending |
| M3 — BITE over bTLS | `examples/bite.c` (`make bite`): server (multi-association accept, static files) + `fetch` client; `.bait` destinations; 404/HEAD/concurrency | pending |
| M4 — mesh | site and client on two islands through a gateway seed; P2P and relay; wrong-endpoint spoof test fails the bTLS handshake | pending |

Commit convention applies (one commit per file, English, push).

## 9. Future work (out of scope for v1)

- **Claimed short names**: a registry where arbitrary labels (e.g.
  `meusite.bait`) are bound to a pub by signed claims gossiped between
  gateways (a GW_NAME control extension, first-claim-wins + renewal).
  Resolution then checks claims only for non-derived labels (length ≠
  32); derived names never depend on it. Requires deciding squatting,
  expiry and gateway trust — a protocol change, planned separately.
- **Zones/subdomains**: labels to the left of a derived label
  (`blog.<label>.bait`) owned by the key holder via a self-signed
  zone; enables one key, many names. Needs a zone fetch mechanism.
- Streaming (multi-message bodies), cookies/sessions, auth tokens,
  server-side includes/templating — application evolution, not
  protocol.
- **HTTP/HTTPS bridge**: a gateway that terminates BITE/bTLS and speaks
  real HTTP(S) to legacy clients (or vice-versa). Trivial by design:
  same methods, same status numbers, same headers; the bridge is where
  X.509 meets `.bait` (a pinned self-signed cert, or a public suffix
  the browser can be taught).
