# BITE — .bait names and the web protocol

BITE is the IPv69 application layer: a web protocol that runs over ICSP
and a self-authenticating name space (`.bait`) derived from Ed25519
public keys. It is the "own HTTPS" the project always pointed to — the
`lib/ed25519` section of USAGE.md ("your future own HTTPS") and the
stated goal of `docs/icsp-spec.md` ("reliable, ordered, multi-stream and
encrypted by default transport, ready for services built on IPv69").

BITE is built from the premise that TLS exists to bolt trust onto
nameless IPs. IPv69 names *are* keys, so the whole PKI apparatus
(CA, certificates, revocation, TOFU) is replaced by one cryptographic
check: the name must match the key that signed the handshake. And the
transport is already encrypted (ICSP AEAD), so there is no TLS layer to
add either. `bite://` is `https` by construction — no extra "s".

```
┌─────────────────────────────────────────────┐
│  BITE (this spec): requests, responses,     │
│  methods, .bait names                       │
├─────────────────────────────────────────────┤
│  ICSP (docs/icsp-spec.md): association,     │
│  streams, TSN/SACK, AEAD crypto, auth by    │
│  Ed25519 identity                           │
├─────────────────────────────────────────────┤
│  IPv69 L2: 40-bit addresses, raw backend    │
│  (AF_PACKET / Npcap), gateways / mesh       │
└─────────────────────────────────────────────┘
```

## 1. Goals and non-goals

Goals:

1. A site addressable by a name **derived from its public key**, with
   no registrar, no CA and no central database: `xhz7...bait` is born
   the moment its key is generated.
2. Name resolution that is **fully local and cryptographic** — the
   network never sees the name, only the 40-bit address it already
   knows how to route (QUERY / P2P / relay / mesh).
3. The closest possible thing to *choosing* a name: vanity grinding of
   the key until the derived name starts with the wanted label, with an
   honest cost model (section 5).
4. A simple, HTTP-shaped protocol over ICSP so existing mental models,
   tools and bridges transfer: methods, status codes and headers follow
   HTTP semantics; only the trust model is new.
5. One key per site (the keyring `~/.hosts69` already supports named
   keys via `keygen --key-file`).

Non-goals (v1):

- A registry that lets anyone claim an arbitrary short name without
  owning the derived key (see section 9, future work).
- TLS, certificates, CAs, OCSP, HSTS — meaningless here; ICSP encrypts,
  the name authenticates.
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
name *is* the address's encoding.

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
  example and any CLI that takes `addr:port` can accept
  `name.bait[:port]`).
- Never in `~/.hosts69/gateways` or `--remote`: those name *gateways*
  (UDP endpoints on the real internet) and keep their real-DNS
  resolution. `.bait` names a *service inside the mesh*; the two layers
  do not mix. If a gateway line ends in `.bait` it is a config error.

### 3.4 Failure modes

- Label not 32 chars / bad charset → "not a derived name" (v1: NXDOMAIN
  equivalent).
- Address unreachable: existing timeout/`ICSP_POLL_DEAD` semantics —
  the site is offline or behind an unreachable NAT.
- A gateway lies about the endpoint (section 4.2): caught by the
  handshake, never by the resolver.

## 4. Authentication and security model

### 4.1 Name ⇔ key binding at the handshake

ICSP's INIT-ACK already carries the server's identity pub (`id_pub`)
and is signed by the server's key. The client that resolved
`label.bait` does one extra check after the existing signature
validation:

```
SHA-512(id_pub from INIT-ACK)[0..19]  ==  base32-decode(label)
```

If the endpoint does not hold the private key of the pub whose digest
is the label, it cannot produce a valid INIT-ACK at all — it fails the
ICSP signature check before the name check ever runs. The client
therefore needs no allowlist, no pinned pub, no TOFU: the name *is*
the pin. This is the onion-service property: the name and the key are
the same object, and possession of the key is proven in-band.

### 4.2 Threat model

| Threat | Outcome |
|---|---|
| Gateway answers a QUERY with its own endpoint | ICSP handshake fails (no valid INIT-ACK for the expected pub); connection refused — the lie is detected, not silently accepted |
| On-path relay replays or mutates data | ICSP AEAD per TSN + replay window; session key derived per handshake |
| Attacker claims your name ("phishing") | Impossible: the label is a digest of your pub; claiming it requires inverting SHA-512 or stealing the key |
| Key theft | Same as SSH: key file is passphrase-encrypted (`H69E1` secretbox); rotate = new key = new name |
| Client identity | v1 clients are anonymous to the server by default (any valid key); a server may require `--peer` allowlist (existing ICSP admission) |

There is no CA to compromise and no name to squat: the trust anchor is
the digest math, not an organization.

### 4.3 Encryption is implicit

ICSP encrypts every DATA chunk (secretbox, per-TSN nonce) after an
authenticated ECDH handshake. BITE adds nothing on top: `bite://` is
confidential and integrity-protected end to end — even through a relay
gateway, which only ever sees ciphertext frames. There is no plaintext
"http" variant of BITE and no port split (80 vs 443) to get wrong.

## 5. Vanity names — closest possible to choosing

### 5.1 The cost model

The label is a digest, so a chosen name can only be obtained by
grinding: generate keypairs until the label starts with the wanted
prefix. base32 is 5 bits/char, so **each extra character multiplies
the expected work by 32** (uniform distribution):

```
chars  bits   expected tries      CPU feel (order of magnitude)
  4     20        1,048,576       seconds
  5     25       33,554,432       minutes
  6     30    1,073,741,824       hours to ~1 day (multicore)
  7     35   34,359,738,368       days–weeks CPU; hours–days GPU
```

Rule of thumb for v1 tooling: advertise 4–6 chars as the practical
band; 7+ is a deliberate long grind. The grind is embarrassingly
parallel (each try is independent) and the target string can be any
prefix over `[a-z2-7]` — e.g. `meusi` + 27 random chars gives
`meusi….bait`, the closest honest approach to `meusite.bait`.

### 5.2 Tool contract: `keygen --vanity <prefix>`

Proposed CLI (to be implemented with the codec):

```
ipv69 keygen --vanity meusi --key-file site     # grind until label
                                                # starts with "meusi"
# prints: key generated at ~/.hosts69/site
#         label  meusiq2l3fy...bait  (vanity 5/32 chars)
```

Semantics:

- Loops `keypair → SHA-512(pub) → label → prefix match`; saves the
  first key that matches and exits 0. Interrupt (Ctrl-C) aborts with
  nothing saved.
- The output key IS the site identity: same keyring, same passphrase
  rules (`-N`, `IPV69_PASSPHRASE`, prompt), same `addr` derivation.
- Vanity is offline — no network, no gateway, no registry involved.
- Do the vanity grind *before* the key is used anywhere: a new key =
  a new label = a new name. Publishing the site under the final key is
  what binds the name to the content.

### 5.3 What "meusite.bait" really costs

7 characters = 2^35 ≈ 34 billion keygens. On a single modern core
(~10⁴–10⁵ keygens/s with a fast ed25519 base-mult) that is weeks; a
GPU or a multicore box with a tuned implementation brings it to
hours–days. Possible, but it is a *project*, not a command. The design
therefore makes vanity a *prefix* property, so every partial win is a
valid, usable name — nothing is wasted grinding toward the 7th char.

## 6. BITE wire protocol (v1)

### 6.1 Transport mapping (ICSP)

- **One ICSP association = one client connection.** The full ICSP
  lifecycle applies: authenticated handshake, heartbeat
  (`hb_interval_s`), dead-peer drop (`dead_timeout_s`), graceful
  SHUTDOWN.
- **One request/response pair per stream.** The client sends the
  request on a fresh stream; the server answers on the same stream and
  closes it (STREAM-RESET) after the response. Streams make concurrent
  requests natural (no head-of-line blocking — the ICSP selling point):
  N parallel requests = N open streams on one association. A client
  that only pipelines sequentially may reuse one stream.
- **Messages, not byte streams.** ICSP is message-oriented with ordered
  per-stream delivery: one request = one message, one response = one
  message. Body framing therefore needs no chunked encoding; lengths
  are implicit (section 6.4 keeps `Content-Length` for validation and
  bridging).
- **Keep-alive** = keep the association; request/response pairs happen
  over its lifetime. Idle association handling is the ICSP heartbeat
  (close on dead peer, not on application timeout).

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
- Every message is delivered whole by ICSP, so a request or response
  never splits mid-header. No chunked transfer in v1.

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
There are no cookies, no auth headers: identity lives in the ICSP
layer (client pub verified at the handshake; server allowlist via
`--peer`), which is strictly stronger than header tokens — nothing in
BITE can be replayed outside its association.

### 6.7 Size caps

v1 enforces a maximum message size on both directions (default 16 MiB,
server configurable, advertised by rejecting with `413`). Streaming
transfers (large bodies in many messages) are future work (section 9).

## 7. Example flows

Local island (site and client share an L2 or a gateway):

```
# the site (key "site" was generated, possibly with --vanity):
ipv69 addr --key-file site                     # prints the class-C addr
ipv69 bite server --key-file site              # listens :8080 on it,
                                               # announced to the mesh
# the client — name resolves locally to the addr, then everything
# is the normal QUERY/P2P/relay path:
ipv69 fetch hwko5je4lafo7aljgv3cxycjkwow2fca.bait/sobre
ipv69 fetch meusi….bait                         # vanity label, default path
```

Across islands the site announces through its gateway exactly like an
`icsp server --remote` (or a `~/.hosts69/gateways` entry) does today;
the client needs no configuration beyond its own gateway list. The
name check (section 4.1) runs regardless of how many relays the frames
crossed.

## 8. Implementation plan (repo layout)

Proposed, following existing conventions (single binary + examples +
static lib; English code/docs; one commit per file):

- `src/IPv69/baitname.c` + `.h` — codec: label⇄digest⇄addr40,
  `bait_label_from_pub()`, `bait_addr_from_label()`,
  `bait_is_derived_name()`; vanity loop `bait_grind(prefix, cb)`
  (pure CPU, no deps beyond lib/ed25519).
- `keygen --vanity <prefix>` in `src/IPv69/keygen.c` — CLI on the
  grind (section 5.2).
- `examples/bite.c` (`make bite`) — server + `fetch` client on the
  ICSP session API, mirroring `examples/icsp_chat.c`; the server is a
  multi-association accept loop (the `icsp_hub` pattern) serving
  static files from a root dir.
- Destination parsing: accept `name.bait[:port]` where commands take
  `addr:port` (parse.c), resolving locally to the addr — no new
  network code.
- Docs: this spec; later README roadmap items ("Name system (.bait)",
  "Application layer (BITE)") and a USAGE §13 when the tools land.

Milestones (each independently testable by you, in order):

- M0 — codec: label⇄addr roundtrip matches `ipv69 addr` output.
- M1 — `keygen --vanity`: grind, save, and `addr`/label agree.
- M2 — `bite` server + `fetch` over veth: static file, 404, HEAD,
  concurrent requests on one association.
- M3 — mesh: site and client on two islands through a gateway seed,
  P2P and relay; wrong-endpoint spoof test fails the handshake.

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
- **HTTP bridge**: a gateway that terminates BITE and speaks real HTTP
  to legacy clients (or vice-versa). Trivial by design: same methods,
  same status numbers, same headers.
