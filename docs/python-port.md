# Python port — status

The C tree (`c/`) is the reference implementation. The Python package
(`python/src/baitnet`) is a second implementation of the same wire formats,
kept honest by tests that assert values produced by the C tools and by a
loopback harness that runs the whole stack in-process.

## Layout (mirrors `c/src`)

| package | modules | C counterpart |
|---|---|---|
| `core/` | constants, addr, crc, header, frame, l2, transport, keyring, mac1, dhcp | `c/src/IPv69` + `c/include/IPv69` |
| `icsp/` | framing (chunks + CRC), session (handshake, DATA/SACK, lifecycle) | `c/src/ICSP` |
| `bite/` | names (.bait), btls (records), bite (documents) | `c/src/BITE` + `c/examples/bite.c` |
| `lib/` | crypto (Ed25519, XSalsa20-Poly1305, Poly1305, X25519, HMAC) | `c/lib/ed25519` |
| `cli.py` | the `baitnet` command | `c/src/IPv69/main.c` |

## Done

| area | module | notes |
|---|---|---|
| addresses | `core/addr.py` | 40-bit value, dotted-hex, classes A-E, derivation from `SHA-512(pub)` |
| header / frames | `core/header.py`, `core/frame.py` | 32-byte header field for field, EtherType `0x6969` |
| crypto | `lib/crypto.py` | Ed25519 (seed = private key), C-compatible secretbox blob, Poly1305, X25519, HMAC-SHA512 |
| keyring | `core/keyring.py` | `~/.hosts69`, `H69E1` encrypted files, byte-compatible with the C one |
| `.bait` | `bite/names.py` | label = base32(SHA-512(pub)[0:20]), label → address |
| mac1 | `core/mac1.py` | Poly1305 keyed by the destination address |
| ICSP framing | `icsp/framing.py` | 12-byte header, chunks, CRC32c over the whole payload |
| DHCP69 client | `core/dhcp.py` | DISCOVER/REQUEST/ACK + mac1 |
| raw L2 | `core/l2.py` | AF_PACKET, `auto` interface (default route, Android fallback) |
| **ICSP session** | `icsp/session.py` | INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK, X25519 + directional keys, DATA with TSN/SACK, replay window, ordered per-stream delivery, retransmission, heartbeat, shutdown, stream reset, allowlist |
| **bTLS** | `bite/btls.py` | ClientHello/ServerHello/Certificate/CertificateVerify/Finished, per-epoch keys, AEAD records, message fragmentation |
| **BITE** | `bite/bite.py` | request/response, static serving (200/400/404/405/500), traversal guard, MIME, HEAD, `.bait` resolution |
| CLI | `cli.py` | `addr`, `keygen`, `selftest`, `send`, `recv`, `ping`, `bite serve`, `bite fetch` |

## Tests

`pytest` runs 50 checks. Two families:

1. **Wire vectors from the C tools** — CRC32c, the ICSP packet hex, address and
   label derivation, a key file written by the C binary.
2. **Loopback stack** (`tests/loopback.py`) — two real endpoints over an
   in-memory link, no root and no NIC: handshake with matching directional
   keys, multi-stream ordered delivery, SACK/retransmission, tamper rejection,
   allowlist rejection, then bTLS + a BITE fetch of a real file (including
   fragmentation and a wrong-`.bait` rejection).

## Still C-only

1. **UDP tunnel gateway** (`--remote` carrier, QUERY/GW_CALL, cryptokey
   routing, mesh, `--peer-gw` federation) — the Python stack is L2-only.
2. **DHCP69 server** — pool, allowlist, `--learn`, signed OFFER/ACK.
3. **PPPoE69** — access concentrator and dialer.
4. **Bring-up daemon** — lease keepalive + `lease/renew/status` socket.
5. **Identity hiding (ICSP IDBOX)** — the C path feeds an Ed25519 key into
   X25519 on one side and a raw seed on the other, so the two sides disagree;
   it is not interoperable and not ported.

Rule of thumb for the next layer: implement against the C wire format, add a
test with a vector captured from the C tool (or a loopback test), and only
then wire it into the CLI. A layer without a test is not "done".
