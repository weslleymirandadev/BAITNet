# Python port — status

The C tree (`c/`) is the reference implementation. The Python package
(`python/src/baitnet`) is a second implementation of the same wire formats,
kept honest by tests that assert values produced by the C tools.

## Done

| area | module | notes |
|---|---|---|
| addresses | `addr.py` | 40-bit value, dotted-hex parse/format, classes A-E, derivation from `SHA-512(pub)` |
| header | `header.py` | 32-byte IPv69 header, field-for-field with `c/include/IPv69/header.h` |
| frames | `frame.py` | Ethernet build/parse, EtherType `0x6969` |
| crypto | `crypto.py` | Ed25519 (seed = private key), XSalsa20-Poly1305 secretbox with the C padding, Poly1305 |
| keyring | `keyring.py` | `~/.hosts69`, bare names, `IPV69_KEYFILE`, `H69E1` encrypted files, plain seeds |
| `.bait` | `bait.py` | label = base32(SHA-512(pub)[0:20]), label → address |
| mac1 | `mac1.py` | `Poly1305(SHA-512("ipv69-mac1"‖addr)[0:32], msg)` |
| ICSP framing | `icsp.py` | 12-byte header, chunks, CRC32c over the whole payload with the field zeroed |
| DHCP69 client | `dhcp.py` | DISCOVER/REQUEST/ACK + mac1, no lease daemon |
| raw L2 | `l2.py` | AF_PACKET, `auto` interface (default route, Android fallback) |
| CLI | `cli.py` | `addr`, `keygen`, `selftest`, `send`, `recv`, `ping` |

## Still C-only (roadmap, in dependency order)

1. **ICSP session** — handshake (INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK),
   HKDF-directional keys, DATA with TSN/SACK + retransmission, rekey,
   heartbeat/shutdown. `icsp.py` currently has only the framing layer.
2. **DHCP69 server** — pool, allowlist, `--learn`, signed OFFER/ACK.
3. **UDP tunnel gateway** — `--remote` carrier, QUERY/GW_CALL hole punching,
   cryptokey routing, gateway mesh and `--peer-gw` federation.
4. **bTLS / BITE** — ECDHE + AEAD records, static file serving, `.bait`
   resolution at the client.
5. **PPPoE69** — access concentrator and dialer (needs a TAP on Linux).
6. **Bring-up daemon** — lease keepalive + `lease/renew/status` socket.

Rule of thumb when porting a layer: write it against the C wire format,
add a test with a vector captured from the C tool, and only then wire it
into the CLI. A layer without a vector test is not "done".
