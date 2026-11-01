# BaitNet — Python implementation of the IPv69 protocol

The same protocol as the C tree (`c/`), in Python: EtherType `0x6969`,
32-byte header, 40-bit addresses, identity-derived addressing, `.bait`
labels, ICSP with the full session layer, the `H69E1` keyring, mac1 and
BITE (bTLS + documents).

```bash
cd python
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'          # pynacl + pytest

baitnet selftest                 # wire vectors, no root, no NIC
baitnet addr --bait              # identity address + .bait label
pytest -q                        # 50 checks: vectors + full loopback stack

# raw L2 (needs root, like c/build/ipv69):
sudo baitnet bite serve --root ./www --ifname eth0 --port 8080
sudo baitnet bite fetch <label>.bait/index.html --ifname eth0 --port 8080
```

## Layout

```
src/baitnet/
  core/      IPv69 layer  (mirrors c/src/IPv69)
    constants.py  wire constants (next_header, control codes, chunk types)
    addr.py       40-bit address: parse/format, classes, derive from a key
    crc.py        CRC32c (Castagnoli)
    header.py     IPv69 header (32B) pack/unpack
    frame.py      Ethernet frame build/parse
    l2.py         AF_PACKET backend + 'auto' interface resolution
    transport.py  L2Transport (real NIC) / LoopTransport (tests)
    keyring.py    ~/.hosts69 key files, H69E1 encrypted format
    mac1.py       Poly1305 pre-auth tag keyed by the destination address
    dhcp.py       DHCP69 client (DISCOVER/REQUEST + mac1)
  icsp/      ICSP       (mirrors c/src/ICSP)
    framing.py    12-byte header, chunks, CRC32c over the whole payload
    session.py    INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK, directional keys,
                  DATA + TSN/SACK, replay window, ordering, retransmission,
                  heartbeat, shutdown, allowlist
  bite/      BITE       (mirrors c/src/BITE + c/examples/bite.c)
    names.py      .bait labels (base32 of SHA-512(pub))
    btls.py       bTLS records: hellos, certificate, key schedule, AEAD
    bite.py       request/response, static files, MIME, traversal guard
  lib/       crypto     (mirrors c/lib/ed25519 — no protocol imports)
    crypto.py     Ed25519, XSalsa20-Poly1305, Poly1305, X25519, HMAC-SHA512
  cli.py     the `baitnet` command
tests/       wire vectors (C-produced) + loopback stack tests
```

## Why the vectors matter

The Python side is not a rewrite of the protocol: it is a second
implementation of the *same bytes*. The tests assert values produced by the
C tools, so any divergence shows up as a failing test:

- `crc32c("abc") == 0x364b3fb7`
- ICSP packet `1f904e20…616263` for a DATA chunk (tsn 7, stream 0, seq 0, "abc")
- `pub 3198c3c0…` → address `83.81.0b.be.6c` and label
  `ioaqxptmw3uodstqdlmfvyeakuvzqwvh.bait`
- `fixtures/c_key_H69E1.asc` is a key file **written by the C binary**
  (passphrase `pyfx`): loading it proves the H69E1 layout and the
  `SHA-512(salt) XOR SHA-512(pass)` KDF are compatible.

The loopback tests (`tests/loopback.py`) go further: two real endpoint state
machines over an in-memory link, so a full ICSP handshake, an encrypted
stream, a bTLS handshake and a BITE download all run in CI without root or a
network interface.

See `../docs/python-port.md` for what is ported and what is still C-only
(the UDP tunnel gateway, the DHCP server, PPPoE69, the bring-up daemon).
