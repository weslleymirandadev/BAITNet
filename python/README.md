# BaitNet — Python implementation of the IPv69 protocol

The same protocol as the C tree (`c/`), in Python: EtherType `0x6969`,
32-byte header, 40-bit addresses, identity-derived addressing, `.bait`
labels, ICSP framing with the CRC32c over the whole payload, the `H69E1`
keyring and the mac1 pre-auth tag.

```bash
cd python
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'          # pynacl + pytest

baitnet selftest                 # wire vectors, no root, no NIC
baitnet addr --bait              # identity address + .bait label
pytest -q                        # 30+ tests, all vectors from the C side
```

`baitnet send/recv/ping` speak raw L2 and therefore need root (or
`CAP_NET_RAW`), exactly like `c/build/ipv69`.

## Layout

```
src/baitnet/
  constants.py   wire constants (next_header, control codes, chunk types)
  addr.py        40-bit address: parse/format, classes, derive from a key
  header.py      IPv69 header (32B) pack/unpack
  frame.py       Ethernet frame build/parse
  l2.py          AF_PACKET backend + 'auto' interface resolution
  crypto.py      Ed25519 + XSalsa20-Poly1305 (PyNaCl) + Poly1305 (pure)
  keyring.py     ~/.hosts69 key files, H69E1 encrypted format
  bait.py        .bait labels (base32 of SHA-512(pub))
  mac1.py        Poly1305 pre-auth tag keyed by the destination address
  icsp.py        ICSP header + chunk framing + CRC32c
  dhcp.py        DHCP69 client (DISCOVER/REQUEST + mac1)
  cli.py         the `baitnet` command
tests/           wire vectors shared with the C implementation
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

See `../docs/python-port.md` for what is ported and what is still C-only.
