"""mac1 — WireGuard-style cheap pre-auth tag (c/src/IPv69/mac1.c).

    key = SHA-512(b"ipv69-mac1" || addr40_be)[0:32]
    tag = Poly1305(key, msg)

The key is derived from the frame's *destination* address, so the server
recomputes it from what it receives and needs no configuration. The tag
guards the handshake before any Ed25519/ECDH work.
"""

from __future__ import annotations

from .constants import MAC1_LABEL, MAC1_LEN
from .crypto import poly1305, sha512


def key_for(server_addr: int) -> bytes:
    if not 0 <= server_addr < (1 << 40):
        raise ValueError("address out of range")
    return sha512(MAC1_LABEL + server_addr.to_bytes(5, "big"))[:32]


def compute(key: bytes, msg: bytes) -> bytes:
    return poly1305(msg, key)


def verify(key: bytes, msg: bytes, tag: bytes) -> bool:
    if len(tag) != MAC1_LEN:
        return False
    expected = compute(key, msg)
    # constant-time compare: tags are public, but keep the habit
    diff = 0
    for a, b in zip(expected, tag):
        diff |= a ^ b
    return diff == 0
