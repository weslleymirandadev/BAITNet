"""BITE ``.bait`` labels — base32 of SHA-512(pub) (c/src/BITE/baitname.c).

A label is 32 chars of ``abcdefghijklmnopqrstuvwxyz234567`` (RFC 4648 base32,
lowercase, no padding) over the first 20 digest bytes. The first 8 chars
encode the first 40 bits, i.e. the address's digest bytes, so a name
resolves to an address with no DNS at all.
"""

from __future__ import annotations

from .addr import format_addr, parse_addr
from .constants import (BAIT_ALPHABET, BAIT_LABEL_LEN, ED25519_PUB_LEN)
from .crypto import sha512

_VALUE = {c: i for i, c in enumerate(BAIT_ALPHABET)}


def label_from_pub(pub: bytes) -> str:
    if len(pub) != ED25519_PUB_LEN:
        raise ValueError("public key must be 32 bytes")
    digest = sha512(pub)
    acc = 0
    nbits = 0
    out: list[str] = []
    for i in range(20):
        acc = (acc << 8) | digest[i]
        nbits += 8
        while nbits >= 5:
            nbits -= 5
            out.append(BAIT_ALPHABET[(acc >> nbits) & 0x1F])
    return "".join(out)


def label_valid(label: str) -> bool:
    if not label or len(label) != BAIT_LABEL_LEN:
        return False
    return all(c.lower() in _VALUE for c in label)


def label_to_addr(label: str) -> int:
    """Decode the address a label stands for (class C, like the C code)."""
    if not label_valid(label):
        raise ValueError(f"invalid .bait label: {label!r}")
    acc = 0
    nbits = 0
    out = bytearray()
    for ch in label[:8]:
        acc = (acc << 5) | _VALUE[ch.lower()]
        nbits += 5
        while nbits >= 8:
            nbits -= 8
            out.append((acc >> nbits) & 0xFF)
    if len(out) < 5:
        raise ValueError("label too short to carry an address")
    return ((0x80 | (out[0] & 0x3F)) << 32) | int.from_bytes(out[1:5], "big")


def name_to_addr(name: str) -> int:
    """``<label>.bait`` (or a plain label) -> address."""
    label = name[:-5] if name.endswith(".bait") else name
    return label_to_addr(label)


def addr_to_name(addr: int) -> str:
    """Reverse lookup is not possible (the digest is not invertible)."""
    raise NotImplementedError(
        "a .bait name is derived from the key, not from the address; "
        f"ask the owner for the label of {format_addr(addr)}"
    )


def is_bait_name(text: str) -> bool:
    return text.endswith(".bait") and label_valid(text[:-5])


__all__ = ["label_from_pub", "label_valid", "label_to_addr", "name_to_addr",
           "is_bait_name", "format_addr", "parse_addr"]
