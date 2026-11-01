"""40-bit IPv69 addresses: parse/format, classes, derivation from a key.

The address is an integer 0..2**40-1 rendered as five dotted hex octets
(``83.81.0b.be.6c``). The first octet carries the IPv4-style class:

    00-3f A private local    40-7f B private extended
    80-bf C public            c0-df D multicast
    e0-ff E reserved (ff.ff.ff.ff.ff = broadcast)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .constants import (ADDR_SPACE, BCAST_ADDR, ED25519_PUB_LEN)

CLASS_A, CLASS_B, CLASS_C, CLASS_D, CLASS_E = "A", "B", "C", "D", "E"


def addr_class(value: int) -> str:
    """IPv4-style class of the first octet (parse.c: ipv69_addr_class)."""
    b = (value >> 32) & 0xFF
    if b & 0xC0 == 0x00:
        return CLASS_A
    if b & 0xC0 == 0x40:
        return CLASS_B
    if b & 0xC0 == 0x80:
        return CLASS_C
    if b & 0xE0 == 0xC0:
        return CLASS_D
    return CLASS_E


def derive_addr(pub: bytes, cls: str = CLASS_C) -> int:
    """Identity-derived address: class byte + four digest bytes.

    Mirrors parse.c: ipv69_addr_derive — the first octet keeps the class
    prefix and takes the low bits of SHA-512(pub)[0].
    """
    if len(pub) != ED25519_PUB_LEN:
        raise ValueError(f"public key must be {ED25519_PUB_LEN} bytes")
    d = hashlib.sha512(pub).digest()
    if cls == CLASS_A:
        first = 0x00 | (d[0] & 0x3F)
    elif cls == CLASS_B:
        first = 0x40 | (d[0] & 0x3F)
    elif cls == CLASS_D:
        first = 0xC0 | (d[0] & 0x1F)
    elif cls == CLASS_E:
        first = 0xE0 | (d[0] & 0x1F)
    elif cls == CLASS_C:
        first = 0x80 | (d[0] & 0x3F)
    else:
        raise ValueError(f"invalid class {cls!r} (A-E)")
    return (first << 32) | int.from_bytes(d[1:5], "big")


def format_addr(value: int) -> str:
    return ".".join(f"{(value >> shift) & 0xFF:02x}" for shift in (32, 24, 16, 8, 0))


def parse_addr(text: str) -> int:
    parts = text.strip().split(".")
    if len(parts) != 5:
        raise ValueError(f"invalid IPv69 address {text!r} (needs 5 octets)")
    value = 0
    for part in parts:
        if not 1 <= len(part) <= 2:
            raise ValueError(f"invalid octet {part!r} in {text!r}")
        octet = int(part, 16)
        if not 0 <= octet <= 0xFF:
            raise ValueError(f"octet out of range in {text!r}")
        value = (value << 8) | octet
    return value


@dataclass(frozen=True, order=True)
class Addr:
    """A 40-bit address with helpers."""

    value: int

    def __post_init__(self) -> None:
        if not 0 <= self.value < ADDR_SPACE:
            raise ValueError(f"address out of range: {self.value:#x}")

    # --- construction ---------------------------------------------------
    @classmethod
    def parse(cls, text: str) -> "Addr":
        return cls(parse_addr(text))

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Addr":
        if len(raw) != 5:
            raise ValueError("an IPv69 address is 5 bytes")
        return cls(int.from_bytes(raw, "big"))

    @classmethod
    def from_pub(cls, pub: bytes, cls_name: str = CLASS_C) -> "Addr":
        return cls(derive_addr(pub, cls_name))

    # --- conversion -----------------------------------------------------
    def to_bytes(self) -> bytes:
        return self.value.to_bytes(5, "big")

    def __str__(self) -> str:
        return format_addr(self.value)

    def __int__(self) -> int:
        return self.value

    @property
    def classification(self) -> str:
        return addr_class(self.value)

    @property
    def is_broadcast(self) -> bool:
        return self.value == BCAST_ADDR

    @property
    def fmt_port(self) -> str:
        return f"{self}"


def parse_addr_port(text: str, default_port: int | None = None) -> tuple[int, int | None]:
    """``addr[:port]`` — the port is decimal and glued to the address."""
    if ":" in text:
        host, _, port = text.rpartition(":")
        return parse_addr(host), int(port, 10)
    return parse_addr(text), default_port
