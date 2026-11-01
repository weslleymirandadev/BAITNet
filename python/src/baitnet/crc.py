"""CRC32c (Castagnoli) — the checksum ICSP puts over its whole payload."""

from __future__ import annotations

_POLY = 0x82F63B78  # reflected Castagnoli polynomial
_TABLE: list[int] = []


def _table() -> list[int]:
    if _TABLE:
        return _TABLE
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ _POLY if crc & 1 else crc >> 1
        _TABLE.append(crc)
    return _TABLE


def crc32c(data: bytes, crc: int = 0xFFFFFFFF) -> int:
    """CRC32c of ``data`` (same value as icsp_crc32c in the C tree)."""
    table = _table()
    for byte in data:
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF
