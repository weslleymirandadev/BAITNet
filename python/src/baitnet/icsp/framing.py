"""ICSP framing: 12-byte header + chunks, CRC32c over the whole payload.

Wire (c/include/ICSP/icsp.h)::

    src_port BE16 | dst_port BE16 | ver | flags | assoc_id BE32 | crc BE16

The CRC covers the whole payload **with the CRC field zeroed** while
summing (the C builder does exactly that, and the receiver checks it), so
``build_pkt``/``check_pkt`` here reproduce the same vectors.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.constants import CHUNK, ICSP_CHUNK_HDR, ICSP_HEADER_LEN, ICSP_MAX_PAYLOAD, ICSP_VERSION
from ..core.crc import crc32c


@dataclass
class IcspHeader:
    src_port: int
    dst_port: int
    assoc_id: int
    ver: int = ICSP_VERSION
    flags: int = 0
    crc: int = 0

    def pack(self, chunk: bytes, *, with_crc: bool = True) -> bytes:
        out = bytearray(ICSP_HEADER_LEN + len(chunk))
        out[0:2] = self.src_port.to_bytes(2, "big")
        out[2:4] = self.dst_port.to_bytes(2, "big")
        out[4] = self.ver
        out[5] = self.flags
        out[6:10] = self.assoc_id.to_bytes(4, "big")
        out[10:12] = b"\x00\x00"          # zero while summing
        out[ICSP_HEADER_LEN:] = chunk
        if with_crc:
            self.crc = crc32c(bytes(out)) & 0xFFFF
            out[10:12] = self.crc.to_bytes(2, "big")
        return bytes(out)

    @classmethod
    def unpack(cls, pkt: bytes) -> "IcspHeader":
        if len(pkt) < ICSP_HEADER_LEN:
            raise ValueError("short ICSP packet")
        return cls(
            src_port=int.from_bytes(pkt[0:2], "big"),
            dst_port=int.from_bytes(pkt[2:4], "big"),
            assoc_id=int.from_bytes(pkt[6:10], "big"),
            ver=pkt[4],
            flags=pkt[5],
            crc=int.from_bytes(pkt[10:12], "big"),
        )


def chunk_put(ctype: int, data: bytes = b"", flags: int = 0) -> bytes:
    """``[type][flags][len BE16][data]`` (icsp_chunk_put)."""
    if len(data) > 0xFFFF:
        raise ValueError("chunk too large")
    return bytes([ctype & 0xFF, flags & 0xFF]) + len(data).to_bytes(2, "big") + data


def build_pkt(src_port: int, dst_port: int, assoc_id: int, chunk: bytes) -> bytes:
    if len(chunk) + ICSP_HEADER_LEN > ICSP_MAX_PAYLOAD:
        raise ValueError("ICSP packet too large")
    return IcspHeader(src_port, dst_port, assoc_id).pack(chunk)


def check_pkt(pkt: bytes) -> bool:
    """True when the CRC matches (recomputed with the field zeroed)."""
    if not ICSP_HEADER_LEN <= len(pkt) <= ICSP_MAX_PAYLOAD:
        return False
    stored = int.from_bytes(pkt[10:12], "big")
    body = bytearray(pkt)
    body[10:12] = b"\x00\x00"
    return (crc32c(bytes(body)) & 0xFFFF) == stored


# --- chunk helpers over a received payload ------------------------------
def iter_chunks(payload: bytes, offset: int = ICSP_HEADER_LEN):
    """Yield ``(type, flags, data)`` for each chunk in an ICSP payload."""
    pos = offset
    while pos + ICSP_CHUNK_HDR <= len(payload):
        ctype = payload[pos]
        flags = payload[pos + 1]
        length = int.from_bytes(payload[pos + 2:pos + 4], "big")
        start = pos + ICSP_CHUNK_HDR
        end = start + length
        if end > len(payload):
            return
        yield ctype, flags, payload[start:end]
        pos = end


__all__ = ["IcspHeader", "chunk_put", "build_pkt", "check_pkt", "iter_chunks",
           "CHUNK", "ICSP_HEADER_LEN", "ICSP_CHUNK_HDR"]
