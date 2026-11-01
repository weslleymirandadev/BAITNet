"""The 32-byte IPv69 header (see c/include/IPv69/header.h).

Field layout is wire order, no padding:

    0  ver_traffic (version << 4 | traffic class)   1  dscp_ecn
    2  payload_len BE16                             4  flow_id BE16
    6  next_header                                  7  hop_limit
    8  flags                                        9  reserved
   10  src_port BE16                               12  dst_port BE16
   14  sequence[4]                                 18  source[5]
   23  source_res[2]                               25  dest[5]
   30  dest_res[2]
"""

from __future__ import annotations

from dataclasses import dataclass

from .constants import (
    DEFAULT_HOP_LIMIT, FLAG_NOFRAG, HEADER_LEN, IPV69_TRAFFIC_CLASS,
    IPV69_VERSION,
)


@dataclass
class IpV69Header:
    payload_len: int = 0
    flow_id: int = 1
    next_header: int = 0
    hop_limit: int = DEFAULT_HOP_LIMIT
    flags: int = FLAG_NOFRAG
    reserved: int = 0
    src_port: int = 0
    dst_port: int = 0
    sequence: bytes = b"\x00\x00\x00\x00"
    source: int = 0
    dest: int = 0
    source_res: bytes = b"\x00\x00"
    dest_res: bytes = b"\x00\x00"
    _version: int = IPV69_VERSION

    # --- wire -----------------------------------------------------------
    def pack(self) -> bytes:
        if len(self.sequence) != 4:
            raise ValueError("sequence must be 4 bytes")
        out = bytearray(HEADER_LEN)
        out[0] = (IPV69_VERSION << 4) | (IPV69_TRAFFIC_CLASS & 0x0F)
        out[1] = 0
        out[2:4] = self.payload_len.to_bytes(2, "big")
        out[4:6] = self.flow_id.to_bytes(2, "big")
        out[6] = self.next_header
        out[7] = self.hop_limit
        out[8] = self.flags
        out[9] = self.reserved
        out[10:12] = self.src_port.to_bytes(2, "big")
        out[12:14] = self.dst_port.to_bytes(2, "big")
        out[14:18] = self.sequence
        out[18:23] = self.source.to_bytes(5, "big")
        out[23:25] = self.source_res
        out[25:30] = self.dest.to_bytes(5, "big")
        out[30:32] = self.dest_res
        return bytes(out)

    @classmethod
    def unpack(cls, data: bytes) -> "IpV69Header":
        if len(data) < HEADER_LEN:
            raise ValueError("short IPv69 header")
        return cls(
            payload_len=int.from_bytes(data[2:4], "big"),
            flow_id=int.from_bytes(data[4:6], "big"),
            next_header=data[6],
            hop_limit=data[7],
            flags=data[8],
            reserved=data[9],
            src_port=int.from_bytes(data[10:12], "big"),
            dst_port=int.from_bytes(data[12:14], "big"),
            sequence=bytes(data[14:18]),
            source=int.from_bytes(data[18:23], "big"),
            source_res=bytes(data[23:25]),
            dest=int.from_bytes(data[25:30], "big"),
            dest_res=bytes(data[30:32]),
            _version=data[0] >> 4,
        )

    @property
    def version(self) -> int:
        """Version nibble as it was decoded from the wire."""
        return self._version

    def __str__(self) -> str:
        from .addr import format_addr
        return (f"nh={self.next_header} hop={self.hop_limit} "
                f"{format_addr(self.source)}->{format_addr(self.dest)} "
                f"ports={self.src_port}/{self.dst_port} len={self.payload_len}")
