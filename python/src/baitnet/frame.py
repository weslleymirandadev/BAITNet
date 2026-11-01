"""Ethernet framing for IPv69 (c/src/IPv69/l2.c: build_frame)."""

from __future__ import annotations

from dataclasses import dataclass

from .constants import (
    DEFAULT_HOP_LIMIT, ETHERTYPE_IPV69, ETH_HEADER_LEN, FLAG_NOFRAG,
    HEADER_LEN, NEXT_CONTROL,
)
from .header import IpV69Header

BCAST_MAC = b"\xff" * 6


def build_frame(dst_mac: bytes, src_mac: bytes, src: int, dst: int,
                next_header: int, payload: bytes = b"", *,
                hop_limit: int = DEFAULT_HOP_LIMIT,
                src_port: int = 0, dst_port: int = 0,
                flow_id: int = 1, flags: int = FLAG_NOFRAG,
                sequence: bytes = b"\x00\x00\x00\x00") -> bytes:
    """Assemble eth header + IPv69 header + payload."""
    if len(dst_mac) != 6 or len(src_mac) != 6:
        raise ValueError("MAC addresses are 6 bytes")
    header = IpV69Header(
        payload_len=len(payload),
        flow_id=flow_id,
        next_header=next_header,
        hop_limit=hop_limit,
        flags=flags,
        src_port=src_port,
        dst_port=dst_port,
        sequence=sequence,
        source=src,
        dest=dst,
    )
    eth = bytearray()
    eth += dst_mac
    eth += src_mac
    eth += ETHERTYPE_IPV69.to_bytes(2, "big")
    return bytes(eth) + header.pack() + payload


@dataclass
class Frame:
    eth_dst: bytes
    eth_src: bytes
    ethertype: int
    header: IpV69Header
    payload: bytes

    @property
    def data(self) -> bytes:
        return self.payload

    def is_control(self) -> bool:
        return self.header.next_header == NEXT_CONTROL

    def __str__(self) -> str:
        return (f"{self.eth_src.hex(':')}->{self.eth_dst.hex(':')} "
                f"{self.header}")


def parse_frame(data: bytes) -> Frame:
    """Split a received frame; raises ValueError when it is not IPv69."""
    if len(data) < ETH_HEADER_LEN + HEADER_LEN:
        raise ValueError("short frame")
    ethertype = int.from_bytes(data[12:14], "big")
    if ethertype != ETHERTYPE_IPV69:
        raise ValueError(f"not IPv69 (ethertype {ethertype:#06x})")
    header = IpV69Header.unpack(data[ETH_HEADER_LEN:ETH_HEADER_LEN + HEADER_LEN])
    end = ETH_HEADER_LEN + HEADER_LEN + header.payload_len
    return Frame(
        eth_dst=bytes(data[0:6]),
        eth_src=bytes(data[6:12]),
        ethertype=ethertype,
        header=header,
        payload=bytes(data[ETH_HEADER_LEN + HEADER_LEN:end]),
    )
