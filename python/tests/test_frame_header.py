"""Frame/header packing: the C wire layout, byte for byte."""

from ipv69.addr import format_addr
from ipv69.constants import (ETHERTYPE_IPV69, FLAG_NOFRAG, HEADER_LEN,
                             NEXT_DGRAM, NEXT_STREAM)
from ipv69.frame import BCAST_MAC, build_frame, parse_frame
from ipv69.header import IpV69Header

SRC = 0x83_81_0B_BE_6C
DST = 0x00_00_00_00_10
MAC_A = bytes.fromhex("94de80f5483b")
MAC_B = bytes.fromhex("0008229c03fc")


def test_frame_layout():
    payload = b"hello"
    frame = build_frame(BCAST_MAC, MAC_A, SRC, DST, NEXT_DGRAM, payload,
                        src_port=7, dst_port=16)
    assert len(frame) == 14 + HEADER_LEN + len(payload)
    assert frame[0:6] == BCAST_MAC
    assert frame[6:12] == MAC_A
    assert int.from_bytes(frame[12:14], "big") == ETHERTYPE_IPV69
    # ver_traffic = (6 << 4) | 9
    assert frame[14] == (6 << 4) | 9
    assert int.from_bytes(frame[16:18], "big") == len(payload)   # payload_len
    assert frame[20] == NEXT_DGRAM                                # next_header
    assert frame[21] == 64                                        # hop_limit
    assert frame[22] == FLAG_NOFRAG
    assert int.from_bytes(frame[24:26], "big") == 7               # src_port
    assert int.from_bytes(frame[26:28], "big") == 16              # dst_port
    assert int.from_bytes(frame[32:37], "big") == SRC             # source
    assert int.from_bytes(frame[39:44], "big") == DST             # dest
    assert frame[-len(payload):] == payload


def test_parse_roundtrip():
    frame = build_frame(MAC_B, MAC_A, SRC, DST, NEXT_STREAM, b"data",
                        hop_limit=32, src_port=1, dst_port=2)
    got = parse_frame(frame)
    assert got.eth_dst == MAC_B and got.eth_src == MAC_A
    assert got.header.next_header == NEXT_STREAM
    assert got.header.hop_limit == 32
    assert got.header.source == SRC and got.header.dest == DST
    assert got.header.src_port == 1 and got.header.dst_port == 2
    assert got.payload == b"data"
    assert got.header.version == 6
    assert str(got).startswith(MAC_A.hex(":"))


def test_header_offsets_and_roundtrip():
    header = IpV69Header(payload_len=3, src_port=0x1234, dst_port=0x5678,
                         source=SRC, dest=DST, next_header=NEXT_DGRAM)
    raw = header.pack()
    assert len(raw) == HEADER_LEN
    assert raw[10:12] == b"\x12\x34" and raw[12:14] == b"\x56\x78"
    back = IpV69Header.unpack(raw)
    assert (back.source, back.dest, back.src_port, back.dst_port) == (SRC, DST, 0x1234, 0x5678)
    assert format_addr(back.source) == "83.81.0b.be.6c"


def test_parse_rejects_non_ipv69():
    bogus = bytearray(60)
    bogus[12:14] = (0x0800).to_bytes(2, "big")
    try:
        parse_frame(bytes(bogus))
    except ValueError as exc:
        assert "not IPv69" in str(exc)
    else:
        raise AssertionError("expected ValueError")
