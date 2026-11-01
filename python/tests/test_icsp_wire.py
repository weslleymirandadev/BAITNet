"""Wire constants and checksums must match the C implementation exactly."""

from baitnet.core.crc import crc32c
from baitnet.icsp.framing import IcspHeader, build_pkt, check_pkt, chunk_put, iter_chunks
from baitnet.core.constants import CHUNK, ICSP_HEADER_LEN


def test_crc32c_known_value():
    # same value the C unit test (c/tests/icsp_crc_test.c) asserts
    assert crc32c(b"abc") == 0x364B3FB7


def test_crc32c_empty():
    assert crc32c(b"") == 0x00000000


def _data_chunk():
    # DATA chunk: [type][flags][len] + tsn(4) + stream(2) + seq(2) + payload
    body = (7).to_bytes(4, "big") + (0).to_bytes(2, "big") + (0).to_bytes(2, "big") + b"abc"
    return chunk_put(CHUNK.DATA, body)


def test_packet_vector_matches_c():
    pkt = build_pkt(8080, 20000, 0x0A0B0C0D, _data_chunk())
    assert pkt.hex() == "1f904e2001000a0b0c0d750e0000000b0000000700000000616263"


def test_crc_is_over_the_whole_payload_with_field_zeroed():
    pkt = build_pkt(8080, 20000, 0x0A0B0C0D, _data_chunk())
    assert check_pkt(pkt)
    # protecting src_port (the original bug started summing at byte 2)
    corrupted = bytes([pkt[0] ^ 0x01]) + pkt[1:]
    assert not check_pkt(corrupted)


def test_every_single_byte_corruption_is_rejected():
    pkt = build_pkt(8080, 20000, 0x0A0B0C0D, _data_chunk())
    for i in range(len(pkt)):
        bad = bytearray(pkt)
        bad[i] ^= 0x01
        assert not check_pkt(bytes(bad)), f"byte {i} corruption accepted"


def test_short_packet_rejected():
    assert not check_pkt(b"\x01\x02\x03")


def test_header_roundtrip_and_chunk_iter():
    pkt = build_pkt(1, 2, 3, _data_chunk())
    hdr = IcspHeader.unpack(pkt)
    assert (hdr.src_port, hdr.dst_port, hdr.assoc_id) == (1, 2, 3)
    chunks = list(iter_chunks(pkt))
    assert len(chunks) == 1
    ctype, flags, data = chunks[0]
    assert ctype == CHUNK.DATA and flags == 0 and data.endswith(b"abc")
    assert len(pkt) == ICSP_HEADER_LEN + 4 + len(data)
