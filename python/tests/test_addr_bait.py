"""Addresses and .bait names against vectors produced by the C binary.

The vectors come from `ipv69 addr --bait --key-file srv` on the real
keyring: pub 3198c3c0… -> 83.81.0b.be.6c and label ioaqxptm….
"""

import pytest

from ipv69.addr import (Addr, addr_class, derive_addr, format_addr,
                        parse_addr, parse_addr_port)
from ipv69.bait import (is_bait_name, label_from_pub, label_to_addr,
                        label_valid, name_to_addr)

PUB = bytes.fromhex(
    "3198c3c0ee69051b6217ae50baf0a39ad7e98c70b21e970d740ab51b4204cef1")
ADDR_C = 0x83_81_0B_BE_6C
LABEL = "ioaqxptmw3uodstqdlmfvyeakuvzqwvh"


def test_derive_class_c_vector():
    assert derive_addr(PUB, "C") == ADDR_C
    assert format_addr(ADDR_C) == "83.81.0b.be.6c"


def test_derive_classes_keep_the_prefix():
    for cls, lo, hi in (("A", 0x00, 0x3F), ("B", 0x40, 0x7F),
                        ("C", 0x80, 0xBF), ("D", 0xC0, 0xDF),
                        ("E", 0xE0, 0xFF)):
        first = derive_addr(PUB, cls) >> 32
        assert lo <= first <= hi, (cls, hex(first))


def test_invalid_class():
    with pytest.raises(ValueError):
        derive_addr(PUB, "Z")


def test_bait_label_vector_and_roundtrip():
    assert label_from_pub(PUB) == LABEL
    assert label_valid(LABEL)
    assert label_to_addr(LABEL) == ADDR_C
    assert name_to_addr(LABEL + ".bait") == ADDR_C
    assert is_bait_name(LABEL + ".bait")
    assert not is_bait_name("short.bait")


def test_label_case_insensitive():
    assert label_to_addr(LABEL.upper()) == ADDR_C


def test_addr_class_ranges():
    assert addr_class(0x0000000000) == "A"
    assert addr_class(0x3FFFFFFFFF) == "A"
    assert addr_class(0x4000000000) == "B"
    assert addr_class(0x8000000000) == "C"
    assert addr_class(0xBFFFFFFFFF) == "C"
    assert addr_class(0xC000000000) == "D"
    assert addr_class(0xE000000000) == "E"
    assert addr_class(0xFFFFFFFFFF) == "E"


def test_parse_and_format_roundtrip():
    assert parse_addr("83.81.0b.be.6c") == ADDR_C
    assert str(Addr(ADDR_C)) == "83.81.0b.be.6c"
    assert Addr.from_bytes(ADDR_C.to_bytes(5, "big")).value == ADDR_C
    assert Addr(ADDR_C).classification == "C"
    assert Addr(0xFFFFFFFFFF).is_broadcast


def test_parse_rejects_garbage():
    # dotted hex accepts 1-2 digits per octet, so only real defects are listed
    for bad in ("83.81.0b.be", "83.81.0b.be.gg", "83.81.0b.be.6c.1",
                "83.81.0b.be.100"):
        with pytest.raises(ValueError):
            parse_addr(bad)


def test_addr_port_convention_is_decimal_glued():
    assert parse_addr_port("00.00.00.00.10:16") == (0x10, 16)
    assert parse_addr_port("00.00.00.00.10") == (0x10, None)
