"""A full-size bTLS record must fit ONE ICSP DATA message.

This is the invariant that the C tree violated: BTLS_MAX_PAYLOAD was 1360,
so a record was 1397 B, the ICSP DATA needed 12+4+8+32+1397 bytes and the
sender overflowed its `box[]` (stack smashing) instead of fitting.
"""

from baitnet.bite.btls import MAX_PAYLOAD
from baitnet.core.constants import ICSP_MAX_PAYLOAD


def test_max_record_fits_one_icsp_datagram():
    record = 3 + 32 + 2 + MAX_PAYLOAD          # rec hdr + secretbox + type/flags
    packet = 12 + 4 + 8 + 32 + 8 + record      # ICSP hdr + chunk + clear hdr + box
    assert packet <= ICSP_MAX_PAYLOAD, (
        f"record {record}B gives a {packet}B ICSP packet (limit {ICSP_MAX_PAYLOAD}B)")


def test_a_1300_byte_message_is_fragmented():
    import os

    from baitnet.bite.btls import Btls, SERVER
    t = Btls(SERVER, os.urandom(32))
    t.state = "done"
    t.send_key = b"k" * 32
    t.recv_key = b"k" * 32
    frags = t.send_app(b"x" * (MAX_PAYLOAD * 2 + 10))
    assert len(frags) == 3
    for frag in frags:
        packet = 12 + 4 + 8 + 32 + 8 + len(frag)
        assert packet <= ICSP_MAX_PAYLOAD
