"""mac1 and the DHCP69 message framing (no socket involved)."""

from ipv69 import mac1
from ipv69.constants import BCAST_ADDR, CTRL_DHCP_DISCOVER, CTRL_DHCP_OFFER
from ipv69.crypto import seed_to_pub
from ipv69.dhcp import _frame, _msg, _parse_reply
from ipv69.frame import parse_frame
from ipv69.keyring import derive_key  # noqa: F401  (documents the KDF source)

MAC = bytes.fromhex("94de80f5483b")


def test_poly1305_rfc8439_vector():
    """The published Poly1305 test vector, so the primitive itself is pinned."""
    from ipv69.crypto import poly1305
    key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
    msg = b"Cryptographic Forum Research Group"
    assert poly1305(msg, key).hex() == "a8061dc1305136c6c22b8baf0c0127a9"


def test_mac1_key_is_bound_to_the_destination():
    a = mac1.key_for(0x83_81_0B_BE_6C)
    b = mac1.key_for(0x83_81_0B_BE_6D)
    assert len(a) == 32 and a != b


def test_mac1_compute_and_verify():
    key = mac1.key_for(BCAST_ADDR)
    msg = b"handshake bytes"
    tag = mac1.compute(key, msg)
    assert len(tag) == 16
    assert mac1.verify(key, msg, tag)
    assert not mac1.verify(key, msg + b"!", tag)
    assert not mac1.verify(mac1.key_for(1), msg, tag)


def test_discover_message_is_tagged():
    msg = _msg(CTRL_DHCP_DISCOVER, MAC)
    payload, tag = msg[:-16], msg[-16:]
    assert msg[0] == CTRL_DHCP_DISCOVER
    assert msg[1:7] == MAC
    assert mac1.verify(mac1.key_for(BCAST_ADDR), payload, tag)
    # 1 control + 6 mac + 16 mac1 (unsigned)
    assert len(msg) == 1 + 6 + 16


def test_signed_discover_embeds_pub_and_signature():
    from ipv69.crypto import verify
    seed = bytes(range(32))
    msg = _msg(CTRL_DHCP_DISCOVER, MAC, seed)
    body = len(msg) - 16 - 96
    pub = msg[body:body + 32]
    sig = msg[body + 32:body + 96]
    assert pub == seed_to_pub(seed)
    assert verify(pub, sig, msg[:body])
    assert mac1.verify(mac1.key_for(BCAST_ADDR), msg[:-16], msg[-16:])


def test_frame_wraps_the_payload_with_ipv69_header():
    payload = _msg(CTRL_DHCP_DISCOVER, MAC)
    frame = parse_frame(_frame(payload, MAC))
    assert frame.eth_src == MAC
    assert frame.header.dest == BCAST_ADDR
    assert frame.header.source == 0
    assert frame.payload == payload


def test_parse_reply_extracts_offer():
    addr, lease = 0x0000000000000010, 3600
    payload = bytes([CTRL_DHCP_OFFER]) + MAC + addr.to_bytes(5, "big") + lease.to_bytes(4, "big")
    frame = _frame(payload, MAC)
    assert _parse_reply(frame, CTRL_DHCP_OFFER, MAC, None) == (addr, lease)
    # a different MAC is not ours
    other = bytes.fromhex("001122334455")
    assert _parse_reply(frame, CTRL_DHCP_OFFER, other, None) is None
    # the wrong control code is ignored
    assert _parse_reply(frame, CTRL_DHCP_DISCOVER, MAC, None) is None
