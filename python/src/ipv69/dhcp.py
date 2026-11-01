"""DHCP69 client (c/tests/af69_raw.c: dhcp_discover / dhcp_client).

Wire (nh=0 control, dst = broadcast):

    DISCOVER [7][mac 6]        (+ [pub 32][sig 64] when signing)
    OFFER    [8][mac 6][addr 5][lease 4]
    REQUEST  [9][mac 6][addr 5] (+ [pub 32][sig 64] when signing)
    ACK     [10][mac 6][addr 5][lease 4]

Every message ends with a 16-byte mac1 tag (Poly1305 keyed by the frame's
destination address, broadcast here) — the server verifies it before doing
any signature work and drops unsigned/mistagged frames silently.
"""

from __future__ import annotations

import time

from . import mac1
from .constants import (BCAST_ADDR, CTRL_DHCP_ACK, CTRL_DHCP_DISCOVER,
                       CTRL_DHCP_OFFER, CTRL_DHCP_REQUEST, MAC1_LEN,
                       NEXT_CONTROL)
from .crypto import sign, verify
from .frame import build_frame, parse_frame
from .l2 import BCAST_MAC, L2

MAC_LEN = 6
ADDR_LEN = 5


def _signed_body(msg: bytearray, seed: bytes | None) -> int:
    """Append [pub 32][sig 64] when signing; returns the signed length."""
    if seed is None:
        return len(msg)
    from .crypto import seed_to_pub
    pub = seed_to_pub(seed)
    body = len(msg)
    msg += pub
    msg += sign(seed, bytes(msg[:body]))
    return body


def _tag(msg: bytearray, dst_addr: int) -> None:
    key = mac1.key_for(dst_addr)
    msg += mac1.compute(key, bytes(msg))


def _msg(ctype: int, mac: bytes, seed: bytes | None = None,
         extra: bytes = b"") -> bytes:
    msg = bytearray([ctype])
    msg += mac
    msg += extra
    _signed_body(msg, seed)          # signature covers [type][mac][extra]
    _tag(msg, BCAST_ADDR)
    return bytes(msg)


def _frame(payload: bytes, my_mac: bytes) -> bytes:
    return build_frame(BCAST_MAC, my_mac, 0, BCAST_ADDR, NEXT_CONTROL,
                       payload, hop_limit=64, src_port=0, dst_port=0)


def _parse_reply(frame_bytes: bytes, expect: int, my_mac: bytes,
                 server_pub: bytes | None):
    """Return (addr, lease) when the frame is `expect` for us, else None."""
    try:
        frame = parse_frame(frame_bytes)
    except ValueError:
        return None
    data = frame.payload
    if len(data) < 1 + MAC_LEN + ADDR_LEN + 4 or data[0] != expect:
        return None
    if data[1:1 + MAC_LEN] != my_mac:
        return None
    if server_pub is not None:
        # [ ... ][pub 32][sig 64]: verify the body before trusting it
        body = len(data) - 96
        if body <= 0 or data[body:body + 32] != server_pub:
            return None
        if not verify(server_pub, bytes(data[body + 32:body + 96]),
                      bytes(data[:body])):
            return None
    addr = int.from_bytes(data[7:12], "big")
    lease = int.from_bytes(data[12:16], "big")
    return addr, lease


def discover(l2: L2, seed: bytes | None = None, *,
             server_pub: bytes | None = None, timeout: float = 3.0,
             attempts: int = 3) -> tuple[int, int] | None:
    """Ask for an address; returns (addr, lease_seconds) or None."""
    for attempt in range(attempts):
        l2.send(_frame(_msg(CTRL_DHCP_DISCOVER, l2.mac, seed), l2.mac))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            raw = l2.recv(max(0.0, deadline - time.monotonic()))
            if raw is None:
                break
            got = _parse_reply(raw, CTRL_DHCP_OFFER, l2.mac, server_pub)
            if got:
                return got
    return None


def request(l2: L2, addr: int, seed: bytes | None = None, *,
            server_pub: bytes | None = None, timeout: float = 3.0) -> tuple[int, int] | None:
    """Confirm the offered address; returns (addr, lease) or None."""
    msg = _msg(CTRL_DHCP_REQUEST, l2.mac, seed, addr.to_bytes(5, "big"))
    l2.send(_frame(msg, l2.mac))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        raw = l2.recv(max(0.0, deadline - time.monotonic()))
        if raw is None:
            break
        got = _parse_reply(raw, CTRL_DHCP_ACK, l2.mac, server_pub)
        if got:
            return got
    return None


def configure(l2: L2, seed: bytes | None = None, *,
              server_pub: bytes | None = None) -> tuple[int, int]:
    """DISCOVER + REQUEST; returns (addr, lease) or raises RuntimeError."""
    offer = discover(l2, seed, server_pub=server_pub)
    if not offer:
        raise RuntimeError("no DHCP69 server answered (run a dhcpd)")
    ack = request(l2, offer[0], seed, server_pub=server_pub)
    if not ack:
        raise RuntimeError(f"lease {offer[0]:010x} was not acknowledged")
    return ack
