"""Raw L2 backend: AF_PACKET on Linux (mirrors c/src/IPv69/l2.c).

A frame is injected/received on the whole Ethernet device with EtherType
0x6969; there is no IP in the path. Root (or CAP_NET_RAW) is required.
"""

from __future__ import annotations

import fcntl
import os
import select
import socket
import struct
from pathlib import Path

from .constants import ETHERTYPE_IPV69

SIOCGIFHWADDR = 0x8927
SIOCGIFINDEX = 0x8933
SOL_PACKET = 263
PACKET_IGNORE_OUTGOING = 23

BCAST_MAC = b"\xff" * 6


def default_ifname() -> str:
    """The interface carrying traffic: default route, else first UP non-lo.

    Android keeps the default route in a policy-routing table, so
    /proc/net/route only shows the connected route there — same fallback as
    l2_default_ifname() in the C tree.
    """
    fallback = ""
    try:
        lines = Path("/proc/net/route").read_text().splitlines()[1:]
    except OSError:
        raise RuntimeError("cannot read /proc/net/route to resolve 'auto'")
    for line in lines:
        cols = line.split()
        if len(cols) < 4:
            continue
        iface, dest, _gw, flags = cols[0], int(cols[1], 16), cols[2], int(cols[3], 16)
        if not flags & 0x1:          # RTF_UP
            continue
        if dest == 0:
            return iface
        if not fallback and iface != "lo":
            fallback = iface
    if fallback:
        return fallback
    raise RuntimeError("no interface found for 'auto'")


def iface_mac(ifname: str) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tmp:
        ifreq = struct.pack("256s", ifname.encode()[:15])
        res = fcntl.ioctl(tmp.fileno(), SIOCGIFHWADDR, ifreq)
    return res[18:24]


class L2:
    """One AF_PACKET socket bound to an interface."""

    def __init__(self, ifname: str = "auto", *, ignore_outgoing: bool = False):
        self.requested = ifname
        self.ifname = default_ifname() if ifname in ("auto", "", None) else ifname
        self.mac = iface_mac(self.ifname)
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                  socket.htons(ETHERTYPE_IPV69))
        self.sock.bind((self.ifname, ETHERTYPE_IPV69))
        if ignore_outgoing:
            try:
                self.sock.setsockopt(SOL_PACKET, PACKET_IGNORE_OUTGOING, 1)
            except OSError:
                pass

    # --- io --------------------------------------------------------------
    def send(self, frame: bytes, dst_mac: bytes = BCAST_MAC) -> int:
        return self.sock.send(frame)

    def recv(self, timeout: float | None = 2.0) -> bytes | None:
        """One frame (bytes) or None on timeout."""
        if timeout is None:
            return self.sock.recv(65535)
        ready, _, _ = select.select([self.sock], [], [], timeout)
        if not ready:
            return None
        return self.sock.recv(65535)

    def close(self) -> None:
        self.sock.close()

    def __enter__(self) -> "L2":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"L2({self.ifname}, mac={self.mac.hex(':')})"


def open_l2(ifname: str = "auto", **kw) -> L2:
    return L2(ifname, **kw)


def is_root() -> bool:
    return os.geteuid() == 0
