"""Transports the ICSP session can run on.

``L2Transport`` puts frames on a real interface (AF_PACKET). ``LoopTransport``
connects two in-process ends over queues, which is how the tests exercise a
whole handshake/data exchange without root or a NIC.
"""

from __future__ import annotations

import queue
from typing import Protocol

from .l2 import L2


class Transport(Protocol):
    mac: bytes

    def send(self, frame: bytes) -> None: ...
    def recv(self, timeout: float) -> bytes | None: ...
    def close(self) -> None: ...


class L2Transport:
    """Raw Ethernet frames on a real interface."""

    def __init__(self, l2: L2):
        self.l2 = l2
        self.mac = l2.mac

    def send(self, frame: bytes) -> None:
        self.l2.send(frame)

    def recv(self, timeout: float) -> bytes | None:
        return self.l2.recv(timeout)

    def close(self) -> None:
        self.l2.close()


class LoopTransport:
    """One end of an in-memory link; both ends created by :meth:`pair`."""

    def __init__(self, mac: bytes, inbox: "queue.Queue[bytes]",
                 outbox: "queue.Queue[bytes]"):
        self.mac = mac
        self._in = inbox
        self._out = outbox
        self.sent: list[bytes] = []
        self.closed = False

    @classmethod
    def pair(cls, mac_a: bytes = b"\x02\x00\x00\x00\x00\x01",
             mac_b: bytes = b"\x02\x00\x00\x00\x00\x02") -> tuple["LoopTransport", "LoopTransport"]:
        qa: queue.Queue[bytes] = queue.Queue()
        qb: queue.Queue[bytes] = queue.Queue()
        return cls(mac_a, qa, qb), cls(mac_b, qb, qa)

    def send(self, frame: bytes) -> None:
        self.sent.append(frame)
        self._out.put(frame)

    def recv(self, timeout: float) -> bytes | None:
        try:
            return self._in.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self) -> None:
        self.closed = True
