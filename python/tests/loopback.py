"""Helpers for driving two ICSP endpoints in-process (no root, no NIC)."""

from __future__ import annotations

import threading
from dataclasses import dataclass

from baitnet.core.addr import derive_addr
from baitnet.lib.crypto import seed_to_pub
from baitnet.icsp.session import Assoc
from baitnet.core.transport import LoopTransport


@dataclass
class Peer:
    assoc: Assoc
    seed: bytes

    @property
    def pub(self) -> bytes:
        return seed_to_pub(self.seed)

    @property
    def addr(self) -> int:
        return derive_addr(self.pub)


def make_pair(seed_client: bytes, seed_server: bytes, port: int = 6969,
              client_port: int = 50001) -> tuple[Peer, Peer]:
    """(client, server) over an in-memory link with distinct MACs."""
    tc, ts = LoopTransport.pair()
    client = Peer(Assoc(transport=tc, seed=seed_client), seed_client)
    server = Peer(Assoc(transport=ts, seed=seed_server), seed_server)
    client.assoc.src_addr = client.addr
    client.assoc.src_port = client_port
    client.assoc.dst_addr = server.addr
    client.assoc.dst_port = port
    server.assoc.src_addr = server.addr
    server.assoc.src_port = port
    return client, server


def run_in_thread(target, *args, **kwargs) -> tuple[threading.Thread, dict]:
    """Run `target(*args, **kwargs)` on a thread, keeping its result/error."""
    box: dict = {}

    def runner():
        try:
            box["value"] = target(*args, **kwargs)
        except BaseException as exc:      # noqa: BLE001 - reported to the test
            box["error"] = exc

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    return thread, box
