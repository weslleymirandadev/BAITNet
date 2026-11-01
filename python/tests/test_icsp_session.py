"""ICSP session: handshake, key agreement, DATA/SACK, lifecycle, allowlist.

Runs two real endpoint state machines over an in-memory link, so the whole
protocol path is exercised without root or a network interface.
"""

import os
import time

import pytest

from baitnet.lib.crypto import seed_to_pub
from baitnet.icsp.session import ST_ESTABLISHED, ST_SHUTDOWN
from loopback import make_pair, run_in_thread


def _seeds():
    return os.urandom(32), os.urandom(32)


def test_handshake_establishes_matching_keys():
    seed_c, seed_s = _seeds()
    client, server = make_pair(seed_c, seed_s)

    thread, box = run_in_thread(server.assoc.server_accept, [], 5.0)
    client.assoc.client_handshake()
    thread.join(6.0)

    assert "error" not in box, box.get("error")
    assert client.assoc.state == ST_ESTABLISHED
    assert server.assoc.state == ST_ESTABLISHED
    # directional keys: each side sends with the key the other receives with
    assert client.assoc.send_key == server.assoc.recv_key
    assert client.assoc.recv_key == server.assoc.send_key
    assert client.assoc.assoc_id == server.assoc.assoc_id
    assert server.assoc.peer_id == seed_to_pub(seed_c)
    assert client.assoc.peer_id == seed_to_pub(seed_s)


def test_data_is_encrypted_delivered_and_acked():
    seed_c, seed_s = _seeds()
    client, server = make_pair(seed_c, seed_s)

    thread, box = run_in_thread(server.assoc.server_accept, [], 5.0)
    client.assoc.client_handshake()
    thread.join(6.0)
    assert "error" not in box, box.get("error")

    client.assoc.data_send(1, b"ola ipv69")
    events = server.assoc.poll(2.0)
    payloads = [ev[1] for ev in events if ev[0] == "data"]
    assert payloads == [(1, b"ola ipv69")]

    # the server acked it; the client sees the SACK and clears the send queue
    for _ in range(20):
        if client.assoc.all_acked():
            break
        client.assoc.poll(0.2)
    assert client.assoc.all_acked()


def test_multiple_streams_keep_order_and_are_independent():
    seed_c, seed_s = _seeds()
    client, server = make_pair(seed_c, seed_s)
    thread, box = run_in_thread(server.assoc.server_accept, [], 5.0)
    client.assoc.client_handshake()
    thread.join(6.0)
    assert "error" not in box, box.get("error")

    client.assoc.data_send(1, b"a1")
    client.assoc.data_send(2, b"b1")
    client.assoc.data_send(1, b"a2")
    got = []
    for _ in range(3):
        for kind, payload in server.assoc.poll(2.0):
            if kind == "data":
                got.append(payload)
    assert got == [(1, b"a1"), (2, b"b1"), (1, b"a2")]


def test_allowlist_rejects_an_unknown_peer():
    seed_c, seed_s = _seeds()
    client, server = make_pair(seed_c, seed_s)
    stranger = seed_to_pub(os.urandom(32))

    thread, box = run_in_thread(server.assoc.server_accept, [stranger], 3.0)
    with pytest.raises(TimeoutError):
        client.assoc.client_handshake(attempts=2)
    thread.join(5.0)
    assert server.assoc.state != ST_ESTABLISHED


def test_shutdown_is_visible_to_the_peer():
    seed_c, seed_s = _seeds()
    client, server = make_pair(seed_c, seed_s)
    thread, box = run_in_thread(server.assoc.server_accept, [], 5.0)
    client.assoc.client_handshake()
    thread.join(6.0)
    assert "error" not in box, box.get("error")

    client.assoc.shutdown()
    events = server.assoc.poll(2.0)
    assert ("closed", None) in events
    assert server.assoc.state == ST_SHUTDOWN


def test_retransmit_resent_an_unacked_datagram():
    seed_c, seed_s = _seeds()
    client, server = make_pair(seed_c, seed_s)
    thread, box = run_in_thread(server.assoc.server_accept, [], 5.0)
    client.assoc.client_handshake()
    thread.join(6.0)
    assert "error" not in box, box.get("error")

    client.assoc.data_send(1, b"needs an ack")
    assert not client.assoc.all_acked()
    time.sleep(0.05)
    assert client.assoc.data_retransmit(timeout=0.0) == 1


def test_tampered_datagram_is_dropped():
    seed_c, seed_s = _seeds()
    client, server = make_pair(seed_c, seed_s)
    thread, box = run_in_thread(server.assoc.server_accept, [], 5.0)
    client.assoc.client_handshake()
    thread.join(6.0)
    assert "error" not in box, box.get("error")

    # flip a ciphertext byte: the secretbox MAC must reject it
    from baitnet.icsp.framing import chunk_put
    from baitnet.core.constants import CHUNK
    tsn = client.assoc.next_tsn
    clear = tsn.to_bytes(4, "big") + b"\x00\x01" + b"\x00\x00" + b"tampered"
    from baitnet.lib.crypto import seal
    from baitnet.icsp.session import data_nonce
    box_ = bytearray(seal(client.assoc.send_key,
                          data_nonce(client.assoc.assoc_id, tsn), clear))
    box_[-1] ^= 0xFF
    client.assoc._send_chunk(chunk_put(CHUNK.DATA, clear[:8] + bytes(box_)))
    assert server.assoc.poll(1.0) == []
