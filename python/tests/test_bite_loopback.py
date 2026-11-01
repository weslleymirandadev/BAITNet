"""Full stack over an in-memory link: ICSP -> bTLS -> BITE documents.

The client dials a ``.bait`` label, the server presents its Ed25519 key as
the certificate, and the label check is what authenticates it — no CA.
"""

import os

import pytest

from baitnet.bite.bite import (BiteClient, BiteServer, mime_of, parse_response,
                               resolve_document, serve)
from baitnet.bite.names import label_from_pub
from baitnet.lib.crypto import seed_to_pub
from loopback import make_pair, run_in_thread

PORT = 8080


@pytest.fixture
def root(tmp_path):
    (tmp_path / "index.html").write_text("<h1>Ola, Mundo!</h1>\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "a.txt").write_text("texto\n")
    (tmp_path / "big.bin").write_bytes(os.urandom(5000))
    return tmp_path


def _server_thread(server, root, expect_one=True):
    def run():
        server.assoc.server_accept([], 5.0)
        server.handshake(5.0)
        return server.serve_one(5.0)

    return run_in_thread(run)


def test_fetch_returns_the_document(root):
    seed_c, seed_s = os.urandom(32), os.urandom(32)
    client, server = make_pair(seed_c, seed_s, port=PORT)
    srv = BiteServer(server.assoc, root)
    thread, box = _server_thread(srv, root)

    label = label_from_pub(seed_to_pub(seed_s))
    status, headers, body = BiteClient(client.assoc, label).fetch("/index.html")
    thread.join(6.0)

    assert "error" not in box, box.get("error")
    assert status == 200
    assert headers["content-type"] == "text/html"
    assert headers["server"] == "BITE/1.0"
    assert body == b"<h1>Ola, Mundo!</h1>\n"
    assert box["value"] == (200, "/index.html")


def test_fetch_404_for_a_missing_document(root):
    seed_c, seed_s = os.urandom(32), os.urandom(32)
    client, server = make_pair(seed_c, seed_s, port=PORT)
    srv = BiteServer(server.assoc, root)
    thread, box = _server_thread(srv, root)

    label = label_from_pub(seed_to_pub(seed_s))
    status, _headers, body = BiteClient(client.assoc, label).fetch("/nope.html")
    thread.join(6.0)
    assert status == 404 and body == b""
    assert box["value"] == (404, "/nope.html")


def test_fetch_rejects_a_wrong_bait_label(root):
    seed_c, seed_s = os.urandom(32), os.urandom(32)
    client, server = make_pair(seed_c, seed_s, port=PORT)
    srv = BiteServer(server.assoc, root)
    thread, _box = _server_thread(srv, root)

    wrong = label_from_pub(seed_to_pub(os.urandom(32)))
    with pytest.raises(ValueError, match="does not match"):
        BiteClient(client.assoc, wrong).fetch("/index.html")
    thread.join(6.0)


def test_large_document_is_fragmented_and_reassembled(root):
    seed_c, seed_s = os.urandom(32), os.urandom(32)
    client, server = make_pair(seed_c, seed_s, port=PORT)
    srv = BiteServer(server.assoc, root)
    thread, box = _server_thread(srv, root)

    label = label_from_pub(seed_to_pub(seed_s))
    status, _headers, body = BiteClient(client.assoc, label).fetch("/big.bin")
    thread.join(6.0)
    assert "error" not in box, box.get("error")
    assert status == 200
    assert len(body) == 5000
    assert body == (root / "big.bin").read_bytes()


def test_head_returns_headers_without_a_body(root):
    resp = serve(root, "HEAD", "/index.html")
    head, _, body = resp.partition(b"\r\n\r\n")
    assert head.startswith(b"BITE/1.0 200 OK")
    assert b"Content-Length: 21" in head
    assert body == b""


def test_unsupported_method_is_405(root):
    status, headers, body = parse_response(serve(root, "POST", "/index.html"))
    assert status == 405
    assert headers["allow"] == "BITE, GET, HEAD"
    assert body == b""


def test_traversal_never_escapes_the_root(root):
    status, _h, _b = parse_response(serve(root, "GET", "/../etc/passwd"))
    assert status in (400, 404)
    with pytest.raises(ValueError):
        resolve_document(root, "/../etc/passwd")
    # the server answers 400 for a malformed target, not a file
    assert parse_response(serve(root, "GET", "/%2e%2e/x"))[0] == 404


def test_mime_lookup():
    assert mime_of("a.html") == "text/html"
    assert mime_of("a.bin") == "application/octet-stream"
