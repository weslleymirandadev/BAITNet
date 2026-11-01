"""bTLS — the BITE security layer (c/src/BITE/btls.c, docs/btls-spec.md).

TLS 1.3-flavored: X25519 ECDHE, Ed25519 identity as the certificate, an
HMAC-SHA512 key schedule over the transcript and XSalsa20-Poly1305 records.
The client that dialed ``name.bait`` checks ``base32(SHA-512(cert)[0..19])``
against the label, so the name IS the pin (no CA, no TOFU).

Records:

    [type 1][len 2][box]      box = 32-byte secretbox blob of the inner data

    inner (handshake)  = [HANDSHAKE][frame]      frame = [type][len 2][body]
    inner (application) = [APPLICATION][flags][data]

Key schedule::

    prk        = HMAC("btls-v1", X25519(eph, peer_eph))
    key(label) = HMAC(prk, label || transcript || 0x01)[:32]
    epoch 1    : "btls-hs-c2s"/"btls-hs-s2c"
    finished   : "btls-fin-c"/"btls-fin-s"
    epoch 2    : "btls-app-c2s"/"btls-app-s2c"
    nonce      = seq (8B BE) || 16 zero bytes
"""

from __future__ import annotations

import os

from .names import label_from_pub, label_valid
from ..lib.crypto import (hmac_sha512, kdf, open_, seal, seed_to_pub, sha512,
                     sign, verify, x25519, x25519_base)

RT_HANDSHAKE = 0
RT_APPLICATION = 1
RT_ALERT = 2

HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_CERTIFICATE = 11
HS_CERTIFICATE_VERIFY = 15
HS_FINISHED = 20

MAX_REC = 1400
MAX_PAYLOAD = 1290   # icsp DATA fits 1336B of record: 1400-12-4-8-32-8
MAX_MSG = 256 * 1024
FRAG_MORE = 0x01

CLIENT = 0
SERVER = 1

ST_INIT = "init"
ST_CH_SENT = "client-hello-sent"
ST_HS = "handshake"
ST_WAIT_FIN = "wait-finished"
ST_DONE = "done"

CERT_CTX = b"btls/1.0-cert-verify"


def _rec_nonce(seq: int) -> bytes:
    return seq.to_bytes(8, "big") + b"\x00" * 16


def _hs_frame(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + len(body).to_bytes(2, "big") + body


class Btls:
    """One bTLS session (client or server)."""

    def __init__(self, role: int, seed: bytes, expect_label: str | None = None):
        if role not in (CLIENT, SERVER):
            raise ValueError("role must be CLIENT or SERVER")
        self.role = role
        self.seed = seed
        self.pub = seed_to_pub(seed) if seed else b""
        self.expect_label = (expect_label or "").lower()
        if self.expect_label and not label_valid(self.expect_label):
            raise ValueError(f"invalid .bait label: {expect_label}")
        self.state = ST_INIT
        self.epoch = 0
        self.want_hs = 0
        self.random = os.urandom(32)
        self.eph_priv = os.urandom(32)
        self.eph_pub = x25519_base(self.eph_priv)
        self.peer_eph = b""
        self.cert_pub = b""
        self.transcript = b""
        self.prk = b""
        self.send_key = b""
        self.recv_key = b""
        self.send_seq = 0
        self.recv_seq = 0
        self._rx_buf = bytearray()
        self.error = ""

    # --- transcript / keys ---------------------------------------------
    def _th(self, frame: bytes) -> None:
        self.transcript += frame

    def _cert_digest(self) -> bytes:
        return sha512(CERT_CTX + self.transcript)

    def _derive(self, label: bytes) -> bytes:
        return kdf(self.prk, label, self.transcript)

    def _ecdhe(self) -> None:
        if not self.peer_eph:
            raise ValueError("bTLS: peer ephemeral key is missing")
        self.prk = hmac_sha512(b"btls-v1", x25519(self.eph_priv, self.peer_eph))

    def _install_epoch(self, l_c2s: bytes, l_s2c: bytes) -> None:
        c2s, s2c = self._derive(l_c2s), self._derive(l_s2c)
        if self.role == CLIENT:
            self.send_key, self.recv_key = c2s, s2c
        else:
            self.send_key, self.recv_key = s2c, c2s
        self.send_seq = self.recv_seq = 0

    # --- records --------------------------------------------------------
    def _seal(self, inner: bytes) -> bytes:
        box = seal(self.send_key, _rec_nonce(self.send_seq), inner)
        self.send_seq += 1
        return bytes([RT_APPLICATION]) + len(box).to_bytes(2, "big") + box

    def _open(self, rec: bytes) -> bytes:
        if len(rec) < 3 or rec[0] != RT_APPLICATION:
            raise ValueError("bTLS: not an application record")
        blen = int.from_bytes(rec[1:3], "big")
        if blen < 33 or blen > 34 + MAX_PAYLOAD or len(rec) != 3 + blen:
            raise ValueError("bTLS: bad record length")
        inner = open_(self.recv_key, _rec_nonce(self.recv_seq), rec[3:])
        self.recv_seq += 1
        return inner

    # --- handshake ------------------------------------------------------
    def client_start(self) -> bytes:
        if self.role != CLIENT or self.state != ST_INIT:
            raise RuntimeError("bTLS: client_start in the wrong state")
        frame = _hs_frame(HS_CLIENT_HELLO, self.random + self.eph_pub)
        self._th(frame)
        self.state = ST_CH_SENT
        self.want_hs = HS_SERVER_HELLO
        return bytes([RT_HANDSHAKE]) + len(frame).to_bytes(2, "big") + frame

    def feed(self, rec: bytes) -> int:
        """Consume one inbound record. 1 = done, 0 = progress, -1 = failure."""
        try:
            return self._feed(rec)
        except (ValueError, IndexError) as exc:
            self.error = str(exc)
            return -1

    def _feed(self, rec: bytes) -> int:
        if len(rec) < 3:
            raise ValueError("bTLS: short record")
        blen = int.from_bytes(rec[1:3], "big")
        if blen > MAX_REC - 3 or len(rec) != 3 + blen:
            raise ValueError("bTLS: bad record length")
        body = rec[3:]
        if self.epoch == 0:
            if rec[0] != RT_HANDSHAKE or len(body) < 3:
                raise ValueError("bTLS: expected a plaintext handshake")
            msg_type = body[0]
            frame_len = int.from_bytes(body[1:3], "big")
            if frame_len != len(body) - 3:
                raise ValueError("bTLS: bad handshake frame")
            if self.role == SERVER and self.state == ST_INIT:
                if msg_type != HS_CLIENT_HELLO or frame_len != 64:
                    raise ValueError("bTLS: expected ClientHello")
                self.peer_eph = body[3 + 32:3 + 64]
                self._th(body)
                self.state = ST_HS
                self.want_hs = HS_SERVER_HELLO
                return 0
            if (self.role == CLIENT and self.state == ST_CH_SENT and
                    self.want_hs == HS_SERVER_HELLO):
                if msg_type != HS_SERVER_HELLO or frame_len != 64:
                    raise ValueError("bTLS: expected ServerHello")
                self.peer_eph = body[3 + 32:3 + 64]
                self._th(body)
                self._ecdhe()
                self._install_epoch(b"btls-hs-c2s", b"btls-hs-s2c")
                self.epoch = 1
                self.state = ST_HS
                self.want_hs = HS_CERTIFICATE
                return 0
            raise ValueError("bTLS: unexpected plaintext handshake")

        inner = self._open(rec)
        if not inner or inner[0] != RT_HANDSHAKE:
            raise ValueError("bTLS: expected a handshake record")
        return self._feed_hs(inner[1:])

    def _feed_hs(self, frame: bytes) -> int:
        if len(frame) < 3:
            raise ValueError("bTLS: short handshake frame")
        msg_type = frame[0]
        blen = int.from_bytes(frame[1:3], "big")
        if 3 + blen != len(frame):
            raise ValueError("bTLS: bad handshake frame length")
        body = frame[3:]

        if self.role == SERVER:
            if (self.state != ST_WAIT_FIN or msg_type != HS_FINISHED or
                    blen != 32):
                raise ValueError("bTLS: expected the client Finished")
            if self._derive(b"btls-fin-c") != body:
                raise ValueError("bTLS: client Finished does not verify")
            self._th(frame)
            self._install_epoch(b"btls-app-c2s", b"btls-app-s2c")
            self.epoch = 2
            self.state = ST_DONE
            return 1

        if self.want_hs == HS_CERTIFICATE:
            if msg_type != HS_CERTIFICATE or blen != 32:
                raise ValueError("bTLS: expected the certificate")
            self.cert_pub = body
            if self.expect_label:
                if label_from_pub(self.cert_pub) != self.expect_label:
                    raise ValueError(
                        "bTLS: certificate does not match "
                        f"{self.expect_label}.bait")
            self._th(frame)
            self.want_hs = HS_CERTIFICATE_VERIFY
            return 0
        if self.want_hs == HS_CERTIFICATE_VERIFY:
            if msg_type != HS_CERTIFICATE_VERIFY or blen != 64:
                raise ValueError("bTLS: expected CertificateVerify")
            if not verify(self.cert_pub, body, self._cert_digest()):
                raise ValueError("bTLS: CertificateVerify signature is bad")
            self._th(frame)
            self.want_hs = HS_FINISHED
            return 0
        if self.want_hs == HS_FINISHED:
            if msg_type != HS_FINISHED or blen != 32:
                raise ValueError("bTLS: expected the server Finished")
            if self._derive(b"btls-fin-s") != body:
                raise ValueError("bTLS: server Finished does not verify")
            self._th(frame)
            self.want_hs = 0
            return 0
        raise ValueError("bTLS: unexpected handshake message")

    def pump(self) -> bytes | None:
        """Next outbound record (server flight, or the client Finished)."""
        if self.role == SERVER and self.state == ST_HS:
            if self.want_hs == HS_SERVER_HELLO:
                frame = _hs_frame(HS_SERVER_HELLO, self.random + self.eph_pub)
                self._th(frame)
                self._ecdhe()
                self._install_epoch(b"btls-hs-c2s", b"btls-hs-s2c")
                self.epoch = 1
                self.want_hs = HS_CERTIFICATE
                return bytes([RT_HANDSHAKE]) + len(frame).to_bytes(2, "big") + frame
            if self.want_hs == HS_CERTIFICATE:
                frame = _hs_frame(HS_CERTIFICATE, self.pub)
                self._th(frame)
                self.want_hs = HS_CERTIFICATE_VERIFY
                return self._seal(bytes([RT_HANDSHAKE]) + frame)
            if self.want_hs == HS_CERTIFICATE_VERIFY:
                sig = sign(self.seed, self._cert_digest())
                frame = _hs_frame(HS_CERTIFICATE_VERIFY, sig)
                self._th(frame)
                self.want_hs = HS_FINISHED
                return self._seal(bytes([RT_HANDSHAKE]) + frame)
            if self.want_hs == HS_FINISHED:
                frame = _hs_frame(HS_FINISHED, self._derive(b"btls-fin-s"))
                self._th(frame)
                self.state = ST_WAIT_FIN
                return self._seal(bytes([RT_HANDSHAKE]) + frame)
        if self.role == CLIENT and self.state == ST_HS and self.want_hs == 0:
            frame = _hs_frame(HS_FINISHED, self._derive(b"btls-fin-c"))
            self._th(frame)
            rec = self._seal(bytes([RT_HANDSHAKE]) + frame)
            self._install_epoch(b"btls-app-c2s", b"btls-app-s2c")
            self.epoch = 2
            self.state = ST_DONE
            return rec
        return None

    # --- application ----------------------------------------------------
    def send_app(self, msg: bytes) -> list[bytes]:
        """Fragment a message into records (last one has FRAG_MORE clear)."""
        if self.state != ST_DONE:
            raise RuntimeError("bTLS: handshake is not complete")
        if not 0 < len(msg) <= MAX_MSG:
            raise ValueError("bTLS: message must be 1..256KiB")
        out = []
        for off in range(0, len(msg), MAX_PAYLOAD):
            piece = msg[off:off + MAX_PAYLOAD]
            more = FRAG_MORE if off + MAX_PAYLOAD < len(msg) else 0
            inner = bytes([RT_APPLICATION, more]) + piece
            out.append(self._seal(inner))
        return out

    def recv_app(self, rec: bytes) -> bytes | None:
        """Consume one application record; whole message or None (fragment)."""
        if self.state != ST_DONE:
            raise RuntimeError("bTLS: handshake is not complete")
        inner = self._open(rec)
        if not inner or inner[0] != RT_APPLICATION:
            raise ValueError("bTLS: not an application record")
        flags = inner[1]
        data = inner[2:]
        if len(self._rx_buf) + len(data) > MAX_MSG:
            raise ValueError("bTLS: message exceeds 256KiB")
        self._rx_buf += data
        if flags & FRAG_MORE:
            return None
        msg = bytes(self._rx_buf)
        self._rx_buf.clear()
        return msg
