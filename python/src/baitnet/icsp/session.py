"""ICSP session: authenticated handshake, encrypted streams, SACK, lifecycle.

Mirrors c/src/ICSP/{icsp_handshake,icsp_data,icsp_life}.c:

    client: INIT -> INIT-ACK(cookie) -> COOKIE-ECHO -> COOKIE-ACK
    server: accept(INIT) -> INIT-ACK -> validate COOKIE-ECHO -> COOKIE-ACK

INIT chunk body:  [ver][streams_in 2][streams_out 2][eph_pub 32][ts 8]
                  [id_pub 32][sig 64][mac1 16]
INIT-ACK body:    [ver][streams_in 2][streams_out 2][eph_pub 32][id_pub 32]
                  [sig 64][cookie 48]
COOKIE-ECHO body: [cookie 48][sig 64]
DATA chunk body:  [tsn 4][stream 2][seq 2][secretbox(clear=[tsn][stream][seq][msg])]
SACK body:        [cumulative_tsn 4]

Session keys are directional: prk = HMAC("icsp-v1", X25519(eph,peer_eph)),
send = HMAC(prk, "icsp-send"||0x01)[:32], recv = the same with "icsp-recv";
the responder swaps them. DATA nonce = SHA-512(assoc_id||tsn)[:24].

Identity hiding (ICSP_INIT_FLAG_IDBOX) is deliberately NOT implemented: the C
path feeds an Ed25519 key into X25519 on one side and a raw seed on the other,
so the two sides disagree — the tested, interoperable path is the clear id.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from ..core import mac1
from ..core.constants import (
    CHUNK, DEFAULT_HOP_LIMIT, ICSP_CHUNK_HDR, ICSP_MAX_PAYLOAD, ICSP_VERSION,
    MAC1_LEN, NEXT_STREAM,
)
from ..lib.crypto import (hmac_sha512, kdf, seal, open_, seed_to_pub, sha512,
                     sign, verify, x25519, x25519_base)
from ..core.frame import BCAST_MAC, build_frame, parse_frame
from .framing import build_pkt, check_pkt, chunk_put

COOKIE_LEN = 48
COOKIE_TTL = 300
INIT_ID_LEN = 32
INIT_PRE_SIG = 1 + 4 + 32 + 8 + INIT_ID_LEN      # 77 (id in the clear)
INIT_LEN = INIT_PRE_SIG + 64 + MAC1_LEN          # 141

ST_CLOSED = "closed"
ST_COOKIE_WAIT = "cookie-wait"
ST_ESTABLISHED = "established"
ST_SHUTDOWN = "shutdown"

STREAM_DATA = 1


def data_nonce(assoc_id: int, tsn: int) -> bytes:
    """nonce = SHA-512(assoc_id_be || tsn_be)[0:24]."""
    return sha512(assoc_id.to_bytes(4, "big") + tsn.to_bytes(4, "big"))[:24]


def derive_keys(shared: bytes, initiator: bool) -> tuple[bytes, bytes]:
    """(send_key, recv_key) — directional, mirrored by the responder."""
    prk = hmac_sha512(b"icsp-v1", shared)
    mine = kdf(prk, b"icsp-send")
    theirs = kdf(prk, b"icsp-recv")
    return (mine, theirs) if initiator else (theirs, mine)


@dataclass
class Assoc:
    transport: object                      # Transport (send/recv/mac)
    seed: bytes = b""                      # 32-byte Ed25519 seed
    src_addr: int = 0
    src_port: int = 0
    dst_addr: int = 0
    dst_port: int = 0
    streams_in: int = 4
    streams_out: int = 4

    state: str = ST_CLOSED
    assoc_id: int = 0
    peer_id: bytes = b""
    peer_eph: bytes = b""
    eph_priv: bytes = b""
    eph_pub: bytes = b""
    send_key: bytes = b""
    recv_key: bytes = b""
    peer_mac: bytes | None = None
    last_rx: float = 0.0
    last_init_ts: int = 0

    streams: dict[int, dict] = field(default_factory=dict)
    sendq: list[dict] = field(default_factory=list)
    rcvbuf: dict[int, dict[int, bytes]] = field(default_factory=dict)
    cum_tsn: int = 0
    rw_tsn: int = 0
    rw_mask: int = 0
    next_tsn: int = 0

    cookie_secret: bytes = b""

    # --- helpers --------------------------------------------------------
    @property
    def pub(self) -> bytes:
        return seed_to_pub(self.seed) if self.seed else self.peer_id

    @property
    def has_key(self) -> bool:
        return bool(self.send_key)

    def _stream(self, sid: int) -> dict:
        return self.streams.setdefault(sid, {"send_seq": 0, "recv_seq": 0})

    def _reset_data_plane(self) -> None:
        self.streams.clear()
        self.sendq.clear()
        self.rcvbuf.clear()
        self.cum_tsn = self.rw_tsn = self.rw_mask = 0
        self.next_tsn = int.from_bytes(os.urandom(4), "big")

    def _send_chunk(self, chunk: bytes) -> None:
        pkt = build_pkt(self.src_port, self.dst_port, self.assoc_id, chunk)
        dst_mac = self.peer_mac or BCAST_MAC
        frame = build_frame(dst_mac, self.transport.mac, self.src_addr,
                            self.dst_addr, NEXT_STREAM, pkt,
                            hop_limit=DEFAULT_HOP_LIMIT,
                            src_port=self.src_port, dst_port=self.dst_port)
        self.transport.send(frame)

    def _recv_payload(self, timeout: float) -> bytes | None:
        """Next ICSP payload addressed to us, or None on timeout."""
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            raw = self.transport.recv(left)
            if raw is None:
                return None
            try:
                frame = parse_frame(raw)
            except ValueError:
                continue
            if frame.header.next_header != NEXT_STREAM:
                continue
            # our own TX coming back (same NIC): drop control chunks, and the
            # data path drops anything that fails the recv_key
            if frame.eth_src == self.transport.mac:
                if len(frame.payload) < 12 + ICSP_CHUNK_HDR:
                    continue
                sport = int.from_bytes(frame.payload[0:2], "big")
                ctype = frame.payload[12]
                if sport == self.src_port and ctype not in (
                        CHUNK.INIT, CHUNK.INIT_ACK, CHUNK.COOKIE_ECHO,
                        CHUNK.COOKIE_ACK, CHUNK.DATA):
                    continue
            if not check_pkt(frame.payload):
                continue
            self.dst_addr = frame.header.source
            if frame.eth_src != self.transport.mac:
                self.peer_mac = frame.eth_src
            self.last_rx = time.monotonic()
            return frame.payload

    # --- handshake ------------------------------------------------------
    def _build_init(self) -> bytes:
        self.eph_priv = os.urandom(32)
        self.eph_pub = x25519_base(self.eph_priv)
        d = bytearray()
        d += bytes([ICSP_VERSION])
        d += self.streams_in.to_bytes(2, "big")
        d += self.streams_out.to_bytes(2, "big")
        d += self.eph_pub
        d += int(time.time()).to_bytes(8, "big")
        d += seed_to_pub(self.seed)
        body = bytes(d)                                    # 45 bytes
        sig = sign(self.seed, body)                        # over [ver..id]
        signed = body + sig
        tag = mac1.compute(mac1.key_for(self.dst_addr), signed)
        return chunk_put(CHUNK.INIT, signed + tag)

    def client_handshake(self, attempts: int = 5) -> None:
        """INIT -> INIT-ACK -> COOKIE-ECHO -> COOKIE-ACK."""
        if not self.src_port:
            self.src_port = 50000 + os.getpid() % 1000
        self.state = ST_COOKIE_WAIT
        self._reset_data_plane()
        self.assoc_id = int.from_bytes(os.urandom(4), "big")
        init = self._build_init()
        cookie = b""
        for _ in range(attempts):
            self._send_chunk(init)
            payload = self._recv_payload(3.0)
            if payload is None:
                init = self._build_init()      # fresh ephemeral + timestamp
                continue
            body = payload[12 + ICSP_CHUNK_HDR:]
            if payload[12] != CHUNK.INIT_ACK or len(body) < 181:
                continue
            if body[0] != ICSP_VERSION:
                continue
            peer_eph = body[5:37]
            peer_id = body[37:69]
            sig = body[69:133]
            if not verify(peer_id, sig, body[:69]):
                raise ValueError("ICSP: INIT-ACK signature is not valid")
            self.peer_eph, self.peer_id = peer_eph, peer_id
            shared = x25519(self.eph_priv, self.peer_eph)
            self.send_key, self.recv_key = derive_keys(shared, initiator=True)
            cookie = body[133:181]
            # COOKIE-ECHO [cookie][sig]
            echo = cookie + sign(self.seed, cookie)
            self._send_chunk(chunk_put(CHUNK.COOKIE_ECHO, echo))
            for _ in range(attempts):
                payload = self._recv_payload(3.0)
                if payload is None:
                    self._send_chunk(chunk_put(CHUNK.COOKIE_ECHO, echo))
                    continue
                if payload[12] == CHUNK.COOKIE_ACK:
                    self.state = ST_ESTABLISHED
                    self._reset_data_plane()
                    return
            raise TimeoutError("ICSP: no COOKIE-ACK")
        raise TimeoutError("ICSP: no INIT-ACK")

    def _cookie_make(self) -> bytes:
        if not self.cookie_secret or (
                time.monotonic() - getattr(self, "_cookie_ts", 0) > COOKIE_TTL):
            self.cookie_secret = os.urandom(32)
            self._cookie_ts = time.monotonic()
        buf = (self.peer_id + self.peer_eph +
               self.streams_in.to_bytes(2, "big") +
               self.streams_out.to_bytes(2, "big"))
        return hmac_sha512(sha512(self.cookie_secret), buf)[:COOKIE_LEN]

    def server_accept(self, peers: list[bytes] | None = None,
                      timeout: float = 30.0) -> None:
        """Wait for an INIT, answer it, validate COOKIE-ECHO."""
        peers = peers or []
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("ICSP: no INIT")
            payload = self._recv_payload(left)
            if payload is None:
                continue
            if payload[12] != CHUNK.INIT:
                continue
            body = payload[12 + ICSP_CHUNK_HDR:]
            if len(body) < INIT_PRE_SIG + 64 + MAC1_LEN or body[0] != ICSP_VERSION:
                continue
            signed, tag = body[:INIT_PRE_SIG + 64], body[INIT_PRE_SIG + 64:INIT_PRE_SIG + 64 + MAC1_LEN]
            if not mac1.verify(mac1.key_for(self.src_addr), signed, tag):
                continue
            ts = int.from_bytes(body[37:45], "big")
            if ts <= self.last_init_ts:
                continue
            self.last_init_ts = ts
            self.assoc_id = int.from_bytes(payload[6:10], "big")
            peer_eph = body[5:37]
            peer_id = body[45:77]
            if not verify(peer_id, body[77:141], body[:77]):
                continue
            if peers and peer_id not in peers:
                continue
            self.peer_eph, self.peer_id = peer_eph, peer_id
            return self._answer_init()

    def _answer_init(self) -> None:
        self.eph_priv = os.urandom(32)
        self.eph_pub = x25519_base(self.eph_priv)
        shared = x25519(self.eph_priv, self.peer_eph)
        self.send_key, self.recv_key = derive_keys(shared, initiator=False)
        d = bytearray()
        d += bytes([ICSP_VERSION])
        d += self.streams_in.to_bytes(2, "big")
        d += self.streams_out.to_bytes(2, "big")
        d += self.eph_pub
        d += seed_to_pub(self.seed)
        sig = sign(self.seed, bytes(d))
        cookie = self._cookie_make()
        self._send_chunk(chunk_put(CHUNK.INIT_ACK, bytes(d) + sig + cookie))
        # wait COOKIE-ECHO
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            payload = self._recv_payload(max(0.0, deadline - time.monotonic()))
            if payload is None:
                continue
            if payload[12] != CHUNK.COOKIE_ECHO:
                continue
            body = payload[12 + ICSP_CHUNK_HDR:]
            if len(body) < COOKIE_LEN + 64:
                continue
            echo, sig = body[:COOKIE_LEN], body[COOKIE_LEN:COOKIE_LEN + 64]
            if echo != cookie or not verify(self.peer_id, sig, echo):
                continue
            self._send_chunk(chunk_put(CHUNK.COOKIE_ACK))
            self.state = ST_ESTABLISHED
            self._reset_data_plane()
            return
        raise TimeoutError("ICSP: no COOKIE-ECHO")

    # --- data -----------------------------------------------------------
    def data_send(self, stream_id: int, data: bytes) -> int:
        if not self.has_key:
            raise RuntimeError("association is not established")
        # 12 (ICSP hdr) + 4 (chunk hdr) + 8 (clear hdr) + 32 (secretbox) + len
        if len(data) > ICSP_MAX_PAYLOAD - 56:
            raise ValueError("ICSP message too large (max 1344 bytes)")
        s = self._stream(stream_id)
        tsn = self.next_tsn
        self.next_tsn = (tsn + 1) & 0xFFFFFFFF
        clear = (tsn.to_bytes(4, "big") + stream_id.to_bytes(2, "big") +
                 s["send_seq"].to_bytes(2, "big") + data)
        box = seal(self.send_key, data_nonce(self.assoc_id, tsn), clear)
        chunk = chunk_put(CHUNK.DATA, clear[:8] + box)
        self._send_chunk(chunk)
        self.sendq.append({"tsn": tsn, "stream": stream_id, "seq": s["send_seq"],
                           "chunk": chunk, "sent_at": time.monotonic(),
                           "acked": False})
        s["send_seq"] = (s["send_seq"] + 1) & 0xFFFF
        return tsn

    def data_retransmit(self, timeout: float = 0.5) -> int:
        now = time.monotonic()
        n = 0
        for item in self.sendq:
            if item["acked"] or now - item["sent_at"] < timeout:
                continue
            self._send_chunk(item["chunk"])
            item["sent_at"] = now
            n += 1
        return n

    def all_acked(self) -> bool:
        return all(item["acked"] for item in self.sendq)

    def _handle_data(self, body: bytes) -> tuple[int, bytes] | None:
        """Decrypt one DATA chunk; returns (stream, payload) when in order."""
        tsn = int.from_bytes(body[0:4], "big")
        sid = int.from_bytes(body[4:6], "big")
        seq = int.from_bytes(body[6:8], "big")
        box = body[8:]
        if len(box) < 32:
            return None
        # sliding replay window
        if tsn > self.rw_tsn:
            shift = tsn - self.rw_tsn
            self.rw_mask = ((self.rw_mask << shift) | 1) if shift < 32 else 1
            self.rw_tsn = tsn
        elif self.rw_tsn - tsn >= 32:
            return None
        elif (self.rw_mask >> (self.rw_tsn - tsn)) & 1:
            return None
        else:
            self.rw_mask |= 1 << (self.rw_tsn - tsn)
        try:
            clear = open_(self.recv_key, data_nonce(self.assoc_id, tsn), box)
        except ValueError:
            return None                     # not ours (our own TX, forged)
        if (int.from_bytes(clear[0:4], "big") != tsn or
                int.from_bytes(clear[4:6], "big") != sid or
                int.from_bytes(clear[6:8], "big") != seq):
            raise ValueError("ICSP: DATA header does not match the ciphertext")
        s = self._stream(sid)
        if seq != s["recv_seq"]:
            self.rcvbuf.setdefault(sid, {}).setdefault(seq, clear[8:])
            return None                     # buffered for reordering
        out = [(seq, clear[8:])]
        nxt = s["recv_seq"] + 1
        buf = self.rcvbuf.get(sid, {})
        while nxt in buf:
            out.append((nxt, buf.pop(nxt)))
            nxt += 1
        s["recv_seq"] = nxt & 0xFFFF
        self.cum_tsn = max(self.cum_tsn, tsn)
        return sid, b"".join(chunk for _, chunk in out)

    def handle(self, payload: bytes) -> list[tuple[str, object]]:
        """Process one received payload; returns a list of events."""
        events: list[tuple[str, object]] = []
        saw_data = False
        pos = 12
        while pos + ICSP_CHUNK_HDR <= len(payload):
            ctype = payload[pos]
            clen = int.from_bytes(payload[pos + 2:pos + 4], "big")
            body = payload[pos + ICSP_CHUNK_HDR:pos + ICSP_CHUNK_HDR + clen]
            if len(body) < clen:
                break
            if ctype == CHUNK.DATA:
                saw_data = True
                got = self._handle_data(body)
                if got:
                    events.append(("data", got))
            elif ctype == CHUNK.SACK and len(body) >= 4:
                cum = int.from_bytes(body[:4], "big")
                for item in self.sendq:
                    if not item["acked"] and item["tsn"] <= cum:
                        item["acked"] = True
                events.append(("sack", cum))
            elif ctype == CHUNK.HEARTBEAT:
                self.send_heartbeat(ack=True)
                events.append(("heartbeat", body))
            elif ctype == CHUNK.SHUTDOWN:
                self.state = ST_SHUTDOWN
                events.append(("closed", None))
            elif ctype == CHUNK.STREAM_RESET and len(body) >= 3:
                sid = int.from_bytes(body[0:2], "big")
                self._stream(sid)["recv_seq"] = 0
                events.append(("stream-reset", sid))
            pos += ICSP_CHUNK_HDR + clen
        if saw_data and self.has_key:
            self.send_sack()        # icsp_handle_frame acknowledges every DATA
        return events

    def poll(self, timeout: float = 0.5) -> list[tuple[str, object]]:
        payload = self._recv_payload(timeout)
        if payload is None:
            self.data_retransmit()
            return []
        return self.handle(payload)

    # --- lifecycle ------------------------------------------------------
    def send_sack(self) -> None:
        self._send_chunk(chunk_put(CHUNK.SACK, self.cum_tsn.to_bytes(4, "big")))

    def send_heartbeat(self, ack: bool = False) -> None:
        ctype = CHUNK.HEARTBEAT_ACK if ack else CHUNK.HEARTBEAT
        self._send_chunk(chunk_put(ctype, int(time.time()).to_bytes(4, "big")))

    def stream_reset(self, stream_id: int, mode: int = 0) -> None:
        self._send_chunk(chunk_put(CHUNK.STREAM_RESET,
                                   stream_id.to_bytes(2, "big") + bytes([mode])))

    def shutdown(self) -> None:
        try:
            self._send_chunk(chunk_put(CHUNK.SHUTDOWN))
        finally:
            self.state = ST_SHUTDOWN

    # --- bTLS carrier ---------------------------------------------------
    def send_record(self, record: bytes) -> None:
        self.data_send(STREAM_DATA, record)

    def recv_record(self, timeout: float = 1.0) -> bytes | None:
        """Next record on the data stream (also answers SACK/heartbeats)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            events = self.poll(max(0.0, deadline - time.monotonic()))
            for kind, payload in events:
                if kind == "data":
                    sid, data = payload
                    if sid == STREAM_DATA:
                        return data
                if kind == "closed":
                    return None
        return None
