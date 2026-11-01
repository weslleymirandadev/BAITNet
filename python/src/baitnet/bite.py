"""BITE — the HTTP-shaped protocol over bTLS over ICSP (c/examples/bite.c).

    request   = "METHOD target BITE/1.0\\r\\n\\r\\n"
    response  = "BITE/1.0 <status> <reason>\\r\\n" headers "\\r\\n" [body]

Read verbs are ``BITE``, ``GET`` and ``HEAD``; ``HEAD`` returns the headers
only. Status codes are HTTP's (200/400/404/405/500). Every message travels in
one bTLS message (fragmented into records when larger than 1360 bytes).
"""

from __future__ import annotations

from pathlib import Path

from .btls import MAX_MSG, Btls, CLIENT, SERVER
from .bait import label_from_pub, name_to_addr
from .session import Assoc

HDR_MAX = 2048
READ_VERBS = ("BITE", "GET", "HEAD")
DEFAULT_PORT = 8080

REASONS = {
    200: "OK",
    400: "Bad Request",
    404: "Not Found",
    405: "Method Not Allowed",
    500: "Internal Error",
}

_MIME = {
    ".html": "text/html", ".htm": "text/html", ".css": "text/css",
    ".js": "application/javascript", ".json": "application/json",
    ".txt": "text/plain", ".md": "text/plain", ".png": "image/png",
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
    ".svg": "image/svg+xml", ".ico": "image/x-icon", ".pdf": "application/pdf",
}


# --- messages -----------------------------------------------------------
def mime_of(path: str) -> str:
    return _MIME.get(Path(path).suffix.lower(), "application/octet-stream")


def build_request(method: str, path: str) -> bytes:
    return f"{method} {path} BITE/1.0\r\n\r\n".encode()


def parse_request(data: bytes) -> tuple[str, str]:
    """(method, path) from a request message; raises ValueError when bad."""
    head = data[:HDR_MAX].decode(errors="replace")
    if "\r\n\r\n" not in head:
        raise ValueError("BITE: request without a header terminator")
    line = head.split("\r\n", 1)[0]
    parts = line.split(" ")
    if len(parts) != 3 or parts[2] != "BITE/1.0":
        raise ValueError(f"BITE: malformed request line {line!r}")
    method, target = parts[0], parts[1]
    if not target.startswith("/"):
        raise ValueError("BITE: target must start with '/'")
    if ".." in target.split("?"):
        pass
    if any(seg == ".." for seg in target.split("?")[0].split("/")):
        raise ValueError("BITE: path traversal")
    return method.upper(), target.split("?")[0]


def build_response(status: int, body: bytes = b"", ctype: str | None = None,
                   head_only: bool = False, extra_headers: str = "") -> bytes:
    reason = REASONS.get(status, "Error")
    head = f"BITE/1.0 {status} {reason}\r\n"
    if ctype:
        head += f"Content-Type: {ctype}\r\n"
    if extra_headers:
        head += extra_headers
    head += f"Content-Length: {len(body)}\r\nServer: BITE/1.0\r\n\r\n"
    raw = head.encode() + (b"" if head_only else body)
    if len(raw) > MAX_MSG:
        raise ValueError("BITE: response exceeds the 256KiB message cap")
    return raw


def parse_response(data: bytes) -> tuple[int, dict[str, str], bytes]:
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode(errors="replace").split("\r\n")
    status_parts = lines[0].split(" ", 2)
    if len(status_parts) < 2 or status_parts[0] != "BITE/1.0":
        raise ValueError(f"BITE: malformed status line {lines[0]!r}")
    status = int(status_parts[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers, body


# --- static files -------------------------------------------------------
def resolve_document(root: str | Path, target: str) -> Path:
    """Map a request target to a file under ``root``; '/' -> index.html."""
    rel = target.lstrip("/") or "index.html"
    if rel.endswith("/"):
        rel += "index.html"
    path = (Path(root) / rel).resolve()
    root_abs = Path(root).resolve()
    if root_abs != path and root_abs not in path.parents:
        raise ValueError("BITE: path escapes the document root")
    if not path.is_file():
        raise FileNotFoundError(target)
    return path


def serve(root: str | Path, method: str, target: str) -> bytes:
    """One request -> one response message (mirrors serve() in bite.c)."""
    method = method.upper()
    if method not in READ_VERBS:
        return build_response(405, ctype=None, head_only=False,
                              extra_headers="Allow: BITE, GET, HEAD\r\n")
    head_only = method == "HEAD"
    try:
        path = resolve_document(root, target)
    except ValueError:
        return build_response(400, ctype="text/plain", head_only=head_only)
    except FileNotFoundError:
        return build_response(404, ctype="text/plain", head_only=head_only)
    body = path.read_bytes()
    if len(body) + HDR_MAX > MAX_MSG:
        return build_response(500, ctype="text/plain", head_only=head_only)
    return build_response(200, body, mime_of(str(path)), head_only=head_only)


# --- session plumbing ---------------------------------------------------
class BiteServer:
    """Serve documents over an established ICSP association."""

    def __init__(self, assoc: Assoc, root: str | Path):
        self.assoc = assoc
        self.root = root
        self.btls = Btls(SERVER, assoc.seed)

    def handshake(self, timeout: float = 10.0) -> None:
        """Drive the bTLS handshake until both sides have app keys."""
        import time
        deadline = time.monotonic() + timeout
        while self.btls.state != "done":
            if time.monotonic() > deadline:
                raise TimeoutError("BITE: bTLS handshake timed out")
            rec = self.assoc.recv_record(1.0)
            if rec is None:
                continue
            self.btls.feed(rec)
            while True:
                out = self.btls.pump()
                if out is None:
                    break
                self.assoc.send_record(out)

    def serve_one(self, timeout: float = 10.0) -> tuple[int, str]:
        """Handle one request; returns (status, target)."""
        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            rec = self.assoc.recv_record(1.0)
            if rec is None:
                continue
            msg = self.btls.recv_app(rec)
            if msg is None:
                continue
            method, target = parse_request(msg)
            resp = serve(self.root, method, target)
            for frag in self.btls.send_app(resp):
                self.assoc.send_record(frag)
            status = parse_response(resp)[0]
            return status, target
        raise TimeoutError("BITE: no request arrived")

    def listen(self, port: int, peers: list[bytes] | None = None,
               serve_forever: bool = False) -> None:
        """Accept associations and serve them (needs a session transport)."""
        self.assoc.src_port = port
        while True:
            self.assoc.server_accept(peers)
            try:
                self.handshake()
                self.serve_one()
            except (TimeoutError, ValueError):
                pass
            finally:
                self.btls = Btls(SERVER, self.assoc.seed)
                self.assoc.shutdown()
            if not serve_forever:
                return


class BiteClient:
    """Fetch a document from a BITE server over a new association."""

    def __init__(self, assoc: Assoc, label: str | None):
        self.assoc = assoc
        self.label = label
        self.btls = Btls(CLIENT, assoc.seed, label)

    def fetch(self, target: str = "/", method: str = "BITE",
              timeout: float = 15.0) -> tuple[int, dict[str, str], bytes]:
        import time
        self.assoc.client_handshake()
        first = self.btls.client_start()
        self.assoc.send_record(first)
        deadline = time.monotonic() + timeout
        while self.btls.state != "done":
            if time.monotonic() > deadline:
                raise TimeoutError("BITE: bTLS handshake timed out")
            rec = self.assoc.recv_record(1.0)
            if rec is None:
                continue
            if self.btls.feed(rec) < 0:
                raise ValueError("BITE: bTLS handshake rejected the server")
            while True:
                out = self.btls.pump()
                if out is None:
                    break
                self.assoc.send_record(out)
        for frag in self.btls.send_app(build_request(method, target)):
            self.assoc.send_record(frag)
        while time.monotonic() < deadline:
            rec = self.assoc.recv_record(1.0)
            if rec is None:
                continue
            msg = self.btls.recv_app(rec)
            if msg is None:
                continue
            return parse_response(msg)
        raise TimeoutError("BITE: no response")


def label_for(seed_pub: bytes) -> str:
    return label_from_pub(seed_pub)


def resolve_name(name: str, default_port: int = DEFAULT_PORT) -> tuple[int, int]:
    """``label.bait[:port][/path]`` -> (address, port)."""
    host = name.split("/", 1)[0]
    port = default_port
    if ":" in host:
        host, _, p = host.rpartition(":")
        port = int(p, 10)
    label = host[:-5] if host.endswith(".bait") else host
    return name_to_addr(label), port
