"""Command line: the Python counterpart of `ipv69` (subset).

    ipv69py addr [--class A|B|C] [--bait] [--key-file NAME]
    ipv69py keygen [-f NAME] [-N PASS] [-C COMMENT]
    ipv69py selftest                      # wire vectors, no root, no NIC
    ipv69py ping [ifname] <addr> [payload]
    ipv69py send [ifname] <addr[:port]> <payload>
    ipv69py recv [ifname] <addr[:port]>

Only the parts that are already ported are exposed; see
docs/python-port.md for the rest (gateway, ICSP session, BITE).
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from . import mac1  # noqa: F401  (kept for the handshake helpers upstream)
from .addr import format_addr, parse_addr, parse_addr_port
from .bait import label_from_pub
from .constants import (
    BCAST_ADDR, CTRL_ECHO_REPLY, CTRL_ECHO_REQUEST, NEXT_CONTROL, NEXT_DGRAM,
)
from .crypto import seed_to_pub  # noqa: F401
from .dhcp import configure
from .frame import BCAST_MAC, build_frame, parse_frame
from .keyring import key_paths, load_or_create
from .l2 import L2


def _identity(args) -> tuple[bytes, bytes]:
    passphrase = args.passphrase or os.getenv("IPV69_PASSPHRASE")
    seed, pub, created = load_or_create(passphrase, args.key_file,
                                        os.uname().nodename)
    if created:
        print(f"key generated at {key_paths(args.key_file)[0]}")
    return seed, pub


# --- commands -----------------------------------------------------------
def cmd_addr(args) -> int:
    seed, pub = _identity(args)
    from .addr import derive_addr
    value = derive_addr(pub, args.cls)
    print(f"addr: {format_addr(value)} (derived from identity, class {args.cls})")
    print(f"pubkey: {pub.hex()}")
    if args.bait:
        label = label_from_pub(pub)
        print(f"label: {label}")
        print(f"bait:  {label}.bait")
    return 0


def cmd_keygen(args) -> int:
    key, _pub_path = key_paths(args.key_file)
    if key.exists() and not args.force:
        print(f"keygen: {key} already exists (use --force to overwrite)",
              file=sys.stderr)
        return 1
    seed = os.urandom(32)
    from .keyring import save_keyfile
    pub = save_keyfile(key, seed, args.passphrase, args.comment)
    print(f"Your identification has been saved in {key}")
    print(f"PUBKEY (register on the server): {pub.hex()} {args.comment}".rstrip())
    print(f"bait name: {label_from_pub(pub)}.bait")
    return 0


def cmd_selftest(_args) -> int:
    """Wire vectors that do not need a NIC — the same ones pytest asserts."""
    from .crc import crc32c
    from .icsp import build_pkt, check_pkt, chunk_put
    checks: list[tuple[str, bool]] = []

    checks.append(("crc32c('abc') == 0x364b3fb7", crc32c(b"abc") == 0x364B3FB7))

    chunk = chunk_put(0, b"\x00\x00\x00\x07\x00\x00\x00\x00abc")  # DATA tsn7 s0 q0
    pkt = build_pkt(8080, 20000, 0x0A0B0C0D, chunk)
    gold = "1f904e2001000a0b0c0d750e0000000b0000000700000000616263"
    checks.append(("ICSP packet vector", pkt.hex() == gold))
    checks.append(("ICSP CRC accepted", check_pkt(pkt)))
    checks.append(("ICSP corrupted rejected",
                   not check_pkt(pkt[:10] + bytes([pkt[10] ^ 1]) + pkt[11:])))

    # keyring passphrase round-trip in memory
    from .crypto import open_ as box_open, seal as box_seal
    from .keyring import derive_key
    import os as _os
    seed = _os.urandom(32)
    salt, nonce = _os.urandom(16), _os.urandom(24)
    k = derive_key(salt, "pw")
    checks.append(("secretbox round-trip", box_open(k, nonce, box_seal(k, nonce, seed)) == seed))

    ok = True
    for name, passed in checks:
        print(f"{'PASS' if passed else 'FAIL'} {name}")
        ok &= passed
    return 0 if ok else 1


def _bind_addr(args, l2: L2) -> int:
    """Own address: explicit, or a DHCP69 lease."""
    if args.addr:
        return parse_addr(args.addr)
    lease = configure(l2, None)
    print(f"lease: {format_addr(lease[0])} ({lease[1]}s)")
    return lease[0]


def cmd_ping(args) -> int:
    dst = parse_addr(args.dst)
    with L2(args.ifname) as l2:
        src = _bind_addr(args, l2)
        payload = bytes([CTRL_ECHO_REQUEST]) + args.payload.encode()
        frame = build_frame(BCAST_MAC, l2.mac, src, dst, NEXT_CONTROL, payload)
        l2.send(frame)
        print(f"ping {format_addr(dst)} from {format_addr(src)}")
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            raw = l2.recv(max(0.0, deadline - time.monotonic()))
            if raw is None:
                break
            try:
                got = parse_frame(raw)
            except ValueError:
                continue
            if (got.header.next_header == NEXT_CONTROL and got.payload[:1] ==
                    bytes([CTRL_ECHO_REPLY])):
                text = got.payload[1:].decode(errors="replace")
                print(f"reply from {format_addr(got.header.source)}: {text}")
                return 0
    print("ping: timeout")
    return 1


def cmd_send(args) -> int:
    dst, port = parse_addr_port(args.target)
    port = port or 0
    with L2(args.ifname) as l2:
        src = _bind_addr(args, l2)
        frame = build_frame(BCAST_MAC, l2.mac, src, dst, NEXT_DGRAM,
                            args.payload.encode(), src_port=port,
                            dst_port=port)
        l2.send(frame)
        print(f"sent {len(args.payload)} bytes {format_addr(src)}->"
              f"{format_addr(dst)}:{port}")
    return 0


def cmd_recv(args) -> int:
    addr, port = parse_addr_port(args.target, 0)
    with L2(args.ifname) as l2:
        print(f"listening on {args.ifname} for {format_addr(addr)}:{port}")
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            raw = l2.recv(max(0.0, deadline - time.monotonic()))
            if raw is None:
                break
            try:
                got = parse_frame(raw)
            except ValueError:
                continue
            if got.header.dest not in (addr, BCAST_ADDR):
                continue
            if port and got.header.dst_port != port:
                continue
            text = got.payload.decode(errors="replace")
            print(f"frame: {got} payload={text!r}")
    return 0


# --- parser -------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ipv69py", description="IPv69 (Python)")
    p.add_argument("--key-file", default=None, help="identity file (name or path)")
    p.add_argument("-N", "--passphrase", default=None, help="key passphrase")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("addr", help="identity-derived address")
    a.add_argument("--class", dest="cls", default="C", choices=list("ABCDE"))
    a.add_argument("--bait", action="store_true", help="also print the .bait name")
    a.set_defaults(func=cmd_addr)

    k = sub.add_parser("keygen", help="create a key pair")
    k.add_argument("-f", "--file", dest="key_file", default=None)
    k.add_argument("-N", "--passphrase", default=None)
    k.add_argument("-C", "--comment", default="")
    k.add_argument("--force", action="store_true")
    k.set_defaults(func=cmd_keygen)

    s = sub.add_parser("selftest", help="wire vectors (no root, no NIC)")
    s.set_defaults(func=cmd_selftest)

    for name, func in (("ping", cmd_ping), ("send", cmd_send), ("recv", cmd_recv)):
        sp = sub.add_parser(name, help=f"{name} over raw L2 (needs root)")
        sp.add_argument("ifname", nargs="?", default="auto")
        sp.add_argument("target" if name != "ping" else "dst", help="<addr[:port]>")
        if name == "ping":
            sp.add_argument("payload", nargs="?", default="ping")
            sp.add_argument("--addr", default=None, help="source address (default: DHCP)")
            sp.add_argument("--timeout", type=float, default=3.0)
        elif name == "send":
            sp.add_argument("payload")
            sp.add_argument("--addr", default=None, help="source address (default: DHCP)")
            sp.add_argument("--timeout", type=float, default=3.0)
        else:
            sp.add_argument("--timeout", type=float, default=10.0)
        sp.set_defaults(func=func)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not hasattr(args, "ifname"):
        args.ifname = "auto"
    try:
        return args.func(args)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"ipv69py: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
