"""IPv69 in Python.

Same wire formats as the C implementation (``c/``): EtherType ``0x6969``,
32-byte header, 40-bit addresses, identity-derived addresses, ``.bait``
labels, ICSP chunk framing with the CRC32c of the whole payload, the
``H69E1`` keyring and the mac1 pre-auth filter.

Layout (``src/ipv69``):

    constants.py  wire constants (next_header, control codes, chunk types)
    addr.py       40-bit address, classes, derivation from a public key
    header.py     IPv69 header pack/unpack
    frame.py      Ethernet frame build/parse
    l2.py         AF_PACKET backend (Linux), interface auto-detection
    crypto.py     Ed25519 + XSalsa20-Poly1305 on top of cryptography/pynacl
    keyring.py    ~/.hosts69 key files (H69E1 encrypted format)
    bait.py       .bait labels (base32 of SHA-512(pub))
    mac1.py       WireGuard-style pre-auth tag
    icsp.py       ICSP header + chunk framing + CRC
    dhcp.py       DHCP69 client (DISCOVER/REQUEST over L2)
    cli.py        the `ipv69py` command

Not ported yet (the C tree is the reference for them): the UDP tunnel
gateway, gateway federation/mesh, PPPoE69, bTLS/BITE sessions and the
bring-up daemon. ``docs/python-port.md`` tracks what is done and what is
still missing.
"""

from .addr import Addr, derive_addr, parse_addr, format_addr, addr_class
from .constants import ETHERTYPE_IPV69, NEXT_CONTROL, NEXT_DGRAM, NEXT_STREAM
from .frame import build_frame, parse_frame, Frame
from .header import IpV69Header
from .icsp import IcspHeader, build_pkt, check_pkt, chunk_put, CHUNK

__version__ = "0.1.0"

__all__ = [
    "Addr", "derive_addr", "parse_addr", "format_addr", "addr_class",
    "ETHERTYPE_IPV69", "NEXT_CONTROL", "NEXT_DGRAM", "NEXT_STREAM",
    "build_frame", "parse_frame", "Frame", "IpV69Header",
    "IcspHeader", "build_pkt", "check_pkt", "chunk_put", "CHUNK",
    "__version__",
]
