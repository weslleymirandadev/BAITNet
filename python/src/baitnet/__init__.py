"""BaitNet — the Python implementation of the IPv69 protocol.

Same wire formats as the C implementation (``c/``): EtherType ``0x6969``,
32-byte header, 40-bit addresses, identity-derived addresses, ``.bait``
labels, ICSP chunk framing with the CRC32c of the whole payload, the
``H69E1`` keyring and the mac1 pre-auth filter.

Layout (mirrors ``c/src``)::

    core/    IPv69 layer   -- constants, addr, crc, header, frame, l2,
                              transport, keyring, mac1, dhcp     (= c/src/IPv69)
    icsp/    framing.py (chunks + CRC), session.py (handshake, DATA/SACK,
                              rekey, lifecycle)                  (= c/src/ICSP)
    bite/    names.py (.bait), btls.py (records), bite.py (documents)
                                                                 (= c/src/BITE)
    lib/     crypto.py -- Ed25519, XSalsa20-Poly1305, Poly1305, X25519, HMAC
                                                                 (= c/lib/ed25519)
    cli.py   the `baitnet` command

Not ported yet: the UDP tunnel gateway, gateway federation/mesh, PPPoE69 and
the bring-up daemon. ``docs/python-port.md`` tracks what is done.
"""

from .core.addr import Addr, addr_class, derive_addr, format_addr, parse_addr
from .core.constants import (ETHERTYPE_IPV69, NEXT_CONTROL, NEXT_DGRAM,
                             NEXT_STREAM)
from .core.frame import Frame, build_frame, parse_frame
from .core.header import IpV69Header
from .icsp.framing import CHUNK, IcspHeader, build_pkt, check_pkt, chunk_put

__version__ = "0.1.0"

__all__ = [
    "Addr", "derive_addr", "parse_addr", "format_addr", "addr_class",
    "ETHERTYPE_IPV69", "NEXT_CONTROL", "NEXT_DGRAM", "NEXT_STREAM",
    "build_frame", "parse_frame", "Frame", "IpV69Header",
    "IcspHeader", "build_pkt", "check_pkt", "chunk_put", "CHUNK",
    "__version__",
]
