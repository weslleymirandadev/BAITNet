"""BITE: .bait names, the bTLS record layer and the document protocol.

Mirrors c/src/BITE (names = baitname.c, btls = btls.c) and the server/client
logic of c/examples/bite.c.
"""

from .bite import (BiteClient, BiteServer, build_request, build_response,
                   parse_request, parse_response, resolve_name, serve)
from .btls import CLIENT, SERVER, Btls
from .names import (is_bait_name, label_from_pub, label_to_addr, label_valid,
                    name_to_addr)

__all__ = [
    "BiteClient", "BiteServer", "build_request", "build_response",
    "parse_request", "parse_response", "resolve_name", "serve",
    "Btls", "CLIENT", "SERVER", "label_from_pub", "label_valid",
    "label_to_addr", "name_to_addr", "is_bait_name",
]
