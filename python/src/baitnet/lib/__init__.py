"""Standalone crypto (stands in for c/lib/ed25519 + TweetNaCl).

Nothing here imports the protocol layer: Ed25519, XSalsa20-Poly1305,
Poly1305, X25519 and HMAC-SHA512 only.
"""

from .crypto import (C_PAD, hmac_sha512, kdf, open_, poly1305, seal,
                     seed_to_pub, sha512, sign, verify, x25519, x25519_base)

__all__ = [
    "C_PAD", "hmac_sha512", "kdf", "open_", "poly1305", "seal", "seed_to_pub",
    "sha512", "sign", "verify", "x25519", "x25519_base",
]
