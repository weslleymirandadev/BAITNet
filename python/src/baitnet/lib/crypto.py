"""crypto: Ed25519 and XSalsa20-Poly1305, both from PyNaCl (libsodium).

The private key is the 32-byte seed, like c/lib/ed25519. Libsodium's
secretbox is byte-compatible with TweetNaCl once the padding difference is
handled: the C wrapper keeps 16 zero bytes in front of the box, so

    blob = b"\\x00" * 16 || secretbox(m, nonce, key)      (len 16 + mlen + 16)

``seal``/``open_`` below speak exactly that layout.
"""

from __future__ import annotations

import hmac
import hashlib

from nacl import bindings as _nb
from nacl.exceptions import BadSignatureError, CryptoError
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey

# kept local on purpose: c/lib/ed25519 has no IPv69 dependency either
ED25519_SEED_LEN = 32
ED25519_PUB_LEN = 32
ED25519_SIG_LEN = 64

C_PAD = 16  # zero bytes the C wrapper keeps in front of the box


def sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def seed_to_pub(seed: bytes) -> bytes:
    if len(seed) != ED25519_SEED_LEN:
        raise ValueError("seed must be 32 bytes")
    return bytes(SigningKey(seed).verify_key)


def sign(seed: bytes, msg: bytes) -> bytes:
    if len(seed) != ED25519_SEED_LEN:
        raise ValueError("seed must be 32 bytes")
    return SigningKey(seed).sign(msg).signature


def verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    if len(pub) != ED25519_PUB_LEN or len(sig) != ED25519_SIG_LEN:
        return False
    try:
        VerifyKey(pub).verify(msg, sig)
        return True
    except (BadSignatureError, ValueError):
        return False


# --- XSalsa20-Poly1305 ---------------------------------------------------
def seal(key: bytes, nonce: bytes, msg: bytes) -> bytes:
    """C-compatible secretbox blob (16 zero bytes + MAC + ciphertext)."""
    if len(key) != 32 or len(nonce) != 24:
        raise ValueError("key is 32 bytes and nonce is 24")
    # SecretBox.encrypt returns nonce || MAC || ciphertext: keep the box only
    return b"\x00" * C_PAD + bytes(SecretBox(key).encrypt(msg, nonce).ciphertext)


def open_(key: bytes, nonce: bytes, blob: bytes) -> bytes:
    """Inverse of :func:`seal`; raises ValueError on a bad MAC."""
    if len(key) != 32 or len(nonce) != 24:
        raise ValueError("key is 32 bytes and nonce is 24")
    if len(blob) <= C_PAD or blob[:C_PAD] != b"\x00" * C_PAD:
        raise ValueError("not a C secretbox blob")
    try:
        return SecretBox(key).decrypt(blob[C_PAD:], nonce)
    except CryptoError as exc:
        raise ValueError("secretbox: authentication failed") from exc


_P1305 = (1 << 130) - 5


def poly1305(msg: bytes, key: bytes) -> bytes:
    """Poly1305 tag (RFC 8439), argument order of ed25519_poly1305(out,msg,n,key).

    Pure Python on purpose: PyNaCl does not expose one-shot Poly1305, and this
    is the reference implementation that the mac1 tests pin down.
    """
    if len(key) != 32:
        raise ValueError("poly1305 key is 32 bytes")
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        acc = ((acc + int.from_bytes(block + b"\x01", "little")) * r) % _P1305
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


# --- X25519 (ephemeral ECDH used by ICSP and bTLS) -----------------------
def x25519_base(priv: bytes) -> bytes:
    """Public key of a 32-byte X25519 scalar (clamped by libsodium)."""
    if len(priv) != 32:
        raise ValueError("x25519 private key is 32 bytes")
    return _nb.crypto_scalarmult_base(priv)


def x25519(priv: bytes, peer_pub: bytes) -> bytes:
    if len(priv) != 32 or len(peer_pub) != 32:
        raise ValueError("x25519 keys are 32 bytes")
    return _nb.crypto_scalarmult(priv, peer_pub)


def hmac_sha512(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha512).digest()


def kdf(prk: bytes, label: bytes, extra: bytes = b"") -> bytes:
    """The repo's one-shot "HKDF expand": HMAC(prk, label || extra || 0x01)."""
    return hmac_sha512(prk, label + extra + b"\x01")[:32]
