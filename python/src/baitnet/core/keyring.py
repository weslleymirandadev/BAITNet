"""~/.hosts69 key files — same format as c/src/IPv69/keyring.c.

Encrypted file (magic ``H69E1`` + salt/nonce/box hex, one per line)::

    H69E1
    <salt 16B hex>
    <nonce 24B hex>
    <box hex>          # 16 zero bytes || secretbox(seed 32B)

Key derivation is the repo's simple KDF::

    key = SHA-512(salt)[0:32] XOR SHA-512(passphrase)[0:32]

Plain files hold the 64-hex-character seed on a single line. ``key.pub``
holds ``<pubhex> <comment>``.
"""

from __future__ import annotations

import binascii
import os
import pwd
from pathlib import Path

from .constants import (ED25519_SEED_LEN, KEY_MAGIC, KEY_NONCE_LEN,
                       KEY_SALT_LEN)
from ..lib.crypto import open_ as box_open, seal as box_seal, seed_to_pub, sha512

DEFAULT_DIR = ".hosts69"


def home() -> Path:
    """The real user's home (``sudo`` resets HOME, like keyring_home() in C)."""
    sudo_user = os.getenv("SUDO_USER")
    if sudo_user and os.geteuid() == 0:
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    return Path(os.getenv("HOME") or os.getenv("USERPROFILE") or ".")


def key_paths(name: str | None = None) -> tuple[Path, Path]:
    """Resolve the key file (``--key-file``/IPV69_KEYFILE or the default).

    A bare name lives inside ~/.hosts69; an absolute path is used as-is.
    """
    raw = name or os.getenv("IPV69_KEYFILE")
    if not raw:
        base = home() / DEFAULT_DIR
        return base / "key", base / "key.pub"
    p = Path(raw).expanduser()
    if not p.is_absolute() and p.parent == Path("."):
        p = home() / DEFAULT_DIR / p
    return p, p.with_name(p.name + ".pub")


def derive_key(salt: bytes, passphrase: str) -> bytes:
    a = sha512(salt)
    b = sha512(passphrase.encode())
    return bytes(x ^ y for x, y in zip(a, b))[:32]


def load_keyfile(path: Path, passphrase: str | None = None) -> bytes:
    """Return the 32-byte seed from a key file (encrypted or plain)."""
    text = path.read_text().strip()
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        raise ValueError(f"empty key file: {path}")
    if lines[0] == KEY_MAGIC:
        if passphrase is None:
            raise ValueError("encrypted key: a passphrase is required")
        salt = binascii.unhexlify(lines[1])
        nonce = binascii.unhexlify(lines[2])
        box = binascii.unhexlify(lines[3])
        if len(salt) != KEY_SALT_LEN or len(nonce) != KEY_NONCE_LEN:
            raise ValueError("malformed key file")
        seed = box_open(derive_key(salt, passphrase), nonce, box)
        if len(seed) != ED25519_SEED_LEN:
            raise ValueError("malformed seed")
        return seed
    seed = binascii.unhexlify(lines[0])
    if len(seed) != ED25519_SEED_LEN:
        raise ValueError("malformed seed")
    return seed


def save_keyfile(path: Path, seed: bytes, passphrase: str | None = None,
                 comment: str = "") -> bytes:
    """Write the key (+ .pub); returns the public key."""
    if len(seed) != ED25519_SEED_LEN:
        raise ValueError("seed must be 32 bytes")
    path.parent.mkdir(parents=True, exist_ok=True)
    pub = seed_to_pub(seed)
    if passphrase:
        salt = os.urandom(KEY_SALT_LEN)
        nonce = os.urandom(KEY_NONCE_LEN)
        box = box_seal(derive_key(salt, passphrase), nonce, seed)
        body = "\n".join([
            KEY_MAGIC,
            binascii.hexlify(salt).decode(),
            binascii.hexlify(nonce).decode(),
            binascii.hexlify(box).decode(),
        ]) + "\n"
    else:
        body = binascii.hexlify(seed).decode() + "\n"
    path.write_text(body)
    os.chmod(path, 0o600)
    pub_path = path.with_name(path.name + ".pub")
    pub_path.write_text(f"{binascii.hexlify(pub).decode()} {comment}\n")
    os.chmod(pub_path, 0o600)
    return pub


def load_or_create(passphrase: str | None = None, name: str | None = None,
                   comment: str = "") -> tuple[bytes, bytes, bool]:
    """Load the identity, creating it when missing.

    Returns ``(seed, pub, created)``.
    """
    key, _pub = key_paths(name)
    if key.exists():
        seed = load_keyfile(key, passphrase)
        return seed, seed_to_pub(seed), False
    seed = os.urandom(ED25519_SEED_LEN)
    pub = save_keyfile(key, seed, passphrase, comment)
    return seed, pub, True


def read_pub(path: Path) -> bytes:
    """First token of ``<name>.pub``."""
    token = path.read_text().split()[0]
    return binascii.unhexlify(token)
