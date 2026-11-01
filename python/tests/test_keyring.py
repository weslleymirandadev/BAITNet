"""Keyring: our own round-trip plus interop with a C-created key file.

``fixtures/c_key_H69E1.asc`` was written by ``c/build/ipv69 keygen`` with
passphrase ``pyfx`` — loading it here proves the H69E1 format and the
SHA-512 XOR KDF are byte-compatible with the C implementation.
"""

import os
from pathlib import Path

import pytest

from ipv69.crypto import open_ as box_open, seal as box_seal, seed_to_pub
from ipv69.keyring import (derive_key, load_keyfile, load_or_create,
                          read_pub, save_keyfile)

FIXTURES = Path(__file__).parent / "fixtures"
C_KEY = FIXTURES / "c_key_H69E1.asc"
C_KEY_PASSPHRASE = "pyfx"


def test_load_c_generated_encrypted_key():
    seed = load_keyfile(C_KEY, C_KEY_PASSPHRASE)
    pub = seed_to_pub(seed)
    expected = read_pub(Path(str(C_KEY) + ".pub"))
    assert pub == expected


def test_wrong_passphrase_fails():
    with pytest.raises(ValueError):
        load_keyfile(C_KEY, "not-the-pass")


def test_roundtrip_encrypted(tmp_path):
    key = tmp_path / "mykey"
    seed = bytes(range(32))
    pub = save_keyfile(key, seed, "secret", "unit test")
    assert pub == seed_to_pub(seed)
    assert load_keyfile(key, "secret") == seed
    body = key.read_text().splitlines()
    assert body[0] == "H69E1" and len(body) == 4
    assert oct(key.stat().st_mode & 0o777) == "0o600"
    assert (tmp_path / "mykey.pub").read_text().split()[0] == pub.hex()


def test_roundtrip_plain(tmp_path):
    key = tmp_path / "plain"
    seed = os.urandom(32)
    save_keyfile(key, seed, None)
    assert load_keyfile(key) == seed
    assert len(key.read_text().strip()) == 64


def test_load_or_create_creates_once(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    seed1, pub1, created1 = load_or_create(None, "iden")
    assert created1
    seed2, pub2, created2 = load_or_create(None, "iden")
    assert not created2 and seed1 == seed2 and pub1 == pub2
    assert (tmp_path / ".hosts69" / "iden").exists()


def test_secretbox_blob_layout_matches_c():
    key, nonce = bytes(range(32)), bytes(range(24))
    blob = box_seal(key, nonce, b"mensagem")
    assert blob[:16] == b"\x00" * 16
    assert len(blob) == 16 + len(b"mensagem") + 16
    assert box_open(key, nonce, blob) == b"mensagem"
    with pytest.raises(ValueError):
        box_open(key, nonce, blob[:16] + b"\x00" + blob[17:])
