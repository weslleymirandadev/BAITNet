# IPv69 Security

Authentication and source-validation for the IPv69 protocol stack,
implemented on top of the DHCP69 address lease flow.

## Threat model

Without any of this, an attacker on the same L2 segment can:

1. **Get an address for free** — run `af69_raw dhcp` and join the network.
2. **Impersonate the DHCP server** — answer a client's DISCOVER with a fake
   OFFER/ACK (rogue server, MITM on address assignment).
3. **Spoof a source** — send dgram frames with `src = victim address` and
   have them accepted by every receiver.
4. **Listen to anything** — any unbound/promiscuous socket sees all traffic.

Three layers close these holes. They are independent: use any subset.

## Layer 1 — MAC allowlist (`af69d --allow`)

Only listed MACs may obtain a lease. The server silently ignores
DISCOVER/REQUEST/RELEASE from other MACs.

```
sudo ./af69d eth0 --raw --allow 00:08:22:9c:03:fc
```

Limitation: MACs are spoofable at L2. This layer is convenience, not
cryptographic security.

## Layer 2 — Ed25519 signatures (no shared secret)

Each device has its **own** Ed25519 keypair. The private key never leaves
the device; the server only knows **public** keys (which are not secret —
they can travel in the clear). There is no shared secret to leak, and a
compromised/leaked key revokes only that one device.

Generate keypairs:

```
./ipv69-keygen 2
<privkey_hex> <pubkey_hex>      # device A
<privkey_hex> <pubkey_hex>      # server (or any device)
```

Server — only devices whose public key is in the allowlist get a lease;
the server signs OFFER/ACK with its own key:

```
sudo ./af69d eth0 --raw \
     --peer <pubkey_A_hex> \
     --key  <server_privkey_hex>
```

Client (device A) — signs DISCOVER/REQUEST/RELEASE; optionally validates
the server's OFFER/ACK with `--server-pub` (rogue-server protection):

```
./af69_raw dhcp wlan0 --key <privkey_A_hex> --server-pub <server_pubkey_hex>
./af69_test dhcp eth0 --key <privkey_A_hex> --server-pub <server_pubkey_hex>
```

Wire format (next_header 0, payload). The signature covers every byte
before it:

```
DISCOVER [7][mac 6][pub 32][sig 64]
OFFER    [8][mac 6][addr 5][lease 4][pub 32][sig 64]
REQUEST  [9][mac 6][addr 5][pub 32][sig 64]
ACK      [10][mac 6][addr 5][lease 4][pub 32][sig 64]
RELEASE  [11][mac 6][addr 5][pub 32][sig 64]
```

Implementation: TweetNaCl `crypto_sign` (Ed25519, RFC 8032), validated
against the RFC 8032 test vectors. No external dependencies — runs on the
static arm64 phone build. Without `--peer`/`--key` the legacy short forms
are used (DISCOVER 7, OFFER/ACK 16, REQUEST/RELEASE 12 bytes).

Properties vs a shared secret:

| | shared secret (old) | Ed25519 (current) |
|---|---|---|
| leak of one key | whole network compromised | only that device |
| every peer needs the key | yes (distribution problem) | no — public keys only |
| revoke a device | change the secret for everyone | remove one `--peer` |
| rogue server detection | client validates HMAC | client validates signature |

## Layer 3 — lease binding in the kernel (dgram source auth)

The `af69.ko` module keeps a binding table `addr -> (MAC, expiry)`,
populated by the DHCP server through a new ioctl on an AF_69 socket:

```
IPV69_BIND_ADD  (CAP_NET_ADMIN required)
IPV69_BIND_DEL
```

`af69d` registers the binding right after each ACK and removes it on
RELEASE. The module then enforces, on **receive**:

- dgram frames (`next_header 1`) whose `src` address has no valid binding
  **are dropped**;
- dgram frames whose `src` matches a binding but come from a **different
  MAC** are dropped (anti-spoof);
- control traffic (DHCP, ND, echo) always passes — the protocol needs it
  to bootstrap.

Consequences for clients:
- you must send dgram with your **leased address** as `src`, otherwise the
  receiver's module drops it:
  ```
  ./af69_raw send wlan0 00.00.00.00.10 1 16 "hi" 00.00.00.00.10
  #                                          ^^^^^^^^^^^^^^ your leased addr
  ```
- an unleased address (e.g. `src 00.00.00.00.11` you never got) is
  dropped by the peer — spoofing fails.

The binding table is in-memory: on module reload it starts empty and the
next DHCP renew repopulates it. `af69d` re-registers on every ACK.

## Putting it together

Server on the VM (all three layers):

```
sudo ./af69d eth0 --raw \
     --allow 00:08:22:9c:03:fc \
     --peer <pubkey_hex> \
     --key <server_privkey_hex>
```

Phone client:

```
export PATH=/usr/bin:/bin
/root/af69_raw dhcp wlan0 --key <privkey_hex> --server-pub <server_pubkey_hex>
/root/af69_raw send wlan0 00.00.00.00.10 1 16 "hi" 00.00.00.00.10
```

Expected server log:

```
af69d: raw AF_PACKET (ifindex 2), pool 0000000000000010-00000000000000fe lease 3600s
af69d: allow=1 mac(s), peers=1 pubkey(s), server-key=sim
af69d: DISCOVER 00:08:22:9c:03:fc -> OFFER 0000000000000010
af69d: REQUEST 00:08:22:9c:03:fc -> ACK 0000000000000010
```

Rejected client (unknown key or unlisted MAC) — server logs and ignores:

```
af69d: pub f38f9008... nao esta na allowlist -> ignorado
af69d: 0a:a6:50:c5:86:17 assinatura/pubkey invalida -> ignorado
```

Client rejecting a rogue server:

```
dhcp: OFFER assinatura invalida
```

## Files touched

- `src/IPv69/tweetnacl.c` / `include/IPv69/tweetnacl.h` — TweetNaCl
  (public domain), Ed25519/SHA-512; `crypto_sign_seed_to_pk` added
- `src/IPv69/randombytes.c` — getrandom() backend for TweetNaCl
- `src/IPv69/ipv69-keygen.c` — keypair generator (`ipv69-keygen`)
- `src/IPv69/af69d.c` — `--peer` (pubkey allowlist), `--key` (server
  signing), binding ioctl on ACK/RELEASE
- `tests/af69_raw.c` / `tests/af69_test.c` — `--key`, `--server-pub` on
  `dhcp`, optional `src_addr` on `send`
- `kernel/af69/af69.c` — binding table + `ipv69_ioctl` (BIND_ADD/DEL) +
  dgram source validation in `ipv69_rcv`
- `include/IPv69/af69.h` — `struct ipv69_bind_req`, ioctl numbers
