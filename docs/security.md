# IPv69 Security

Authentication and source-validation for the IPv69 protocol stack,
implemented on top of the DHCP69 address lease flow.

## Threat model

Without any of this, an attacker on the same L2 segment can:

1. **Get an address for free** — run `ipv69 dhcp` and join the network.
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
sudo ./af69d eth0 --allow 00:08:22:9c:03:fc
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
sudo ./af69d eth0 \
     --peer <pubkey_A_hex> \
     --key  <server_privkey_hex>
```

Client (device A) — signs DISCOVER/REQUEST/RELEASE; optionally validates
the server's OFFER/ACK with `--server-pub` (rogue-server protection):

```
./ipv69 dhcp wlan0 --key <privkey_A_hex> --server-pub <server_pubkey_hex>
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

## Layer 3 — source authentication (userspace)

No kernel module: source authentication lives in the tools.

- `dhcpd` tracks `mac -> {addr, expiry}` from the lease table: a REQUEST
  for an address leased to another MAC gets no ACK, and the pool only
  hands out addresses to allowlisted/signed clients.
- Every client signs its DISCOVER/REQUEST with its Ed25519 key; the
  server only leases to known `--peer` pubkeys (or auto-learns with
  `--learn`).
- The gateway (`ipv69 gw`) never trusts a source address: it learns
  each peer's range only from authenticated traffic (signed INIT or ND
  announce) and validates every datagram's src against the learned
  ranges with a hash lookup — forged src frames are dropped silently
  (cryptokey routing, USAGE.md §7).

Consequences for clients:
- your `src` is never user-chosen: locally the DHCP server assigns the
  lease for your MAC; on `--remote` it is derived from your identity.
  Passing a manual src is rejected by the tools.
- an address you never got (or that is not yours) is dropped by the
  receiver/gateway — spoofing fails.

## Putting it together

Server on the VM (all three layers):

```
sudo ./ipv69 dhcpd eth0 \
     --allow 00:08:22:9c:03:fc \
     --peer <pubkey_hex> \
     --key <server_privkey_hex>
```

Phone client:

```
export PATH=/usr/bin:/bin
/root/ipv69 dhcp wlan0 --key <privkey_hex> --server-pub <server_pubkey_hex>
/root/ipv69 send wlan0 00.00.00.00.10:16 1 "hi"
```

Expected server log:

```
af69d: raw L2 (eth0), pool 0000000000000010-00000000000000fe lease 3600s
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

- `lib/ed25519/` — TweetNaCl (public domain), Ed25519/SHA-512 and the
  standalone public API (`ed25519.h`)
- `src/IPv69/keygen.c` / `src/IPv69/keyring.c` — keypair generator and
  the `~/.hosts69` keyring (`ipv69 keygen`)
- `src/IPv69/af69d.c` — `ipv69 dhcpd`: `--peer` (pubkey allowlist),
  `--key` (server signing), `--learn` (auto-register)
- `tests/af69_raw.c` — `ipv69 dhcp/send/recv/ping`: `--key`,
  `--server-pub`, identity-derived `src` on `--remote`
- `include/IPv69/af69.h` — control types and DHCP69 constants
  (`IPV69_CTRL_DHCP_*`, `IPV69_SERVER_ADDR`, pool range)
