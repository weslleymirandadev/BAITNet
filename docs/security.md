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
# server: only this phone can join
sudo ./af69d eth0 --raw --allow 00:08:22:9c:03:fc

# multiple MACs (repeat the flag)
sudo ./af69d eth0 --raw --allow 00:08:22:9c:03:fc --allow aa:bb:cc:dd:ee:ff

# no --allow = every MAC may join (default, as before)
```

Limitation: MACs are spoofable at L2. This layer is convenience, not
cryptographic security.

## Layer 2 — shared secret (HMAC-SHA256 token)

Both server and client know a secret. Every DHCP message carries an
8-byte token = first 8 bytes of HMAC-SHA256(secret, client MAC),
appended after the payload:

```
DISCOVER [7][mac 6][token 8]
OFFER    [8][mac 6][addr 5][lease 4][token 8]
REQUEST  [9][mac 6][addr 5][token 8]
ACK      [10][mac 6][addr 5][lease 4][token 8]
RELEASE  [11][mac 6][addr 5][token 8]
```

- The **server** verifies the token on every DISCOVER/REQUEST/RELEASE and
  drops messages with a bad/absent token (rogue clients can't join).
- The **client** verifies the token on OFFER/ACK and aborts on mismatch
  (rogue servers can't answer).
- Message length changes: DISCOVER 7→15, OFFER/ACK 16→24, REQUEST/RELEASE
  12→20. Older clients without `--secret` talk the short form; a server
  with `--secret` rejects them, and vice versa.

```
# server
sudo ./af69d eth0 --raw --secret 6b65792d6970763639

# client (phone / VM / any host)
./af69_raw dhcp wlan0 --secret 6b65792d6970763639
./af69_test dhcp eth0 --secret 6b65792d6970763639
```

Generate a secret: `head -c 16 /dev/urandom | xxd -p` (32 hex chars).

Limitations: the token is a shared secret — anyone who knows it can join
and (if the secret leaks) impersonate. It is not per-client keys. HMAC
truncated to 8 bytes is fine for LAN-grade auth; do not use for
Internet-facing services.

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
     --secret 6b65792d6970763639
```

Phone client:

```
export PATH=/usr/bin:/bin
/root/af69_raw dhcp wlan0 --secret 6b65792d6970763639
/root/af69_raw send wlan0 00.00.00.00.10 1 16 "hi" 00.00.00.00.10
```

Expected server log:

```
af69d: raw AF_PACKET (ifindex 2), pool 0000000000000010-00000000000000fe lease 3600s
af69d: allow=1 mac(s), secret=sim (HMAC)
af69d: DISCOVER 00:08:22:9c:03:fc -> OFFER 0000000000000010
af69d: REQUEST 00:08:22:9c:03:fc -> ACK 0000000000000010
```

Rejected client (bad secret or unlisted MAC) — server logs and ignores:

```
af69d: 00:08:22:9c:03:fc token HMAC invalido -> ignorado
af69d: aa:bb:cc:dd:ee:ff nao esta na allowlist -> ignorado
```

## Files touched

- `src/IPv69/hmac.c` / `include/IPv69/hmac.h` — standalone HMAC-SHA256
  (RFC 4231 test vector verified), no external deps
- `src/IPv69/af69d.c` — `--allow`, `--secret`, binding ioctl on ACK/RELEASE
- `tests/af69_raw.c` / `tests/af69_test.c` — `--secret` on `dhcp`, optional
  `src_addr` on `send`
- `kernel/af69/af69.c` — binding table + `ipv69_ioctl` (BIND_ADD/DEL) +
  dgram source validation in `ipv69_rcv`
- `include/IPv69/af69.h` — `struct ipv69_bind_req`, ioctl numbers
