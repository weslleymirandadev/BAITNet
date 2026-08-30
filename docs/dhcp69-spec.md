# DHCP69 — IPv69 Address Configuration (spec v0.4)

Automatic 40-bit address assignment for IPv69 hosts, DHCP-style.
Removes the need to type `ff.ff.ff.ff.ff` addresses by hand: a server
leases addresses from a pool, clients discover/request/keep them.

Status: **spec only** — not implemented yet.

## Addressing conventions

| value          | meaning                    |
|----------------|----------------------------|
| `00.00.00.00.00` | unconfigured / any      |
| `00.00.00.00.01` | DHCP69 server (reserved) |
| `00.00.00.00.02` – `00.00.00.00.0f` | reserved (future) |
| `00.00.00.00.10` – `00.00.00.00.fe` | default lease pool |
| `ff.ff.ff.ff.ff` | broadcast               |

Pool is configurable on the server (start/end), default
`00.00.00.00.10`–`00.00.00.00.fe` (239 addresses).

## Control types (next_header 255)

Payload layout: `[type 1B][fields...]` — same control channel as ND/echo
(`IPV69_CTRL_*` in `include/IPv69/af69.h`).

| type | name      | payload                                  |
|------|-----------|------------------------------------------|
| 7    | DISCOVER  | `[7][mac 6B]`                            |
| 8    | OFFER     | `[8][mac 6B][addr 5B][lease 4B]`         |
| 9    | REQUEST   | `[9][mac 6B][addr 5B]`                   |
| 10   | ACK       | `[10][mac 6B][addr 5B][lease 4B]`        |
| 11   | RELEASE   | `[11][mac 6B][addr 5B]`                  |

All multi-byte fields big-endian. `lease` is seconds (4B BE).
`mac` is the CLIENT's Ethernet MAC (client knows it via SIOCGIFHWADDR;
included in payload because kernel recvfrom does not expose the sender
MAC, and the raw AF_PACKET path and the AF_69 path must agree).

## Flow

```
client (unconfigured, src=0)          server (src=00.00.00.00.01)
        |  DISCOVER (broadcast, mac)        |
        |---------------------------------->|
        |  OFFER (broadcast, mac, addr, lease) |
        |<----------------------------------|
        |  REQUEST (broadcast, mac, addr)   |
        |---------------------------------->|
        |  ACK (broadcast, mac, addr, lease)|
        |<----------------------------------|
        bind(src=addr)  -- configured --
```

- All DHCP messages travel with Ethernet dst MAC `ff:ff:ff:ff:ff:ff`
  (no neighbor discovery needed before addressing exists).
- Client filters replies by the `mac` field (promiscuous sockets may
  see other clients' traffic).
- Server tracks `mac -> addr + lease expiry`; pool entries are
  recycled after lease expiry; a REQUEST for an address leased to
  another MAC gets no ACK (client restarts DISCOVER).
- Client renews by re-sending REQUEST before expiry; RELEASE on
  clean shutdown.
- Server is identified by `src=00.00.00.00.01`; client may address
  REQUEST/RELEASE to it directly (demux delivers dst==socket addr or
  broadcast).

## Implementation plan

- `src/IPv69/af69d.c` — server daemon:
  - socket AF_69 (kernel module) or AF_PACKET raw (no module)
  - bind src `00.00.00.00.01`, port filter 0 (control has no ports)
  - CLI: `af69d <ifname|ifindex> [pool_start] [pool_end] [lease_sec]`
  - state: lease table `mac -> {addr, expiry}`; log offers/acks
- `tests/af69_test.c` and `tests/af69_raw.c` — client mode:
  - `af69_test dhcp <ifindex> [iface]` / `af69_raw dhcp <ifname>`
  - send DISCOVER, wait OFFER (filter by own MAC), send REQUEST,
    wait ACK, bind(src=addr), print assigned address
- no kernel changes required: `ipv69_rcv` already accepts next_header
  255 and the control switch defaults to delivery; new types flow to
  userspace sockets untouched.
- shared constants go to `include/IPv69/af69.h`
  (`IPV69_CTRL_DHCP_DISCOVER` etc.) so kernel/userspace/raw agree.

## Test (after implementation)

1. VM Kali: `sudo af69d eth0` (or `af69d 2` with the module)
2. Phone (chroot): `af69_raw dhcp wlan0` → prints leased address
3. `af69_raw ping wlan0 <leased_addr>` works with no manual address
4. Second client gets a different address; lease expiry recycles
