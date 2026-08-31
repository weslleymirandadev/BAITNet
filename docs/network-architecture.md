# IPv69 — Network architecture (bootstrap, addressing, P2P)

How IPv69 reaches the internet without depending on a single server.
Three independent mechanisms, each optional:

1. **Addressing**: derive the 40-bit address from the Ed25519 identity
   (SLAAC-style) — no DHCP server required to "get" an address.
2. **Bootstrap**: any gateway with a public IP (multi-gateway, seed
   nodes) bridges UDP tunnels to the IPv69 L2 network.
3. **Traffic**: P2P direct between peers after bootstrap — the gateway
   introduces them and steps out of the data path (hole punching;
   relay only as fallback).

The protocol itself is pure L2 and fully independent on a local
network (Wi-Fi, cable, veth): ND, echo, dgram and binding all work
directly, no server anywhere. This document is about crossing the
internet boundary.

## 1. The bootstrap paradox

To get an IPv69, a new user must talk to a server — but DHCP69 runs on
L2 frames (EtherType 0x6969) that do not cross the internet. So the
first contact always happens over the existing internet (plain IP)
through a UDP tunnel. IPv69 is born inside the tunnel.

This holds for every new protocol ever born:

- IPv6 was born inside tunnels over IPv4 (6in4, Teredo, 6to4)
- ZeroTier/Tailscale build the virtual network inside an IP tunnel
- Bitcoin bootstraps via DNS/seed nodes

**Design consequence:** bootstrap needs a gateway, but nothing else
does. Addressing and traffic are server-free.

## 2. Addressing: identity-derived (no DHCP needed)

Instead of asking a server for an address, a device derives its own
from its Ed25519 public key. **IPv4-style classes** organize the 40-bit
space into private/public worlds:

```
00.xx.xx.xx.xx   class A — private local      (LAN, DHCP pool)
01.xx.xx.xx.xx   class B — private extended   (VPN / multi-site)
10.xx.xx.xx.xx   class C — public             (internet, via gateway)
110.xx.xx.xx.xx  class D — multicast
111.xx.xx.xx.xx  class E — reserved           (broadcast ff.ff.ff.ff.ff)
```

The derived address prefixes 4 hash bytes with the class byte:

```
addr = [class byte] + first 4 bytes of SHA-512(pubkey)   →  40 bits
```

- Deterministic: same key + same class = same address, forever.
- No server, no lease, no renewal, no broadcast — the address is a
  property of the identity, like IPv6 SLAAC privacy addresses.
- 32 free bits per class → ~2^16 devices before meaningful birthday
  collision risk; collisions are detected by **DAD** (duplicate address
  detection): send an ND request for your own address; a reply means
  collision.
- One device, several worlds: `ipv69 addr` (class C) for the internet,
  `ipv69 addr --class A` for the local LAN — same key, different
  classes.

The gateway is the **class guard**: without `--private` only public
class C crosses it (private never leaks to the internet); with
`--private`, classes A/B also route (private VPN over the internet).

DHCP69 remains **optional** and is **private-network oriented**:
it is for closed networks that want centrally assigned pool addresses
(with allowlists, leases, binding). Public/open networks use the
identity-derived address — no server at all. The two models are
explicit alternatives:

```
dhcp-based:     af69_raw dhcp wlan0            → address from the pool
                (private networks: allowlist, leases, binding)
identity-based: af69_raw addr wlan0            → address from your key
                (open/public networks: no server, no lease)
```

The kernel binding (addr↔MAC) still applies to both: whoever owns the
address is whoever owns the MAC that claimed it.

## 3. Bootstrap: multi-gateway (seed nodes)

Any host with a public IP can run `ipv69gw` — the tunnel gateway. There
is no single required gateway: clients keep a **list** of gateways and
fail over between them (like DNS resolvers / Bitcoin seeds).

```
        User A (phone)                       User B (PC)
        ┌────────────────┐                   ┌────────────────┐
        │ ip69d app      │                   │ ip69d app      │
        │ TAP ip69-0     │                   │ TAP ip69-0     │
        │ UDP tunnel ────┼──┐            ┌──┼─── UDP tunnel  │
        └────────────────┘  │            │  └────────────────┘
                            ▼            ▼
                ┌────────────────────────────┐
                │  ipv69gw (any public IP)   │
                │  UDP listener              │
                │  table addr/mac↔endpoint   │
                │  forwarding + QUERY        │
                └────────────────────────────┘
                ┌────────────────────────────┐
                │  ipv69gw (another seed)    │  ← optional, same role
                └────────────────────────────┘
```

The gateway keeps a learned table `40-bit address ↔ UDP endpoint` and
`MAC ↔ endpoint` (learned from traffic, like an Ethernet switch), and:

- **forwards** frames between tunnels (and to a local L2 interface
  when present, e.g. where the DHCP69 server lives);
- **replicates** broadcast frames to every tunnel;
- **answers QUERY** — "which endpoint has address X?" — so peers can
  talk directly (section 4).

Wire format of the tunnel (minimalist, VXLAN-like without extra
headers):

```
UDP datagram: [full IPv69 frame: eth 14 + header 38 + payload]
UDP control (same socket, magic-prefixed):
  "Q" + addr40(5)         → "E" + addr40(5) + endpoint(ip:port)
```

The DHCP69 server (`af69d`) is unchanged: DISCOVER arrives as a normal
frame on the gateway's local interface (or is forwarded to the tunnel
of the server when the gateway has no local L2).

## 4. Traffic: P2P after bootstrap

The gateway introduces peers and steps out of the data path:

1. A asks the gateway: `QUERY B`.
2. Gateway answers: `B is at ip:port` (the endpoint B's tunnel is
   using — its public NAT mapping).
3. A sends a probe directly to that endpoint; B does the same to A's
   endpoint (simultaneous hole punching, both behind NAT).
4. When the direct path works, A and B exchange frames directly —
   the gateway is no longer in the data path, just a directory.

The direct path is retried; on failure traffic falls back through the
gateway (relay). The gateway therefore doubles as a **last-resort
relay** — which is exactly the Tailscale DERP model: direct when
possible, relayed when not.

P2P works only when at least one side is reachable (public IP, port
forwarding, or hole punching success). When neither is reachable, the
relay still works — the network degrades gracefully instead of dying.

## 5. What changes and what does NOT change

| Component | Change |
|---|---|
| `af69d` (DHCP69) | **None** — still runs on L2; still optional |
| `af69_raw` / `ip69d` (client) | `--remote gw1,gw2:port` → UDP tunnel backend; `addr` command for identity-derived addresses; DAD |
| `ipv69gw` (new) | UDP listener + addr/mac↔endpoint tables + forwarding + QUERY + relay |
| `lib/ed25519` | Exposes SHA-512 for address derivation |
| Kernel module, wire format, DHCP, binding | **Nothing changes** |

## 6. Deployment modes

| Mode | Addressing | Bootstrap | Traffic |
|---|---|---|---|
| Local network | DHCP or identity | none | direct |
| Internet, single gateway | DHCP or identity | one `ipv69gw` | relayed (hub) or P2P |
| Internet, seeds | identity (or DHCP on each seed) | any of N gateways | P2P with relay fallback |

## 7. Relationship with ICSP

ICSP (docs/icsp-spec.md) is the stream transport **inside** the IPv69
network. The gateway/tunnel is the transport that **connects the IPv69
network to the internet**. They are independent:

- Without ICSP: dgram (nh=1) works through the gateway normally.
- Without gateway: ICSP works on local L2 (veth, Wi-Fi, bridge).
- Together: reliable, encrypted streams between users on the internet,
  direct (P2P) or relayed.
