# IPv69 — Network architecture (bootstrap + gateway)

How DHCP69 becomes the "father of connections" and brand-new users on
the internet get their first IPv69. Defines the **hub-and-spoke** model
with a central server (VPS) and UDP tunnels.

## 1. The bootstrap paradox

To get an IPv69, the user must talk to the DHCP69 server. But DHCP69
runs on L2 frames (EtherType 0x6969) — which do not cross the internet.
Therefore: **nobody gets a first IPv69 without already having a
connection to the server through some other means**.

This holds for every new protocol ever born:

- IPv6 was born inside tunnels over IPv4 (6in4, Teredo, 6to4)
- ZeroTier/Tailscale build the virtual network inside an IP tunnel
- Bitcoin bootstraps via DNS/seed nodes

**Design consequence:** the bootstrap connection is the existing
internet (plain IP) through a tunnel. IPv69 is born INSIDE the tunnel.
DHCP69 never needs to "know" it is on the internet — to it, the
DISCOVER arrives as a regular frame on the gateway interface.

## 2. Hub-and-spoke model

```
        User A (phone)                       User B (PC)
        ┌────────────────┐                 ┌────────────────┐
        │ ip69d app      │                 │ ip69d app      │
        │ TAP ip69-0     │                 │ TAP ip69-0     │
        │ UDP/IP tunnel ─┼──┐          ┌──┼── UDP/IP tunnel│
        └────────────────┘  │          │  └────────────────┘
                            ▼          ▼
                    ┌───────────────────────┐
                    │  VPS on the internet   │
                    │  public IP             │
                    │  ┌───────────────────┐ │
                    │  │ ipv69gw (gateway) │ │
                    │  │  UDP listener     │ │
                    │  │  addr↔tunnel table│ │
                    │  │  virtual L2 switch│ │
                    │  └───────────────────┘ │
                    │  ┌───────────────────┐ │
                    │  │ af69d (DHCP69)    │ │
                    │  │  global pool      │ │
                    │  └───────────────────┘ │
                    └───────────────────────┘
```

The "father" server is a VPS with a public IP running:

1. **`ipv69gw` (tunnel gateway)** — receives 0x6969 frames encapsulated
   in UDP from clients; keeps the `40-bit address ↔ tunnel` table;
   forwards frames between tunnels (virtual L2 switch).
2. **`af69d` (DHCP69)** — the same one from the VM, **zero changes**:
   allocates addresses from the global pool, validates Ed25519 keys,
   registers addr↔MAC binding in the kernel.
3. **Virtual L2 switch** — when A sends a frame to B, the gateway
   forwards it through B's tunnel.

## 3. New-user flow (zero prior knowledge)

1. Downloads the app (ip69d client + tunnel), types the server address
   (e.g. `gw.ipv69.net`).
2. The app connects the UDP tunnel to the server — here it is still
   using plain IP (the regular internet).
3. Inside the tunnel, it runs the DHCP69 client → DISCOVER → the server
   allocates an IPv69 from the pool → **done, it has an address**.
4. The auto-key (`~/.ipv69/key`) handles identity: the server with
   `--learn` registers the pub automatically and persists it in the
   peer-file.

The user never sees IP, never configures routing — the app does it all.

## 4. How A talks to B

The gateway learns the `40-bit address ↔ tunnel` table from traffic
itself (like an Ethernet switch learns MACs). Frame from A to B:

1. A encapsulates the 0x6969 frame in a UDP datagram → sends to the
   server.
2. The gateway decapsulates, reads the 40-bit dest, finds B's tunnel.
3. Re-encapsulates and sends through B's tunnel.
4. Kernel binding still applies (the server registered addr↔MAC for
   each client on the DHCP ACK).

All traffic passes through the server — simple, predictable, and how
commercial VPNs start (ZeroTier, Hamachi, Tailscale DERP).

## 5. Tunnel encapsulation (wire format)

```
UDP datagram: [full IPv69 frame: eth 14 + header 38 + payload]

UDP dest port: fixed (e.g. 6969) — the port identifies the service on
the server; the IPv69 address still lives in the frame header.
```

Minimalist on purpose (VXLAN-like without an extra header): the whole
IPv69 frame inside one UDP datagram. The gateway only needs to read the
0x6969 header to decide the destination.

## 6. What changes and what does NOT change in the code

| Component | Change |
|---|---|
| `af69d` (DHCP69) | **None** — the DISCOVER arrives as a regular frame on the gateway interface |
| `af69_raw` / `ip69d` (client) | Gains a `--remote server:port` mode: instead of AF_PACKET on wlan0, sends frames over UDP |
| `ipv69gw` (new, server) | Multi-client UDP listener + addr↔tunnel table + forwarding (~200 lines) |
| Encapsulation | 0x6969 frame inside UDP, fixed port |
| Tunnel crypto | Ed25519 identity authenticates the client (already exists); encrypt the tunnel with secretbox once ICSP exists |

Wire format, DHCP, binding, protocol: **nothing changes**. Only a new
transport between client and server appears.

## 7. Future variations

- **P2P after bootstrap**: the server introduces peers (Tailscale/DERP
  style) and clients talk directly via hole punching — the server
  becomes just a coordinator, spending almost no bandwidth. Natural
  phase 2.
- **Home server**: port forwarding + DDNS works, but router NAT +
  dynamic IP = less stable than a VPS.
- **Multi-tenant**: the same gateway runs N isolated networks (each
  with its own pool and allowlist) — a per-network/per-device
  subscription model.

## 8. Relationship with ICSP

ICSP (docs/icsp-spec.md) is the stream transport **inside** the IPv69
network. The gateway/tunnel is the transport that **connects the IPv69
network to the internet**. They are independent:

- Without ICSP: dgram (nh=1) works through the gateway normally.
- Without gateway: ICSP works on local L2 (veth, Wi-Fi, bridge).
- Together: reliable, encrypted streams between users on the internet.
