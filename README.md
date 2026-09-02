# IPv69 — Experimental Network Protocol

> **New here? Start with [USAGE.md](USAGE.md)** — build, DHCP69,
> Ed25519 auth, ip69d/ip69 and troubleshooting.

## Overview

IPv69 is a meme protocol that will really be used for great stuff — tools
that exclusively run over IPv69, and all of its dependent protocols.

The idea is not just a new packet format, but eventually a full network
stack based on IPv69, implementable in software, embedded systems and,
further down the road, dedicated hardware.

The project started in x86-64 Assembly (full history in git) and evolved to
C with static libc — the focus remains working directly with memory, bytes,
sockets and network interfaces, with no high-level abstractions beyond
libc. The C implementation is portable to future phases (embedded, ESP32).

## How the network fits together

IPv69 is a link-layer protocol with its own addressing and security, so
the network it forms is a set of **islands** — every place that shares a
wire, a Wi-Fi network, or any L2 medium you control runs IPv69 natively,
with no IP of any kind on the wire:

```
 island A (office LAN)              island B (home LAN)
 ┌───────────────────┐              ┌───────────────────┐
 │ phone             │              │ laptop            │
 │ laptop        gw ─┼── internet ──┼── gw        phone │
 └───────────────────┘              └───────────────────┘
      native L2 (0x6969)                native L2 (0x6969)
```

To join islands that are in *different places*, each island runs a
**gateway** (`ipv69 gw`) on any host with a public IP — a VPS, or a home
connection with a forwarded port. A gateway is not a middlebox that all
traffic passes through; it is an **entry point to the mesh** with two
jobs:

1. **Introduce** — when a client asks "where is address X?", the gateway
   answers with X's endpoint (and tells X who asked), so the two peers
   talk **directly** and the gateway leaves the path;
2. **Relay as a fallback** — if a direct path cannot open (for example
   two strict NATs), the gateway forwards the frames and the
   communication still works.

Gateways can know each other (`--peer-gw`): each one announces the
clients it serves and learns the routes of its neighbours, so a client
on island A reaches a client on island B the same way it reaches its
own island. There is **no central server and no load balancer**: every
gateway serves its own island, so load is distributed by construction,
and clients keep a *list* of gateways (`--remote gw1:6969,gw2:6969`)
purely for redundancy — if one is down they fail over. More gateways
means more entry points to the mesh, never a bigger middlebox.

## Roadmap

### Phase 1 — Protocol
- [x] Define the IPv69 concept
- [x] Define the initial header
- [x] Define addresses (40 bits, form `ff.ff.ff.ff.ff`)
- [x] Define experimental EtherType `0x6969`
- [x] Define big-endian usage
- [x] Create `BE16`, `BE32` and `BE64` macros
- [x] Finalize the header spec (v0.2)
- [ ] Define extension headers
- [x] Define parsing rules (basic validation in `src/IPv69/parse.c`)

### Phase 2 — Packet I/O
- [x] Create detector
- [x] Capture frames via `AF_PACKET`
- [x] Identify EtherType `0x6969`
- [x] Full header parsing
- [x] Validate packets (basic)
- [x] Create packet generator
- [x] Transmit packets (raw socket)
- [x] Host → host IPv69 communication (Kali/QEMU on phone ↔ VirtualBox bridged VM)

### Phase 3 — Stack
- [x] Basic transport (dgram protocol, raw stream reserved)
- [x] Addressing (40-bit, `ff.ff.ff.ff.ff`)
- [ ] Routing table (forwarding exists: relay on another up iface of the netns)
- [x] Forwarding (3-netns relay validated)
- [x] Hop Limit (decrement on forward, drop at 0 + TIME_EXCEEDED)
- [x] ICMP-like / control messages (echo/ping, dest unreachable, time exceeded, ND)
- [x] Transport protocol (next_header 2 stream: ICSP, SCTP-derived)
- [x] Raw-socket API (AF_PACKET backend, send/recv demux by addr/port)

### Phase 4 — Operating system
- [x] ICSP session layer + stream transport (docs/icsp-spec.md)
- [x] TAP interface daemon (ip69d) + DHCP69 client
- Implement IPv69 support in Linux (kernel native)

### Phase 5 — Embedded
- Microcontroller implementation
- ESP32 implementation
- Ethernet implementation
- Wi-Fi implementation
- PC ↔ embedded device tests

### Phase 6 — Hardware
- IPv69 parser in FPGA
- Header processing in hardware
- IPv69 NIC research
- Possible ASIC implementation

## Current status

IPv69 is in the protocol experimentation phase: detector/receiver and
transmitter run without root (CAP_NET_RAW), with interface auto-detection,
40-bit addressing (`ff.ff.ff.ff.ff`) and the dgram protocol with native
header ports. The stack runs on the portable raw L2 backend (AF_PACKET
on Linux, Npcap on Windows): demux by addr/port, neighbor discovery
(40-bit → MAC), hop limit, forwarding, a control plane (echo/ping,
errors, ND), DHCP69 addressing, Ed25519 authentication, an ICSP stream
transport (nh=2) and tunnel gateways for the internet (see USAGE.md).

The immediate goal is not to replace the existing Internet, but to build an
experimental network stack from scratch, starting at the lowest level
possible:

```text
bytes
  ↓
Ethernet
  ↓
IPv69
  ↓
transport
  ↓
application
```

The implementation started in Assembly precisely to make the whole packet
building, transmission, reception and interpretation process explicit —
and that knowledge is preserved in git history while the current code
evolves in C.
