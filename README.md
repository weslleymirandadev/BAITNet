# IPv69 — Experimental Network Protocol

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
- [x] Basic transport (253 datagram, 254 raw stream, no payload)
- Addressing
- Routing
- Forwarding
- Hop Limit
- ICMP-like / control messages
- Transport protocol
- API/socket

### Phase 4 — Operating system
- [x] Native address family `AF_69` (module `kernel/af69/af69.ko`)
- Define integration API
- Implement IPv69 support in Linux
- Create an IPv69 network interface
- Integrate with existing drivers
- Test real applications over IPv69

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
40-bit addressing (`ff.ff.ff.ff.ff`) and transport beyond the 253 datagram
(254 raw stream, no payload). The AF_69 kernel module gives native socket
access to the protocol.

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
