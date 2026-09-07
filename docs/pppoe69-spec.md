# PPPoE69 — access sessions for IPv69 (spec v0.1)

An *improved PPPoE*: the part of RFC 2516 that is timeless — discover an
access concentrator on a shared L2 segment, negotiate a private session
with a 16-bit session id, then exchange frames only inside that session
— with the parts that only existed to carry PPP+IP removed, because
IPv69 already has identity, addressing and security.

Where RFC 2516 says "PPPoE exists so PPP can run over Ethernet", here:

```
PPPoE69 exists so a host on a shared segment can get a private,
authenticated, point-to-point logical link to the network edge — the
access concentrator — and appear on the edge's L2 exactly as if it
were plugged into it.
```

Implemented as `ipv69 pppoe ac` (access concentrator) and
`ipv69 pppoe host` (the dialing side). Spec version v0.1 = the L2
session core; the roadmap at the end lists the next phases.

---

## 1. Where PPPoE fits in IPv69 (the analysis)

IPv69 today has four ways of being on a network:

| Mechanism | Role |
|---|---|
| DHCP69 (`dhcpd`/`dhcp`) | centrally assigned pool addresses, private networks |
| identity addressing (`addr`) | SLAAC-style address from the key, no server |
| raw L2 send/recv/ping | data plane on an island segment |
| `gw` + `--remote` | joining islands across the internet (UDP carrier) |

What is missing is the **access edge**: the place where a host that is
not a plain citizen of the segment (it wants admission control, a
private channel, a session) joins an island. In real networks that role
is PPPoE's: the DSLAM/BRAS sits at the edge of the access network and
gives each subscriber a private session over a shared medium.

Concretely, PPPoE-style sessions fill three gaps in the current design:

1. **Admission before traffic.** Today a gateway validates sources as
   frames flow (cryptokey routing, learned ranges). A concentrator
   validates the *identity at session setup* (signed PADR) and can
   refuse to create the session at all — the access decision happens
   once, up front, before any data frame exists.

2. **A private, unicast-only channel on a shared segment.** In a
   session, nothing the host sends is broadcast, and nothing the island
   broadcasts is pushed into the session. The session carries only
   frames addressed to that host. This is isolation by construction —
   the L2 equivalent of a VPN on a shared wire.

3. **A uniform access primitive that outlives the medium.** The session
   unit — `[session_id][full IPv69 frame]` — is carrier-agnostic. On L2
   it is what this spec implements; over a UDP tunnel, a v6-only link or
   (future) a serial hop it is the same unit. The host dials once and
   its whole stack (`dhcp`, `send`, `recv`, `icsp`, the chat example)
   runs over the session as if the remote island were its own wire.

It also matches the project's router mental model: a gateway's links
are point-to-point; a PPPoE69 session turns the host↔edge leg into a
point-to-point link with a session id, exactly like a `--peer-gw` link
is a point-to-point link between gateways.

### Pure PPPoE vs improved (why this is not RFC 2516 on the wire)

| RFC 2516 element | Verdict in PPPoE69 | Why |
|---|---|---|
| Discovery dance PADI/PADO/PADR/PADS/PADT | **kept** (as control types on the existing EtherType) | the session bootstrap is the timeless part |
| 16-bit session id, unicast-only session frames | **kept** | per-session demux + isolation |
| Separate EtherTypes 0x8863/0x8864 for discovery/session | **dropped** | IPv69 has one EtherType; discovery = `next_header 0` control codes, session = new `next_header 3` |
| PPP itself: LCP, ACCM, MRU negotiation | **dropped** | nothing to negotiate: IPv69 frames have no HDLC-ish flags/escape |
| PAP/CHAP authentication | **dropped** | Ed25519 identity from the `~/.hosts69` keyring, allowlisted at PADR |
| IPCP/IPv6CP address assignment | **dropped** | IPv69 has no IP; addressing stays identity-derived or DHCP69 (which can run *inside* the session) |
| Service-name / AC-name tags | **dropped** (v0.1) | multi-AC selection by address (`--ac`) or first PADO; tags are a later phase |

The result is a protocol with the *shape* of PPPoE and none of the
legacy: five control messages, one session header, full IPv69 frames as
payload — every byte that is not the session itself is already an IPv69
frame.

## 2. Roles and topology

```
             access segment (shared L2)             island L2 (the AC's leg)
 ┌──────────────────────────────┐       ┌──────────────────────────────────┐
 │  host A (dial, tap ip69p0) ──┼───────┼── ac (ipv69 pppoe ac) ── dhcpd   │
 │  host B (dial, tap ip69p0) ──┼───────┼── recv / send / icsp peers       │
 └──────────────────────────────┘       └──────────────────────────────────┘
        session A ────────────┘              each dialed host appears on the
        session B ────────────┘              AC's L2 with its own MAC
```

- **`ac`** — the access concentrator (server role). Runs on the island
  edge, on the interface that faces the access segment (same segment as
  the dialing hosts, or the wired side of an AP). Terminates sessions,
  answers neighbor discovery for the dialed hosts, and *bridges* their
  frames onto its own L2 leg. Works on Linux and Windows (pure `l2_*`
  backend, like `dhcpd`).
- **`host`** — the dialing side. Sends PADI/PADR, receives PADO/PADS,
  then exposes the session as a **TAP interface** (`ip69p0` by default)
  so the normal tools run unchanged: `ipv69 dhcp ip69p0`,
  `ipv69 recv ip69p0 <addr>`, `ipv69 send ip69p0 <dst>:16 msg`, the
  chat example, ICSP — whatever. Linux only in v0.1 (TAP); the dial
  logic itself is portable and the Windows host comes with the UDP
  carrier phase.

The AC is a **switch, not a router**: it never looks at the inner
40-bit addresses for forwarding decisions beyond "which session owns
this address", it does not decrement hop limits, and the inner frames
keep their original Ethernet headers. The dialed host is virtually
plugged into the AC's island port.

## 3. Wire format

### 3.1 Discovery (next_header 0, control payload[0])

All multi-byte fields big-endian. Signature and mac1 conventions are
the repository's standard ones:

- a **signature covers every byte before the appended `pub`**;
  `pub` comes right after the signed fields, `sig` after `pub`;
- the **mac1 tag** (16B, Poly1305, key = `mac1_key(40-bit dst of the
  frame)`) is appended last and covers everything before it — on
  client→concentrator messages only (concentrator replies carry the
  signature, which is strictly stronger; this mirrors DHCP69, where
  clients mac1 their DISCOVER/REQUEST and the server signs OFFER/ACK).

| code | name | direction | payload |
|---|---|---|---|
| 17 | PADI | host → broadcast | `[17][mac 6][mac1 16]` |
| 18 | PADO | ac → host (unicast) | `[18][mac 6][ac_mac 6][ac_addr 5][pub 32][sig 64]` |
| 19 | PADR | host → ac (unicast) | `[19][mac 6][pub 32][sig 64][mac1 16]` |
| 20 | PADS | ac → host (unicast) | `[20][mac 6][sid 2][pub 32][sig 64]` |
| 21 | PADT | either → other | `[21][sid 2][mac1 16]` (host→ac) / `[21][sid 2]` (ac→host) |

- `mac` is always the **host's control MAC** (the Ethernet src of its
  dial socket). Replies are filtered by it, exactly like DHCP69 clients
  filter by their MAC in the payload.
- `ac_mac`/`ac_addr`/`pub` in PADO teach the host where to send PADR
  (eth unicast + 40-bit unicast) and which key validates PADS.
- PADR is the admission point: `pub` must be allowlisted (`--peer`,
  `--peer-file`) or valid-and-learnable (`--learn`), and the signature
  over `[19][mac]` proves the host owns that key.
- Concentrator replies (PADO/PADS) keep the DHCP69 server convention:
  the **IPv69 dst is broadcast** even though the Ethernet frame is
  unicast to the host's control MAC — the client filters by payload
  MAC, so no address check is needed on either side.

Outer addresses: the concentrator's 40-bit address is identity-derived
(default class A — a private island service like DHCP69; `--class`
overrides). The host sends PADI with src `0` (unconfigured, like the
DHCP DISCOVER) and PADR/PADT unicast to the AC address it learned.

### 3.2 Session (next_header 3)

```
outer IPv69 frame (host ↔ ac):
  eth src  = sender MAC        eth dst = ac MAC (host→ac) / host control MAC (ac→host)
  ipv69 src= 0 / ac addr       ipv69 dst= ac addr / broadcast
  next_header = 3
  payload = [sid 2 BE][full inner IPv69 frame: eth 14 + ipv69 32 + payload]
```

The inner frame is the original frame **unchanged** — the same unit the
UDP tunnel gateway carries in a datagram. The concentrator routes by
inner destination and, when it puts a host's frame on its L2 leg,
rewrites only the inner Ethernet **src** to the session's *wire MAC*
(3.3). No mac1/signature on session frames: the inner frames carry the
stack's own protection (signed announces, authenticated dgrams, ICSP
crypto); per-session data crypto is a later phase (see Security).

### 3.3 The session's identity on the wire (MAC learning)

A session has two MACs:

- **control MAC** — the Ethernet src of the host's PADI/PADR. Used for
  discovery replies and as the outer dst of ac→host frames (it is the
  address of the host's real NIC, so the NIC accepts those frames).
- **wire MAC** — learned from the **inner** frames' Ethernet src (the
  host's TAP MAC when the session is exposed via `ip69p0`). When the AC
  bridges a host's frame to its L2 leg it rewrites the inner src to the
  wire MAC, so the whole island sees the host as that MAC: the DHCP69
  server binds the lease to it, peers reply unicast to it, and the AC
  catches those replies (promiscuous mode) and wraps them into the
  session. Same learning a real Ethernet switch port does.

## 4. Concentrator behavior

### 4.1 Discovery state machine

```
PADI (bcast) ──► PADO (unicast: ac_mac, ac_addr, pub)
PADR (signed) ─► [identity ok?] ─► PADS (sid)      or silent drop
PADT (either) ─► session freed, sid reusable
```

- PADI/PADR/PADT pass the mac1 pre-auth filter and the per-MAC token
  bucket first (same discipline as `dhcpd`); garbage is dropped
  silently before any Ed25519 work.
- PADR is checked against `--peer`/`--peer-file`; with `--learn` an
  unknown-but-valid key is registered (appended to the peer file, like
  `dhcpd --learn`) and accepted. No flags = open network (any valid
  signature).
- One session per control MAC. A second PADR from the same MAC gets
  PADS with the existing session id (idempotent re-dial). Max 64
  sessions; sessions idle for 300s are reaped with a PADT.
- The concentrator needs its own identity (auto-created keyring
  `~/.hosts69/key`, like `dhcpd`); `--key <hex>` overrides. The PADO
  pub + signed PADS let the host verify it is really talking to the AC
  it dialed; `--ac-pub <hex>` on the host pins the AC out-of-band
  (rogue-AC protection, like `--server-pub` for DHCP).

### 4.2 Bridging rules

Each received frame is classified in order:

1. **Ethernet src == own MAC** → ignore (Npcap echoes the AC's own TX).
2. **`next_header 3`, eth dst == own MAC** → session data from a host:
   unwrap by outer eth src (control MAC) → process inner.
3. **Discovery control** (PADI/PADR/PADT) → state machine above.
4. **ND_REQUEST (code 1)** from the L2: target address owned by a
   session or by the AC itself → answer with an ND_REPLY (the stack's
   first ND responder — makes duplicate-address detection work for
   dialed hosts); target elsewhere → ignore.
5. **Inner 40-bit dst == a session's address** → wrap into that session
   (dialed A ↔ dialed B and L2-peer ↔ dialed-host unicast flows).
6. **Ethernet dst == a session's wire MAC with 40-bit dst broadcast** →
   wrap (the DHCP69 server's OFFER/ACK convention: eth unicast to the
   client MAC, IPv69 dst broadcast).
7. Anything else (other hosts' unicast, island broadcast) → ignored:
   the AC is not a hub and sessions do not receive island broadcast.

Inner frames from a session:

1. Learn/refresh the wire MAC (inner eth src) and the address (inner
   IPv69 src; plus a DHCP69 REQUEST/ACK snoop for the case where the
   src is still 0 during lease acquisition).
2. **ND_REQUEST with src 0** (a lookup/DAD): target owned by another
   session or the AC → proxy ND_REPLY straight back into this session;
   target owned by this same session → ignore (self-check). **Signed
   ND_REQUEST** (src != 0, the cryptokey announce) → bridge to L2 so
   an island gateway learns the host.
3. **Broadcast inner** (DHCP DISCOVER etc.) → bridge to the L2 leg
   (eth src rewritten to the wire MAC).
4. **Unicast inner, 40-bit dst owned by another session** → rewrap into
   that session (never emitted on the L2).
5. **Unicast inner, dst = the AC's own address** → ignored in v0.1
   (the AC is not a service endpoint yet).
6. Otherwise (an island host) → bridge to the L2 leg with eth src = the
   wire MAC.

Because hosts on an island reach each other with broadcast Ethernet +
the 40-bit dst filter, the two wrap triggers (rules 5 and 6) cover all
inbound traffic: datagrams and ICSP INITs addressed to a dialed host
(40-bit dst = session addr, eth broadcast) and DHCP69 replies (eth
unicast to the wire MAC, 40-bit dst broadcast).

### 4.3 Promiscuous mode

Catching frames addressed to a wire MAC (DHCP replies, ICSP unicast
replies) requires promiscuous mode on the AC's interface. Npcap opens
promiscuous by default; the POSIX backend gained `l2_set_promisc()`
(AF_PACKET `PACKET_MR_PROMISC`), which the AC enables on open.

## 5. Host behavior (dial)

```
PADI (bcast, 3 tries, backoff) ──► PADO ──► PADR (signed) ──► PADS ──► session
```

- Identity from the keyring (required — PADR is signed). `--ac <addr>`
  targets one concentrator; without it the first valid PADO wins.
  `--ac-pub <hex>` pins the AC key (otherwise the PADO pub is used to
  validate PADS).
- On session up, the host creates the TAP (`--tap NAME`, default
  `ip69p0`) and forwards frames in both directions:

```
app (ipv69 dhcp/recv/send/icsp on ip69p0)
        │  full IPv69 frames
   /dev/net/tun (tap ip69p0)
        │
   host loop: unwrap [sid][inner] ◄──┐  wrap [sid][inner] ──►
        │                            │
   raw L2 socket on the dial iface ──┴──► ac (outer eth dst = ac_mac)
```

- Frames with Ethernet src == own MAC are ignored (Npcap TX echo).
- Ctrl-C sends a best-effort PADT and exits; the AC reaps dead sessions
  by idle timeout if the host vanishes.

## 6. Addressing inside the session

The session is transparent to addressing, so both models work
unchanged:

```
dialed host on a private island:
  ipv69 dhcp ip69p0        # DHCP69 runs INSIDE the session: the AC bridges
                           # DISCOVER to its L2, the island dhcpd leases to
                           # the host's wire MAC, OFFER/ACK come back through
                           # the session (class A pool)
dialed host with identity:
  ipv69 addr --class C     # identity-derived; no DHCP anywhere
```

The concentrator learns the address by observing the inner frames, so
its ND proxy and its session→session rewraps work for both models.

## 7. CLI

```
ipv69 pppoe ac [ifname] [--peer HEX]... [--peer-file F] [--learn]
               [--key HEX] [--class A|B|C]
ipv69 pppoe host [ifname] [--ac ADDR] [--ac-pub HEX] [--tap NAME] [--key HEX]
```

`[ifname]` is optional everywhere (auto = default-route interface, same
rule as send/recv/icsp). `ac` is portable (Linux + Windows); `host`
needs TAP and reports "not supported on Windows" there, like `tun`.

### Example: two hosts on one access segment, island with dhcpd

```bash
# island edge (e.g. the VM, wired side of the segment):
sudo ./ipv69 dhcpd eth0 --peer-file /home/kali/peers.txt
sudo ./ipv69 pppoe ac eth0 --peer-file /home/kali/peers.txt
./ipv69 recv eth0 00.00.00.00.10:16        # an island listener

# host A (e.g. the phone chroot, over Wi-Fi):
export PATH=/usr/bin:/bin HOME=/root
/root/bin/ipv69 pppoe host wlan0 --tap ip69p0
#   host: PADI -> PADO ac=... -> PADR -> PADS sid=N
#   host: session N up via ip69p0 — now use the stack as if local:
/root/bin/ipv69 dhcp ip69p0                # lease from the island dhcpd
/root/bin/ipv69 send ip69p0 00.00.00.00.10:16 "oi"
/root/bin/ipv69 recv ip69p0 <lease>:16
```

### Example: veth E2E (the standard test pattern)

```bash
# netns: v0 = island (dhcpd + ac + recv), v1 = access side (dial)
sudo ip link add v0 type veth peer name v1
sudo ip link set v0 up && sudo ip link set v1 up

# island (v0):          # access side (v1):
ipv69 dhcpd v0          ipv69 pppoe host v1          # session up, tap ip69p0
ipv69 pppoe ac v0       ipv69 dhcp ip69p0            # lease via the session
ipv69 recv v0 00.00.00.00.10:16
                        ipv69 send ip69p0 00.00.00.00.10:16 "oi"
```

The island `recv` sees the dialed host's datagram; the dialed host can
`recv ip69p0 <its lease>` and receive datagrams sent from the island —
DHCP, datagrams and (with a second dialed host) session-to-session
traffic all work through the AC without any change to the existing
tools.

## 8. Security considerations

- **Admission is the point**: no valid allowlisted signature, no
  session. This is stronger than cryptokey routing because it happens
  before any data path exists.
- mac1 + per-MAC token buckets protect the discovery state machine from
  cheap CPU exhaustion (same as `dhcpd`).
- PADO carries the AC pub and PADS is signed: a host can verify it
  dialed the AC it meant (`--ac-pub` pins it out-of-band).
- **Session frames are not encrypted in v0.1** — the session provides
  isolation (unicast-only, no island broadcast) and admission, not
  confidentiality. On a shared medium an observer sees the inner frames
  addressed to a wire MAC. Confidentiality is the stack's job at the
  layers above (authenticated datagrams, ICSP secretbox) exactly as it
  is for two plain L2 hosts; per-session link crypto is planned (see
  roadmap).
- The AC trusts the inner src after admission (L2 semantics — spoofing
  the wire MAC of a session requires being on the segment, same as any
  L2 spoof).

## 9. v0.1 scope and roadmap

Implemented in v0.1 (this spec, matching the code):

- discovery PADI/PADO/PADR/PADS/PADT over the control channel
  (mac1 + Ed25519 admission, `--peer`/`--peer-file`/`--learn`);
- session transport (`next_header 3`, `[sid][inner frame]`), host side
  exposed as a TAP (`ip69p0`) so the whole existing stack runs over the
  session;
- concentrator bridging: host ↔ island L2, session ↔ session, DHCP69
  through the session, ND proxy/DAD support, idle reaping;
- Linux host + Linux/Windows concentrator.

Not in v0.1 (next phases):

- **session over a UDP carrier** — dial a remote island's AC through
  the internet (`--remote`/gateway file): the session unit is already
  carrier-agnostic, and the host TAP then works from anywhere
  (the "join my home island" path);
- AC acting as a service endpoint (echo/ping to the AC itself) and
  integration with `gw` (the AC as an access leg of the gateway);
- per-session link crypto (session key from the PADR ECDH-style
  exchange) and keepalive between host and AC;
- multi-session hosts (several sessions per control MAC), service-name
  tags, Windows host (Npcap has no TAP; the session would terminate in
  a userspace socket like the tunnel does).

## 10. References

- RFC 2516 — A Method for Transmitting PPP Over Ethernet (PPPoE)
- RFC 1661 — The Point-to-Point Protocol (PPP) — the parts PPPoE69
  deliberately does not carry
- docs/network-architecture.md — the island/gateway model this slots
  into (the AC is the access edge of an island)
- docs/dhcp69-spec.md — the control-channel and signature conventions
  PPPoE69 reuses
