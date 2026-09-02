# IPv69 — Usage guide

Experimental protocol of its own (EtherType `0x6969`, 40-bit addresses)
with DHCP69 (automatic address configuration) and Ed25519
authentication. Everything runs on L2 — no IP, no router, no internet.
No kernel module: the AF_69 socket family was removed; every tool uses
the portable raw L2 backend (AF_PACKET on Linux, Npcap on Windows).

```
┌─────────────────┐   Wi-Fi / Ethernet cable     ┌─────────────────┐
│  phone (raw)    │ ───────────────────────────▶ │  Kali VM (raw   │
│  no module      │ ◀─────────────────────────── │  AF_PACKET)     │
└─────────────────┘                               └─────────────────┘
```

## What is what

**One binary, git-style subcommands.** `ipv69` dispatches by the first
argument (no legacy aliases):

```
ipv69 gw       tunnel gateway                     [--port N] [--iface eth0]
ipv69 tun      interface daemon: TAP + address   (Linux only)
ipv69 addr     identity-derived address          [--dad]
ipv69 keygen   generate Ed25519 key pairs
ipv69 dhcpd    DHCP69 server (private networks)
ipv69 dhcp     DHCP69 client
ipv69 send/recv/ping
ipv69 lease/renew/status                         (Linux only)
```

| Subcommand | Role | Where it runs |
|---|---|---|
| `ipv69 dhcpd` | **DHCP69 server** (private networks only: pool, allowlist, signed leases) | VM / any host |
| `ipv69 recv/send/ping/dhcp` | Generic client over raw L2, **no module** | phone (arm64), VM, Windows |
| `ipv69 keygen` | Generates Ed25519 key pairs | any host |
| `ipv69 tun` | Interface daemon: holds a DHCP address and creates the `ip69-0` TAP | Linux (phone/VM) |
| `ipv69 lease/renew/status` | Queries `ip69d` (like `ip addr` for IPv69) | same host as ip69d |
| `ipv69 gw` | **Tunnel gateway**: bridges IPv69 frames over UDP so clients behind NAT can join through any host with a public IP (multi-gateway, P2P) | any host with a public IP |

Besides the binaries, the project has a **separate crypto library**:

| Path | What it is |
|---|---|
| `lib/ed25519/include/ed25519.h` | Public API (keypair, sign, verify, keyfile) |
| `lib/ed25519/src/` | Implementation (`ed25519.c` + `tweetnacl.c` + `randombytes.c`) |

It depends on nothing from IPv69 — reusable in any project (your future
"own HTTPS", for example). Details in section 8.

## Addresses and ports

- Addresses: 40-bit, format `00.00.00.00.10` (5 octets), IPv4-style classes
  (first octet ranges; the rest `xx` is any value):
  - `00.xx.xx.xx.xx`–`3f.xx.xx.xx.xx` **class A** — private local (LAN, DHCP pool)
  - `40.xx.xx.xx.xx`–`7f.xx.xx.xx.xx` **class B** — private extended (VPN / multi-site)
  - `80.xx.xx.xx.xx`–`bf.xx.xx.xx.xx` **class C** — public (internet, via gateway)
  - `c0.xx.xx.xx.xx`–`df.xx.xx.xx.xx` **class D** — multicast
  - `e0.xx.xx.xx.xx`–`ff.xx.xx.xx.xx` **class E** — reserved (broadcast `ff.ff.ff.ff.ff`)
  - `00.00.00.00.01` = DHCP server (reserved, class A)
  - `00.00.00.00.10`–`00.00.00.00.fe` = DHCP pool (default, class A)
  - identity-derived: `ipv69 addr [--class A|B|C]` (default C = public, first octet 80–bf)
- Ports: **decimal**, glued to the address as `addr:port`
  (e.g. `00.00.00.00.10:16` = address `.10`, port 16; no leading zeros)
- `next_header`: `0` control (DHCP/ND/echo), `1` dgram, `2` stream (reserved)

---

## 1. Keys (SSH-style, automatic)

Each device has ITS OWN key in `~/.hosts69/` (like `~/.ssh`). **The
private key never leaves the device**; the server only knows
**public** ones (not a secret).

### Auto-key (recommended)

All clients and the server generate the key on first run and store it
in `~/.hosts69/key` (+ `~/.hosts69/key.pub`). Run once and copy the
PUBKEY it prints:

```bash
export HOME=/root          # important in the phone chroot!
/root/bin/ipv69 dhcp wlan0      # first run: generates the key and prints:
#   key generated at /root/.hosts69/key
#   register this PUBKEY on the server:
#   616833cf40e2708d42db3626c1a8e7f7434dc5bfcd2f004c5b6d4ec541379822
```

From the second run on it loads `~/.hosts69/key` and uses the same
identity — like `~/.ssh/id_ed25519`.

### ssh-keygen style (name + passphrase)

```bash
# create a key with a comment (name) and a passphrase, like ssh-keygen:
./ipv69 keygen -f ~/.hosts69/key -C "meu-servidor" -N "minha-senha"
#   Enter passphrase (empty for no passphrase):   ← prompted if -N omitted
#   Enter same passphrase again:                  ← typed with NO echo

# without -N and with a tty, the passphrase is prompted twice (no echo),
# retrying until they match — identical to ssh-keygen.
```

The private key file starts with `H69E1` when encrypted (XSalsa20-
Poly1305, key derived from the passphrase); `key.pub` holds
`<pubkey_hex> <comment>`. `--key <privkey_hex>` on the CLI still works
for the legacy/manual flow — but no longer needed.

### Manual (optional)

```bash
./ipv69 keygen 2
<privkey_hex> <pubkey_hex>      # line 1: device A (e.g. phone)
<privkey_hex> <pubkey_hex>      # line 2: device B (e.g. server/VM)
```

Then just pass `--key <privkey_hex>` (and `--server-pub <pubkey_hex>`
on clients) — auto-key is bypassed when `--key` is given.

---

## 2. Starting the DHCP server (VM)

### Auto-registration (`--learn`) — zero manual setup

```bash
# the server accepts any pubkey with a valid signature and registers
# it by itself (append to --peer-file, if given). Its own key comes
# from ~/.hosts69/key automatically (passphrase via IPV69_PASSPHRASE
# or prompted on the tty) — no --key needed:
sudo ./ipv69 dhcpd eth0 --raw --peer-file /home/kali/peers.txt --learn

# log:
#   af69d: keyring /root/.hosts69/key (servidor)
#   af69d: learned pub 8566295b... from MAC 00:08:22:9c:03:fc -> registered in peer-file
#   af69d: DISCOVER 00:08:22:9c:03:fc -> OFFER 0000000000000010
#   af69d: REQUEST 00:08:22:9c:03:fc -> ACK 0000000000000010
```

The phone runs `dhcp wlan0` and done — no hex copying at all.
`--learn` without `--allow` is an **open network** (anyone with a key
gets in); with `--allow MAC...` it restricts learning to the listed
MACs only.

### With a peers file (closed — automatic reload)

```bash
# 1) create the file with the allowed PUBKEYs (one per line):
echo '616833cf40e2708d42db3626c1a8e7f7434dc5bfcd2f004c5b6d4ec541379822' > /home/kali/peers.txt

# 2) start the server pointing at it:
sudo ./ipv69 dhcpd eth0 --raw --peer-file /home/kali/peers.txt \
     --key <server_privkey_hex>
```

**Adding a new device = editing the file.** The server notices the
change by itself (checks the file mtime every ~1s) and starts accepting
the new pubkey — no restart, no signal:

```bash
echo 'another_pubkey_hex' >> /home/kali/peers.txt   # takes effect right away
```

### With a single key on the command line

```bash
sudo ./ipv69 dhcpd eth0 --raw \
     --allow 00:08:22:9c:03:fc \        # (optional) allowed MACs
     --peer  <phone_pubkey_hex> \       # only this pub gets in
     --key   <server_privkey_hex>       # signs OFFER/ACK (anti rogue)
```

Expected log:

```
af69d: raw AF_PACKET (ifindex 2), pool 0000000000000010-00000000000000fe lease 3600s
af69d: allow=1 mac(s), peers=1 pubkey(s), server-key=yes
af69d: DISCOVER 00:08:22:9c:03:fc -> OFFER 0000000000000010
af69d: REQUEST 00:08:22:9c:03:fc -> ACK 0000000000000010
```

Rejections look like this:

```
af69d: pub f38f9008... not in allowlist -> ignored
af69d: 00:08:22:9c:03:fc invalid signature/pubkey -> ignored
```

> `--raw` is required when the AP/router filters wired→wireless
> broadcast (replies go unicast to the client MAC).
> Custom pool: `af69d eth0 00.00.00.00.10 00.00.00.00.fe 3600 --raw ...`

---

## 3. Phone: get an address and talk

Inside the Nethunter chroot (Kali arm64):

```bash
export PATH=/usr/bin:/bin
export HOME=/root

# 1) request an address (uses the automatic key from ~/.ipv69/key):
/root/bin/ipv69 dhcp wlan0 --server-pub <server_pubkey_hex>

# output:
#   dhcp: OFFER 0000000000000010 lease 3600s
#   dhcp: ACK 0000000000000010 — configured!
#   dhcp: bound src=0000000000000010, listening 5s...
```

After configuration, the address is **per-socket**: whoever wants to
"own" `.10` needs a process bound to it (the `dhcp` holds it for 5s).
To keep the address alive, use the daemon:

```bash
# holds the address + creates the TAP interface ip69-0 (auto-key):
sudo /root/bin/ipv69 tun wlan0 --raw --tap ip69-0 \
    --server-pub <server_pubkey_hex>

# in another terminal, query like `ip addr`:
/root/bin/ipv69 status
#   1: ip69-0: <BROADCAST,UP,LOWER_UP> mtu 1500 state UP
#       inet69 0000000000000010/40 brd ffffffffff scope global dynamic
#          valid_lft 3599sec preferred_lft 3599sec

/root/bin/ipv69 lease       # seconds remaining
/root/bin/ipv69 renew       # renew (or SIGUSR1 to ip69d)
```

Sending data — the `src` is **automatic** (anti-spoofing): the send
discovers your real address via a silent DHCP before transmitting
(it also registers the kernel binding for your MAC), or derives it
from the identity when using `--remote`. Ports are **decimal, glued to
the address** (`addr:port`):

```bash
# send dgram: dst:port + src_port (decimal; src is automatic):
/root/bin/ipv69 send wlan0 00.00.00.00.10:16 1 "hi"
#                          ^dst:port(16)   ^src_port(1)
#   send: src = lease 0000000000000010 (auto)

# listen on your address and port (decimal). Without an address the
# recv discovers the lease itself (silent DHCP) — recv wlan0 is enough:
/root/bin/ipv69 recv wlan0
/root/bin/ipv69 recv wlan0 00.00.00.00.10:16

# ping (echo request → reply from the VM module):
/root/bin/ipv69 ping wlan0 00.00.00.00.02 "hi"
```

---

## 4. VM: talk to the phone

```bash
# on the VM, with the module loaded:
./ipv69 test recv 2 00.00.00.00.10:16     # listen on the phone's address, port 16
./ipv69 test send 2 00.00.00.00.10:16 1 "hi phone"   # dst:port + src_port, decimal
./ipv69 test ping 2 00.00.00.00.10 "hi"   # echo request

# without the module (raw, like the phone):
./ipv69 recv eth0 00.00.00.00.10:16
./ipv69 send eth0 00.00.00.00.10:16 1 "hi"
```

> `ifindex`: `2` = eth0 (check with `ip -o link`). In af69_test the
> first arg is the **numeric ifindex**; in af69_raw it is the
> interface **name**.

---

## 5. Security (summary)

| Layer | What it does | Who configures it |
|---|---|---|
| MAC allowlist (`--allow`) | only listed MACs get a lease | server |
| **Ed25519** (`--peer-file`/`--peer`/`--key`/`--server-pub`) | signs DHCP; a leaked device private key only kills that device; no shared secret | server + clients |
| Lease binding in the module (`IPV69_BIND_ADD`) | dgram only from an address with a valid lease and the right MAC; everything else dropped | automatic (af69d) |

Without `--peer`/`--peer-file`/`--key` DHCP has no crypto (only MAC
allowlist if `--allow` is given) — fine for a lab, not for a shared
network.

Details and wire format: `docs/security.md`.

---

## 6. Known pitfalls

- **chroot PATH**: always `export PATH=/usr/bin:/bin` before running
  (otherwise Android's `/system/bin` is used).
- **HOME in the chroot**: `export HOME=/root` — auto-key stores the key
  in `~/.ipv69/key`; without HOME it goes somewhere unexpected.
- **Ports are decimal, glued to the address**: `recv wlan0 00.00.00.00.10:16`
  = port 16; the frame shows `ports=1/16` in decimal.
- **src on send**: automatic now (anti-spoofing) — `send` discovers the
  real lease via silent DHCP (local) or derives it from the identity
  (`--remote`); passing a manual src is rejected. With binding active on
  the receiver, a forged src would be a silent drop anyway.
- **Wired→wireless broadcast**: many APs filter it; use `--raw` on the
  server (unicast) or test VM↔phone through the same router port.
- **Ethernet padding**: short frames arrive with padding (60B minimum)
  — the module accepts it (fix included).
- **No module on the phone**: stock kernel 4.19 (AF_MAX=45) has no
  AF_69 — that is why the phone uses `af69_raw` (AF_PACKET, same wire
  format).
- **Module in use on WSL**: `rmmod af69` fails if an AF_69 socket is
  open — kill the processes (`pkill -f 'build/ip69[d]'`) first.

---

## 7. Internet: tunnel gateway (multi-gateway, P2P)

`ipv69 gw` bridges IPv69 L2 frames over UDP, so devices behind NAT can
join through any host with a public IP. No single gateway is required —
clients keep a list and fail over. See `docs/network-architecture.md`.

```bash
# on the gateway (any host with a public IP):
./ipv69 gw --port 6969
# optional: bridge to a local L2 interface (e.g. where dhcpd runs):
sudo ./ipv69 gw --port 6969 --iface eth0
```

Clients use `--remote` with one or more gateways (numeric IPs; static
binary has no DNS):

```bash
# listen via the tunnel (address derived from the identity, announced
# to the gateway so it can be reached):
./ipv69 recv wlan0 --remote 203.0.113.10:6969

# send via the tunnel: the gateway relays it, or answers QUERY with the
# peer's endpoint and the frame goes direct (P2P, gateway leaves path).
# src is derived from the identity automatically; dst:port in decimal:
./ipv69 send wlan0 <dst_addr>:16 1 "hi" \
    --remote 203.0.113.10:6969,203.0.113.11:6969
```

Identity-derived address (no DHCP). Classes are IPv4-style: class C
(public, default) for the internet, A/B (private) for local/VPN:

```bash
./ipv69 addr                 # print the address derived from your key (class C)
./ipv69 addr --class B       # private extended (VPN)
./ipv69 addr --class A       # private local (LAN)
./ipv69 addr --dad           # ... and check for collision (ND request)
```

The gateway is the class guard: without `--private` only public class C
crosses it (private never leaks to the internet); with `--private`,
class A/B also route (private VPN over the internet).

### Cryptokey routing (WireGuard-style)

The gateway never trusts a source address: it learns each peer's range
ONLY from authenticated traffic — a signed ICSP INIT (handshake) or a
signed ND announce (`recv`/`send --remote` sign theirs) — then validates
every datagram's src against the learned ranges with a hash lookup
(zero per-packet crypto). Forged src frames are dropped silently.

```bash
# allowlist (like WG peers): only these identities may send. The range
# is derived from the key (class C); /prefix narrows it (AllowedIPs):
sudo ./ipv69 gw --port 6969 --iface eth0 \
    --peer <PUBKEY_A> --peer <PUBKEY_B/32>
# without --peer: open mode — any valid signature is learned (rate
# limited per MAC, table evicts LRU)
```

The gateway still answers QUERY ("where is addr?") with the peer's
endpoint for P2P, relays unicast, replicates broadcast (split horizon:
never back to the sender's endpoint; token bucket per source) and rate
limits peer learning. L2-learned peers have no UDP route: a QUERY the
local table cannot answer is forwarded to the gateway mesh instead.

### Gateway mesh (federated gateways on one L2)

Gateways with `--iface` on the same L2 segment announce themselves
(GW_ANN, every 30s + retries at boot), learn each other, and forward
QUERYs between themselves (GW_Q/GW_R): a client behind gateway A finds
a client behind gateway B — the answer relays back to the asker and the
datagram goes P2P, gateway-free:

```bash
# two gateways bridging the same L2 (e.g. two routers on one LAN):
sudo ./ipv69 gw --port 6969 --iface eth0
sudo ./ipv69 gw --port 6969 --iface eth0   # another host, same segment
```

---

## 8. Build

```bash
make ipv69                                   # single binary (all subcommands)
make chat                                    # ICSP chat example (standalone)
make win                                     # Windows: ipv69.exe + chat (MinGW+Npcap)
# arm64 (phone):
aarch64-linux-gnu-gcc -O2 -static -Iinclude -Ilib/ed25519/include \
    -o ipv69_arm64 src/IPv69/main.c src/IPv69/parse.c src/IPv69/af69d.c \
    src/IPv69/ipv69gw.c src/IPv69/ip69d.c src/IPv69/ip69.c src/IPv69/keygen.c \
    src/IPv69/keyring.c tests/af69_raw.c \
    lib/ed25519/src/ed25519.c lib/ed25519/src/tweetnacl.c lib/ed25519/src/randombytes.c
```

---

## 9. The `ed25519` library (for other projects)

The crypto lives in `lib/ed25519/` **separate from the protocol** —
IPv69 consumes the same API you would use in your "own HTTPS". Nothing
there depends on AF_69, header.h or the kernel.

```c
#include "ed25519.h"

uint8_t seed[ED25519_SEED_LEN], sk[ED25519_SK_LEN], pk[ED25519_PUB_LEN];
uint8_t sig[ED25519_SIG_LEN];

ed25519_keypair(sk, pk);                          // sk[0..31]=seed, sk[32..63]=pub
ed25519_seed_to_pub(pk, seed);                    // derive pub from an existing seed
ed25519_sign(sig, msg, msglen, sk);               // sk = seed (derives the pub internally)
ed25519_verify(msg, msglen, sig, pk) == 0;        // 0 = valid signature

// SSH-style persistence (~/.ipv69/key, hex seed, mode 0600):
char path[256];
ed25519_keyfile_default_path(path, sizeof(path));
ed25519_keyfile_load_or_create(sk, path);         // 1 = generated and printed the new pub
```

Compile against the library (without the project Makefile):

```bash
gcc -O2 -Ilib/ed25519/include -o my_app my_app.c \
    lib/ed25519/src/ed25519.c lib/ed25519/src/tweetnacl.c lib/ed25519/src/randombytes.c
```

Notes:
- Signing ~1.7ms (x64) / ~7.4ms (arm64 A53) for small messages.
- The private key is the **seed** (32B hex in the keyfile); the pub is
  derived from it.
- `tweetnacl.c` is CC0/public domain (TweetNaCl 20140427); `ed25519.c`
  is the wrapper with the clean API (separate sig, independent buffers).

---

## 10. Example tool: ICSP chat (`make chat`)

`build/icsp_chat` is a **standalone example** (NOT part of the `ipv69`
binary) showing how to build a tool on the ICSP API — authenticated
handshake, encrypted messages, multi-stream, heartbeat, graceful
close. Port syntax is `addr:porta` (decimal), like send/recv:

```bash
make chat        # builds build/icsp_chat separately

# server (address-less; :porta or plain port):
./build/icsp_chat server eth0 :6969 --peer <client_pub_hex>
./build/icsp_chat server eth0 6969

# client:
./build/icsp_chat client wlan0 00.00.00.00.01:6969

# every subcommand has built-in help: ipv69 help <cmd> or ipv69 <cmd> --help
# after connecting: type + Enter to send (stream 1); Ctrl-D closes
# gracefully. Both sides print the session key — identical on both =
# the authenticated ECDH handshake worked (nobody in the middle can
# read: each message is secretbox-encrypted with a TSN-derived nonce).
```

The example links only the ICSP core + keyring + ed25519 + l2.c —
read `examples/icsp_chat.c` as the template for your own ICSP tool.

---

## 11. Windows build (`make win`)

The **full `ipv69.exe`** (all subcommands) plus the ICSP chat build
natively on Windows with **MinGW + Npcap**. Architecture:

- `include/IPv69/plat.h` — socket layer: `sock_t`, `plat_sock_init()`
  (WSAStartup, called from main), `plat_poll` (WSAPoll), `perror_sock`.
- `src/IPv69/l2_win.c` — libpcap backend for the portable `l2_*` API
  (the same one the Linux build uses on AF_PACKET).
- `addr`, `keygen`, `dhcpd`, `dhcp`, `send`, `recv`, `ping`, `gw`,
  `icsp` work. `tun`, `lease/renew/status`, `test` report
  "nao suportado no Windows" (they need TAP, unix sockets or the AF_69
  kernel module); `gw --iface` too.
- RNG is BCrypt, the keyring uses `%USERPROFILE%` and a console no-echo
  prompt, `--remote` tunnels use Winsock.

```bash
# requirements: MinGW gcc on PATH, Npcap installed, Npcap SDK unpacked
#   to C:/Users/<you>/npcap-sdk (https://npcap.com/dist/npcap-sdk-1.13.zip)
make win        # -> build/ipv69.exe + build/icsp_chat.exe

# run from WSL: pass HOME (WSL interop does NOT forward it) and the
# adapter is matched by substring of the friendly name:
WSLENV=HOME HOME='C:/Users/you' ./build/ipv69.exe addr
./build/ipv69.exe dhcp "Host-Only"
./build/ipv69.exe send "Host-Only" 00.00.00.00.10:16 4242 oi
./build/icsp_chat.exe client "Host-Only" 00.00.00.00.01:6969
```

Windows notes (all validated this session):
- Npcap sees locally-injected frames — a client and a server on the
  SAME adapter connect fine (no AF_PACKET same-interface loopback issue).
- Npcap does **not** expose the Hyper-V `vEthernet (WSL)` adapter, so
  WSL2 <-> Windows over raw L2 is not possible — use the VM or two NICs.
- VirtualBox **bridged** mode does not forward Npcap-injected frames to
  the VM; **host-only** mode does (Windows <-> Kali VM full ICSP
  handshake + identical session keys, validated).

---

## 12. WireGuard-inspired hardening (P0-P3, all implemented)

DoS protection, session discipline, cryptokey routing, self-containment
and datagram auth — see `docs/wireguard-inspired-plan.md` for the full
design. Summary of what to type:

```bash
# bring a device up: keygen-if-missing + DHCP lease with backoff+jitter
./ipv69 net up wlan0

# datagram auth: MAC every frame with X25519(our key, dst pub).
# sender: --auth <dst PUBKEY>; receiver: --peer/--peer-file <trusted pubs>
./ipv69 send wlan0 <dst>:16 1 "hi" --auth <PUBKEY_DST>
./ipv69 recv wlan0 <my_addr> --peer-file /etc/ipv69/peers

# dhcpd allowlist with AllowedIPs-style ranges (key authorizes a range):
sudo ./ipv69 dhcpd wlan0 --raw --peer <PUBKEY_A> --peer <PUBKEY_B/28>

# gateway cryptokey routing + federation: see section 7
```

Under the hood:

- **mac1** (Poly1305, keyed by the dest addr): every INIT/DHCP control
  is MACed; servers verify before ANY signature/ECDH work (~us vs
  ~1.7ms) and drop garbage silently.
- **Per-sender token buckets** (table of 64, eviction): handshake,
  broadcast and peer-learning floods are throttled per MAC/endpoint —
  under load the excess is dropped without a reply (WG "silent").
- **Session discipline**: HKDF-SHA512 labels derive directional keys
  (send/recv); time-based rekey with jitter + zeroing of old keys; INIT
  carries a timestamp (anti-replay); data path has a 32-TSN sliding
  replay window; random initial TSN (SCTP-style).
- **Cryptokey routing**: gateway peers are (identity key, addr range,
  endpoint) learned from signed INITs/announces only; src validation is
  a range lookup — no per-packet crypto; `--peer PUB[/prefix]` is the
  allowlist (WG AllowedIPs); dhcpd allocates leases O(1) by MAC hash
  and lets a signed REQUEST claim any free address inside its range.
- **Gateway mesh**: GW_ANN discovery + QUERY forwarding between
  federated gateways on one L2 (P2P across gateways).

