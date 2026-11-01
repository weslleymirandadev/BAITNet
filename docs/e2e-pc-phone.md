# E2E battery: Windows PC <-> Android phone (same L2)

Two real hosts on one LAN, no gateway and no tunnel: the frames go over the
wireless/wired bridge of the router (EtherType `0x6969`), so this battery
exercises the protocol itself, not the UDP carrier.

```
  Windows PC  (AF_PACKET equivalent: Npcap)        Android phone (AF_PACKET)
  adapter "Realtek" / 192.168.100.6     ── LAN ──  wlan0 / 192.168.100.43
  c/build/ipv69.exe icsp_chat.exe bite.exe           /data/local/tmp/ipv69bench/
```

## Environment (fixed for every case)

| what | PC side | phone side |
|---|---|---|
| directory | `C:\Users\<you>\ipv69bench` (`/mnt/c/Users/<you>/ipv69bench`) | `/data/local/tmp/ipv69bench` |
| ifname | `Realtek` (substring of the Npcap/pcap device description — `"Ethernet 2"` is the Windows *name* and does NOT match) | `wlan0` |
| identity | `HOME=C:/Users/<you>/ipv69bench/<home>` (own `.hosts69` per track) | `HOME=/data/local/tmp/ipv69bench/<home>` |
| run as | plain exe, `WSLENV=HOME HOME='C:/Users/<you>/ipv69bench/<home>' ./ipv69.exe ...` | `adb shell su -c 'HOME=... /data/local/tmp/ipv69bench/ipv69 ...'` |

Rules that come from the platform, not from taste:

- **The phone must run the binaries from `/data/local/tmp` with an absolute
  path and `su -c`.** The Kali NetHunter chroot is not reachable from an
  `adb shell su` on every ROM (`chroot: Operation not permitted`) and
  `/data/local/nhsystem/...` is relabeled by SELinux; the static arm64
  binaries run directly on Android, so the chroot is not needed.
- **`HOME` must already exist** (`mkdir -p`) — the keyring creates
  `.hosts69/` but not the home directory itself; a missing home shows up as
  `could not load/create key at ...`.
- **One identity per track.** Same home = same key = same derived address
  (collides silently).
- **Ports are decimal and glued to the address** (`addr:1684`), and every
  test gets its own port range so two tracks can run at the same time.
- `--remote` and `~/.hosts69/gateways` are NOT used here: any gateway file in
  the home would switch the tools to tunnel mode. The tracks use fresh homes
  with no `gateways` file, i.e. plain local L2.
- Never hardcode addresses: read them from `ipv69 addr` and from the dhcpd
  log (`OFFER <addr>`) — the lease depends on the MAC binding.
- Server logs are only readable because the tools call
  `setvbuf(stdout, NULL, _IONBF, 0)`: MSVCRT treats `_IOLBF` as full
  buffering, so on Windows a redirected server log stayed empty until the
  process exited.

## Track A — IPv69 core (ports 18000-18019, homes `pca` / `pha`)

| id | case | setup | expected evidence |
|---|---|---|---|
| A1 | DHCP69 open network (`--learn`) | PC `dhcpd Realtek --learn`; phone `dhcp wlan0` | PC: `DISCOVER <mac> -> OFFER <addr>` + `REQUEST <mac> -> ACK <addr>`; phone: `dhcp: ACK <addr> — configured!` |
| A2 | DHCP69 closed (allowlist) | PC `dhcpd Realtek --peer-file peers.txt`; phone with the allowlisted key | same as A1 (signed OFFER/ACK) |
| A3 | DHCP69 rejects an unknown identity | same server, phone with a second home (`pha2`) | PC: `pub ... not in allowlist -> ignored` / `invalid signature/pubkey`; phone: no ACK |
| A4 | dgram phone -> PC | PC `recv Realtek <lease_pc>:18001`; phone `send wlan0 <lease_pc>:18001 hello-a4` | PC dump shows `src=... ports=<ephemeral>/18001` and the payload |
| A5 | dgram PC -> phone | phone `recv wlan0 <lease_ph>:18002` (background); PC `send Realtek <lease_ph>:18002 hello-a5` | phone dump shows the payload; PC prints `src = lease <addr> (auto)` |
| A6 | ping/echo phone -> PC | PC `recv`/idle; phone `ping wlan0 <lease_pc> hi` | phone: reply received (`pong`/`echo reply`), PC sees the request |
| A7 | DAD (`addr --dad`) | phone `addr --dad --class A` | no ND reply (documented gap: only the PPPoE AC answers ND on this tree) |
| A8 | PPPoE69 AC + host (optional) | PC `pppoe ac Realtek --learn`; phone `pppoe host wlan0 --tap ip69p0` | AC: `PADI/PADR ok`, session `sid`; host: TAP up. Needs `/dev/net/tun` on the phone |

## Track B — ICSP + BITE (ports 18020-18039 + 8080, homes `pcb` / `phb`)

| id | case | setup | expected evidence |
|---|---|---|---|
| B0 | ICSP CRC unit test (host only, no device) | `cc -O2 scripts/icsp_crc_test.c -Iinclude -Ilib/ed25519/include -o /tmp/crc_test && /tmp/crc_test` | `8 checks` pass, exit 0 |
| B1 | ICSP handshake + data, PC server / phone client, allowlisted | PC `icsp server Realtek :18021 --peer <phone_pub>`; phone `icsp client wlan0 <pc_addr>:18021 hello-b1` | both print the same `session_key`; client `sack=1` |
| B2 | ICSP reverse (phone server / PC client) | phone server (background) `icsp server wlan0 :18022 --peer <pc_pub>`; PC `icsp client Realtek <ph_addr>:18022 hi` | same evidence. If it fails, the failure is the phone receiving the broadcast INIT (Android managed mode) — report it, do not paper over it |
| B3 | ICSP rejects an unknown identity | server with `--peer` of another key; client with `phb2` | client: INIT-ACK never arrives / `peer not authorized` on the server; server keeps running |
| B4 | ICSP rekey in-session | client `--rekey 1` | logs `rekey started`, new `session_key` on both sides, `sack=1` after the rekey |
| B5 | ICSP lossy SACK path | server `--loss 30` | client retransmits (`retransmitted DATA`) and still ends with `sack=1` |
| B6 | ICSP chat relay (`icsp_chat`) | PC `icsp_chat server Realtek :18023 --peer <phone_pub>`; phone client with a piped line | server log `received N bytes ... "line"` |
| B7 | BITE GET by `.bait` name | PC `bite server Realtek --root www` (port 8080); phone `bite fetch <label>.bait/index.html` | `200`, body identical to the file |
| B8 | BITE negatives | phone `fetch <label>.bait/nope`, `fetch <label>.bait/../etc/passwd`, `POST` | `404`, traversal blocked (`400`/`404`, never the file), `405` with `Allow` |
| B9 | BITE `--head` | phone `fetch <label>.bait/index.html --head` | headers only, no body |
| B10 | BITE reverse (phone server / PC fetch) | phone `bite server wlan0 --root www`; PC `bite fetch <phone_label>.bait/` | `200` + body (same broadcast caveat as B2) |

## Running a case by hand

```bash
# PC side: server in the background, log in the bench dir
cd /mnt/c/Users/$USER/ipv69bench
WSLENV=HOME HOME='C:/Users/user/ipv69bench/pca' ./ipv69.exe dhcpd Realtek --learn > logs/A1_pc.log 2>&1 &

# phone side
ADB=/mnt/c/Users/user/AppData/Local/Android/Sdk/platform-tools/adb.exe
"$ADB" shell su -c 'HOME=/data/local/tmp/ipv69bench/pha /data/local/tmp/ipv69bench/ipv69 dhcp wlan0'

# addresses are discovered, never assumed:
WSLENV=HOME HOME='C:/Users/user/ipv69bench/pca' ./ipv69.exe addr | grep '^addr:'
"$ADB" shell su -c 'HOME=/data/local/tmp/ipv69bench/pha /data/local/tmp/ipv69bench/ipv69 addr' | grep '^addr:'
```

`pc.sh` / `phone.sh` in this directory wrap the two invocations
(`pc.sh <home> <tool> [args]`, `phone.sh <home> <tool> [args]`).

## Same host (one PC only): use the local UDP gateway

Two processes on the SAME machine and the SAME NIC cannot talk over raw L2:
a frame injected by one `AF_PACKET` socket is not delivered to another socket
of the same interface (the same class of limitation as the veth TX path), so
the receiver never sees the INIT. The supported way to test a client and a
server on one host is the UDP carrier with a local gateway — no root needed,
because a `gw` without `--iface` is pure UDP:

```bash
# 1) local gateway (user space, no root)
./build/ipv69 gw --port 16969 &

# 2) ONE IDENTITY PER SIDE — with a single ~/.hosts69/key both processes
#    derive the SAME address and the gateway cannot tell them apart (the
#    client overwrites the server's route and the INIT is relayed back to
#    the client). `keygen` refuses to overwrite, so the test keeps the same
#    identity across runs — but if a key IS regenerated its .bait label
#    changes with it, and an old label resolves to an address nobody owns
#    (the server still answers and bTLS then rejects the certificate:
#    "the certificate does not match <label>.bait").
[ -f ~/.hosts69/srv ] || ./build/ipv69 keygen --key-file srv -N srvpass
[ -f ~/.hosts69/cli ] || ./build/ipv69 keygen --key-file cli -N clipass
#    always take the label from the CURRENT key / the server banner:
IPV69_PASSPHRASE=srvpass ./build/ipv69 addr --bait --key-file srv

# 3) server (label printed at boot: dk2kgnnj...bait in this run)
IPV69_PASSPHRASE=srvpass ./build/bite server eth0 :18080 --root ./www \
    --remote 127.0.0.1:16969 --key-file srv

# 4) client — the .bait name plus the port, since :18080 is not the default
IPV69_PASSPHRASE=clipass ./build/bite fetch eth0 \
    dk2kgnnjdivpdwogdhxu6ed6rofnlywp.bait:18080/index.html \
    --remote 127.0.0.1:16969 --key-file cli
```

Validated output (2026-11-01): `INIT-ACK ok` -> `association established` ->
`bite: certificate matches ...bait` -> `status 200` + the file body, and on the
server `BITE /index.html -> 200 (21 bytes)`. Eight consecutive fetches against
one server gave 8x `status 200` and 8x `BITE /index.html -> 200`. The same
works for `ipv69 icsp server|client` by swapping the tool; only the identity
rule stays.

Notes from that run:

- The handshake retransmits: `icsp: no INIT-ACK — retry N/5` and
  `icsp: no COOKIE-ACK — retry N/5`. Without it a single lost first frame
  aborted the connection (~1 in 3 runs on the same-host gateway path).
- Start a **fresh** `ipv69 gw` for a test session. A gateway that has been
  running for a long time accumulates peers from previous runs and was
  observed not relaying to a still-announcing server (fresh gw: 8/8 fetches,
  stale gw: 1/3). Treat that as a gateway route-table bug still open.
- Consecutive fetches against the same `bite server` are fine (the serve loop
  re-accepts after SHUTDOWN), but the server handles one association at a
  time: a second client waits until the current association's idle window
  expires.

## Known limits of this topology

- Broadcast **wired -> wireless** is not delivered reliably by the access
  point (and is dropped entirely while the phone dozes): every unicast reply
  works. That is why the server roles are normally taken by the PC and the
  phone dials in — case B2/B10 below measures the other direction and it is
  flaky by construction, because the first ICSP INIT goes to broadcast.
- Android `wlan0` in managed mode only hands the driver unicast to its own MAC
  (and some broadcast), so the phone is not a reliable frame *sniffer*: use
  the protocol's own `recv` as the sensor, not tcpdump.
- No forwarding/mesh/federation case lives here: they need a third host or a
  public seed (`docs/network-architecture.md`, USAGE section 7).

## Run log 2026-11-01 (Windows PC "Realtek" / 192.168.100.6 <-> Moto G22 wlan0 / .43)

Two parallel tracks, disjoint ports and identities, no tunnel.

| case | result | evidence |
|---|---|---|
| A1 DHCP69 open | PASS | PC: `DISCOVER 00:08:22:9c:03:fc -> OFFER 000000000000009e` / `REQUEST ... -> ACK`; phone: `dhcp: ACK 000000000000009e — configured!` |
| A2 DHCP69 closed (`--peer-file`) | PASS | PC: `peer-file peers_a.txt: 1 pubkey(s)`, `peers=1 ... learn=no`, same OFFER/ACK |
| A3 unknown identity rejected | PASS | PC: `pub 8e9b2839... not in allowlist -> ignored` (3x), phone never ACKed |
| A4 dgram phone->PC | PASS | PC: `... nh=1 ports=50306/18001 payload(8)=hello-a4` |
| A5 dgram PC->phone | PASS | phone dump showed the payload; PC printed `src = lease 0000000000000070 (auto)` |
| A6 ping/echo | PASS (after fix) | phone: `ping: src = lease 000000000000009e (auto)` + `reply from 0000000000000070: hi-a6c`; PC: `recv: echo reply -> 000000000000009e` |
| A7 DAD | PASS (after fix) | `l2: auto interface = wlan0`, `dad: address free` |
| A8 PPPoE69 AC + host | PASS | AC: `PADI ... -> PADO`, `PADR ... -> session 1`; host: `PADS sid=1`, `session 1 up via ip69p0` |
| B0 CRC unit test | PASS | `make crc` -> 8/8 OK |
| B1 ICSP handshake + data | PASS | both sides `session_key=3e5225a1...d5f9`; server `received 8 bytes (stream 1): "hello-b1"`; client `sack=1` |
| B2 ICSP phone as server | PASS (transient) | phone: `INIT ok -> INIT-ACK`, `association established!`; repeats later timed out (see limits) |
| B3 allowlist rejection | PASS | unauthorized `INIT-ACK: Connection timed out`; authorized client then established |
| B4 rekey | PASS | server: `rekey ok! new session_key=35dab83c...` / `9c40ba94...` |
| B5 lossy SACK | PASS | `--loss 30`: `retransmitted DATA`, client still `sack=1` |
| B6 chat relay | PASS | server log: `hello-b6` delivered over stream 1 |
| B7 BITE GET by label | PASS | `bite: certificate matches hsl4...bait`, body `marker-b7-ok`, `status 200` |
| B8 BITE negatives | PASS | `/nope` -> `status 404`; `/../etc/passwd` -> `status 400` (traversal blocked) |
| B9 BITE `--head` | PASS | `BITE/1.0 200 OK` + `Content-Length: 87`, no body |
| B10 BITE phone as server | FAIL | PC `INIT sent` then `INIT-ACK: timed out`; the phone server never logged an INIT. Same result with a plain `icsp server` on any port — the INIT is broadcast from the wire and the AP/driver does not hand it to the phone (verified `mWakefulness=Dozing` drops it entirely; a fresh wake sometimes delivers it) |

Defects found and fixed during the run:

1. `c/src/IPv69/pppoe69.c` — the ND_REPLY MAC was written at `+7` instead of
   `+6` (1-byte stack overflow and a malformed reply) in all three sites.
2. `c/tests/af69_raw.c` — nothing in the tree answered ECHO_REQUEST, so `ping`
   could never work; a bound `recv` now replies unicast, and `ping` no longer
   sends the reserved `00.00.00.00.01` as src (lease / identity instead).
3. `c/tests/af69_raw.c` — `addr --dad` used `argv[2]` as the ifname, so
   `ipv69 addr --dad` tried to open an interface called "--dad"; the ifname is
   now the first non-flag argument (omitted = auto).
4. `c/tests/icsp_test.c`, `c/tests/btls_test.c`, `c/examples/{icsp_chat,bite,icsp_hub}.c`
   — `setvbuf(_IOLBF)` is full buffering under MSVCRT, so redirected server
   logs stayed empty on Windows; switched to `_IONBF`.
5. `c/src/IPv69/l2.c` — `auto` resolved from `/proc/net/route`, which on Android
   only carries the connected route (the default lives in a policy table), so
   every `auto` command failed with "no default-route interface found"; it now
   falls back to the first UP non-loopback interface.
6. `c/examples/bite.c` — `bite fetch <name>.bait` **segfaulted**: the auto-ifname
   guard (`dst_not_ifname`) accepts a `.bait` name or a URL, but
   `parse_insert_auto_ifname` only inserts when the argument parses as an
   address, so the argv came back unchanged and `main()` re-dispatched itself
   until the stack ran out. bite now inserts `auto` itself for URL/.bait
   destinations.
7. `c/examples/bite.c` + `c/src/ICSP/icsp_handshake.c` — the server died after 30s
   of silence (`icsp: INIT: Connection timed out`): the accept window was
   finite and a failed accept returned from the serve loop. The accept is now
   blocking (`timeout_s = 0`) and a failed accept re-enters the loop; the two
   handshake waits also treat `EAGAIN`/`EWOULDBLOCK`/`EINTR` as "no frame
   yet" instead of a fatal socket error.

Open gaps (measured, not implemented):

- No ND responder outside the PPPoE AC, so `addr --dad` always reports
  "address free" on a plain L2 — collision detection is not effective there.
- The first ICSP INIT is sent to broadcast. Making the client resolve the
  peer MAC by ND first (unicast INIT) would make any host a reliable server
  over Wi-Fi; today a phone behind an AP is only reachable when the broadcast
  happens to be delivered.
- BITE's 405 (unknown verb) is implemented server-side but the CLI client only
  issues GET/BITE/HEAD, so it is not exercised end-to-end.

## Defeitos medidos na camada bTLS/BITE (2026-11)

Encontrados ao servir arquivos maiores que um datagrama curto:

1. **Overflow de pilha no ICSP** — `icsp_data_send` declarava
   `uint8_t box[ICSP_MAX_PAYLOAD + 32]`, mas o blob tem `8 + len + 32`
   bytes (o cabeçalho claro de 8 B também é cifrado). No limite, 8 bytes
   passavam do buffer e o processo morria com `*** stack smashing
   detected ***` depois de responder `200`. Corrigido com
   `ICSP_MAX_PAYLOAD + 8 + 32`.

2. **`BTLS_MAX_PAYLOAD` maior que o carrier** — 1360 B de payload geram um
   record de 1397 B, que não cabe num DATA do ICSP
   (`1400 - 12 - 4 - 8 - 32 = 1344`). O servidor então falhava ao enviar
   (ou estourava o buffer acima). Reduzido para 1290 B; o invariante agora
   tem teste no Python (`tests/test_record_size_invariant.py`).

3. **ABERTO: respostas acima de ~980 B não chegam ao cliente** (modo
   `--remote`, same-host). Medido com `bite fetch` de arquivos aleatórios:

   ```
   880 bytes -> status 200      900 bytes -> timeout
   ```

   O ICSP sozinho entrega 1000 B sem problema (`ipv69 icsp client` com
   mensagem de 1000 bytes, servidor recebe inteiro), então a perda está
   acima do ICSP — no caminho de record/entrega do bTLS ou no callback
   `bite_data_cb` (que aceita um record por vez em `pend[BTLS_MAX_REC]`).
   Reprodução: servir `www/` em `--remote` e pedir um arquivo de 900 B.
