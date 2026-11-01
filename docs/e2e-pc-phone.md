# E2E battery: Windows PC <-> Android phone (same L2)

Two real hosts on one LAN, no gateway and no tunnel: the frames go over the
wireless/wired bridge of the router (EtherType `0x6969`), so this battery
exercises the protocol itself, not the UDP carrier.

```
  Windows PC  (AF_PACKET equivalent: Npcap)        Android phone (AF_PACKET)
  adapter "Realtek" / 192.168.100.6     ── LAN ──  wlan0 / 192.168.100.43
  build/ipv69.exe icsp_chat.exe bite.exe           /data/local/tmp/ipv69bench/
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

## Known limits of this topology

- Broadcast **wired -> wireless** may be filtered by the access point; every
  unicast reply works. That is why the server roles are normally taken by the
  PC and the phone dials in (B2/B10 test the other direction on purpose).
- Android `wlan0` in managed mode only hands the driver unicast to its own MAC
  (and some broadcast), so the phone is not a reliable frame *sniffer*: use
  the protocol's own `recv` as the sensor, not tcpdump.
- No forwarding/mesh/federation case lives here: they need a third host or a
  public seed (`docs/network-architecture.md`, USAGE section 7).
