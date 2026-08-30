# IPv69 — User Guide

How to build, run and use the IPv69 stack: the AF_69 kernel module, the
DHCP69 address lease (with Ed25519 authentication), the ip69d interface
daemon and the diagnostic tools.

```
bytes → Ethernet → IPv69 → transport (dgram) → application
```

Everything is pure layer 2: EtherType `0x6969`, 40-bit addresses in the
form `00.00.00.00.02`. No IPv4/IPv6 anywhere.

---

## 1. What is what

| Binary | Role |
|---|---|
| `build/af69.ko` (module) | Native `AF_69` socket family in the kernel (needs patched kernel, see §3). Without it, use raw. |
| `build/af69_test` | AF_69 socket test tool: `recv` / `send` / `ping` / `dhcp`. Requires the module. |
| `build/af69_raw` | AF_PACKET raw tool, **no kernel module needed** (phones, stock kernels). Same wire format. |
| `build/af69d` | DHCP69 **server** daemon: leases 40-bit addresses, optional allowlist + Ed25519. |
| `build/ipv69-keygen` | Generates Ed25519 keypairs (one per device). |
| `build/ip69d` | **Client** daemon: leases an address, keeps it bound, brings up a TAP (`ip69-0`), answers queries. |
| `build/ip69` | CLI that talks to ip69d (`addr show`, `lease`, `renew`) — like `ip addr` for IPv69. |

Two ways to use the protocol:

- **With the module** (`AF_69`): native sockets, kernel demux, ND, hop
  limit, forwarding. Used on the patched VM/WSL.
- **Raw** (`af69_raw`): same wire format, no kernel support. Used on the
  phone (stock Android kernel has no AF_69).

---

## 2. Build

```sh
make af69_test af69_raw af69d ipv69-keygen ip69d ip69
```

Static binaries (glibc static) land in `build/`. Cross-compile the phone
binary with the ARM64 toolchain:

```sh
aarch64-linux-gnu-gcc -Wall -Wextra -O2 -static -Iinclude \
  -o af69_raw_arm64 tests/af69_raw.c src/IPv69/parse.c \
  src/IPv69/tweetnacl.c src/IPv69/randombytes.c
```

---

## 3. The kernel module (optional, but recommended)

The AF_69 family needs a kernel patched with `kernel/af69/af69-kernel.patch`
(`AF_69=69`, `AF_MAX=70`). See `kernel/af69/README.md` for the full build.
Load it:

```sh
sudo insmod kernel/af69/af69.ko
dmesg | tail -1   # af69: AF_69 registered (ethertype 0x6969)
```

The module also enforces **lease bindings**: dgram frames from an address
that was never leased (or from a different MAC) are dropped (see §7).

---

## 4. DHCP69 — getting an address

Start the server on one host (the VM, e.g. eth0). Default pool
`00.00.00.00.10` – `00.00.00.00.fe`, lease 3600 s:

```sh
# plain (no auth)
sudo ./build/af69d eth0 --raw

# MAC allowlist only
sudo ./build/af69d eth0 --raw --allow 00:08:22:9c:03:fc

# Ed25519: pubkey allowlist + server signing key (see §6)
sudo ./build/af69d eth0 --raw --peer <PUBKEY_HEX> --key <SERVER_PRIVKEY_HEX>
```

`--raw` uses AF_PACKET (needs root) and sends replies **unicast to the
client MAC** — required when an AP/router filters wired→wireless
broadcast (the common case with a phone on Wi-Fi).

Client, from the phone chroot:

```sh
export PATH=/usr/bin:/bin
/root/af69_raw dhcp wlan0 --key <YOUR_PRIVKEY_HEX> --server-pub <SERVER_PUBKEY_HEX>
```

Client, on a host with the module:

```sh
./build/af69_test dhcp eth0 --key <YOUR_PRIVKEY_HEX> --server-pub <SERVER_PUBKEY_HEX>
```

On success:

```
dhcp: OFFER 0000000000000010 lease 3600s
dhcp: ACK 0000000000000010 — configurado!
dhcp: bound src=0000000000000010, ouvindo 5s...
```

Server log shows the exchange:

```
af69d: DISCOVER 00:08:22:9c:03:fc -> OFFER 0000000000000010
af69d: REQUEST 00:08:22:9c:03:fc -> ACK 0000000000000010
```

> Note: the leased address is **per-socket**. It exists while a process
> keeps it bound — `af69_raw dhcp` holds it for 5 s then exits. For a
> persistent address, use `ip69d` (§8).

---

## 5. Talking to a peer

### Ping (control plane, kernel answers on the module side)

```sh
# phone → VM (00.00.00.00.02 is the VM's address)
/root/af69_raw ping wlan0 00.00.00.00.02 "hi"

# VM → phone, using the address the phone leased
./build/af69_test ping eth0 00.00.00.00.10 "hi"
```

### dgram (send payload + ports)

```sh
# phone → VM
/root/af69_raw send wlan0 00.00.00.00.02 1 16 "hello" 00.00.00.00.10
#                                                          ^^^^^^^^^^ your leased addr (required: see §7)

# VM → phone (listen on the phone: af69_raw recv wlan0 00.00.00.00.10)
./build/af69_test send eth0 00.00.00.00.10 1 16 "hello"

# with AF_69 socket, bind first so replies address you
./build/af69_test recv eth0 00.00.00.00.02 16
```

Ports are hex in the CLI: `16` = 22 decimal. The frame dump shows
`ports=1/22`.

---

## 6. Ed25519 authentication (no shared secret)

Each device has its own keypair. The **private key never leaves the
device**; the server only knows public keys (safe to share).

```sh
# generate pairs
./build/ipv69-keygen 2
<privkey_hex> <pubkey_hex>      # device A
<privkey_hex> <pubkey_hex>      # server (or another device)
```

Server: allowlist the client's **public** key; sign OFFER/ACK with your
private key so clients can detect rogue servers:

```sh
sudo ./build/af69d eth0 --raw \
     --peer <PUBKEY_A_HEX> \
     --key <SERVER_PRIVKEY_HEX>
```

Client A:

```sh
/root/af69_raw dhcp wlan0 --key <PRIVKEY_A_HEX> --server-pub <SERVER_PUBKEY_HEX>
```

Signed wire format (signature covers every byte before it):

```
DISCOVER [7][mac 6][pub 32][sig 64]
OFFER    [8][mac 6][addr 5][lease 4][pub 32][sig 64]
REQUEST  [9][mac 6][addr 5][pub 32][sig 64]
ACK      [10][mac 6][addr 5][lease 4][pub 32][sig 64]
RELEASE  [11][mac 6][addr 5][pub 32][sig 64]
```

Properties: a leaked key only kills that device (remove its `--peer`);
no peer needs to know another peer's secret; rogue servers are rejected
client-side (`dhcp: OFFER assinatura invalida`).

---

## 7. Lease binding (kernel anti-spoof)

`af69d` registers every ACK in the module (`IPV69_BIND_ADD` ioctl). The
module then drops, on receive:

- dgram whose `src` address has no active lease;
- dgram whose `src` matches a lease but comes from a different MAC.

So always send dgram with **your leased address** as the last argument:

```sh
/root/af69_raw send wlan0 00.00.00.00.02 1 16 "hi" 00.00.00.00.10
```

A spoofed `src` (e.g. `00.00.00.00.11` you never leased) is silently
dropped by the peer's module.

---

## 8. ip69d — the interface daemon (persistent address + TAP)

Leases an address, keeps it bound (survives any single process), creates
a TAP interface `ip69-0` and answers local queries over a unix socket.

```sh
# with the module (no root needed for AF_69 socket)
./build/ip69d eth0

# without the module (raw, needs root) — phone or stock kernel
sudo ./build/ip69d wlan0 --raw

# custom TAP name / socket path
./build/ip69d eth0 --tap ip69-0 --sock /tmp/ip69.sock
```

Query it from anywhere on the machine:

```sh
./build/ip69 addr show   # like `ip addr` for IPv69
./build/ip69 lease       # seconds remaining
./build/ip69 renew       # force lease renewal
```

Example output:

```
1: ip69-0: <BROADCAST,UP,LOWER_UP> mtu 1500 state UP
    inet69 0000000000000010/40 brd ffffffffff scope global dynamic
       valid_lft 3599sec preferred_lft 3599sec
    link ifindex 2 mode raw
```

Quick lab (needs a DHCP69 server on the same netns; inside `unshare` there
is no `/dev/net/tun`, so the TAP is skipped and the address stays bound to
the socket — on a real host the TAP comes up):

```sh
unshare -Urn sh -c '
ip link add v0 type veth peer name v1
ip link set v0 up; ip link set v1 up
./build/af69d v0 --raw > /tmp/af69d.log 2>&1 &
sleep 1
./build/ip69d v1 --raw --sock /tmp/ip69.sock > /tmp/ip69d.log 2>&1 &
sleep 4
./build/ip69 -s /tmp/ip69.sock addr show
'
```

---

## 9. Quick lab (single machine, no root)

veth pair in a user namespace — works on WSL/VM without sudo for the
sockets:

```sh
unshare -Urn sh -c '
ip link add v0 type veth peer name v1
ip link set v0 up; ip link set v1 up
./build/af69d v0 --raw > /tmp/af69d.log 2>&1 &
sleep 1
./build/af69_test dhcp v1
'
```

With Ed25519:

```sh
./build/ipv69-keygen 2 > /tmp/keys.txt
CLIKEY=$(sed -n 1p /tmp/keys.txt | awk "{print \$1}")
CLIPUB=$(sed -n 1p /tmp/keys.txt | awk "{print \$2}")
SRVKEY=$(sed -n 2p /tmp/keys.txt | awk "{print \$1}")
SRVPUB=$(sed -n 2p /tmp/keys.txt | awk "{print \$2}")

unshare -Urn sh -c "
ip link add v0 type veth peer name v1
ip link set v0 up; ip link set v1 up
./build/af69d v0 --raw --peer $CLIPUB --key $SRVKEY > /tmp/af69d.log 2>&1 &
sleep 1
./build/af69_test dhcp v1 --key $CLIKEY --server-pub $SRVPUB
"
```

---

## 10. Phone setup (Moto G22 example)

Stock Android kernel has no AF_69 (`AF_MAX=45`), so use the raw binary.

```sh
# push + chroot (Nethunter)
adb push af69_raw_arm64 /data/local/tmp/af69_raw
adb shell su -c 'cp /data/local/tmp/af69_raw /data/local/nhsystem/kali-arm64/root/af69_raw && chmod 755 /data/local/nhsystem/kali-arm64/root/af69_raw'

# inside the chroot — PATH first (Android's /system/bin shadows /usr/bin)
export PATH=/usr/bin:/bin

# generate keys ON the phone (private key never leaves it)
/root/ipv69-keygen 2

# lease an address from the VM server
/root/af69_raw dhcp wlan0 --key <PRIVKEY> --server-pub <SERVER_PUBKEY>

# persist the address
sudo /root/ip69d wlan0 --raw
/root/ip69 addr show
```

---

## 11. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `socket(AF_PACKET): Operation not permitted` | raw needs root: `sudo` |
| `recvfrom(OFFER): timeout` + server logs nothing | wrong/absent key (`--key`), or MAC not on `--allow`; check server log for `nao esta na allowlist` / `assinatura invalida` |
| `dhcp: OFFER assinatura invalida` | `--server-pub` does not match the server's `--key` |
| phone sees nothing but VM works | AP filters wired→wireless broadcast: server needs `--raw` (unicast replies) |
| dgram sent but never arrives | you sent with `src=0` or a non-leased address — use your leased address as the last `send` arg |
| module rejects `insmod` (`in use`) | stale AF_69 sockets: kill leftover `af69_test`/`ip69d` processes |
| `insmod` fails with `File exists` | module already loaded: `sudo rmmod af69` first |
| no AF_69 in `dmesg` | kernel not patched: apply `af69-kernel.patch`, rebuild, point `.wslconfig` at the new vmlinux |

---

## Docs

- `docs/dhcp69-spec.md` — DHCP69 protocol spec
- `docs/security.md` — security layers in depth
- `kernel/af69/README.md` — module internals, forwarding lab, pitfalls
