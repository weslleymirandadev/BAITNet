# AF_69 — IPv69 socket address family (kernel module)

Registers the IPv69 protocol (EtherType `0x6969`) as a native Linux socket
family, so applications use `socket(AF_69, SOCK_DGRAM, 0)` with no raw
sockets and no interface plumbing. Pure layer 2 — no IPv4/IPv6 anywhere.

## Files

- `af69.c` — the module: AF_69 family + `packet_type` for 0x6969.
  SOCK_DGRAM carries the 253 datagram (src/dst ports + payload);
  `ifindex 0` auto-detects the active L2 interface on send.
- `af69-kernel.patch` — required kernel patch: `AF_69=69`, `AF_MAX=70`
  (`include/linux/socket.h`). Without it the kernel rejects families
  `>= AF_MAX` (~46), so the real 69 cannot be registered.
- `../../include/IPv69/af69.h` — userspace API (`AF_69`, `struct sockaddr_69`).
- `../../tests/af69_test.c` — userspace test (recv/send).

Addresses are 40 bits (5 octets, textual form `ff.ff.ff.ff.ff`); the
`struct sockaddr_69` fields `src`/`dst` carry the 40-bit value. The header
keeps 3 reserved bytes per address field for future 64-bit expansion.

## Build

1. Apply the kernel patch and build the kernel with it:

   ```sh
   cd <kernel-source>
   git apply <repo>/kernel/af69/af69-kernel.patch
   make -j$(nproc) vmlinux
   ```

   WSL2: point `.wslconfig` at the new vmlinux (`kernel=C:\\path\\to\\vmlinux`),
   then `wsl --shutdown` and reopen. Other platforms: install the kernel
   as usual.

2. Build the module against that kernel source (headers prepared):

   ```sh
   cd kernel/af69
   make KDIR=<kernel-source>
   ```

3. Load it (root):

   ```sh
   sudo insmod af69.ko
   dmesg | tail -1   # "af69: AF_69 registered (ethertype 0x6969)"
   ```

## Test (no second machine, no root for the sockets)

Build the test:

```sh
make -C tests af69_test   # or: gcc -Iinclude -o build/af69_test tests/af69_test.c
```

Sender and receiver on the same interface see each other via the kernel's
own L2 loopback; a veth pair in a user namespace works on WSL without root:

```sh
unshare -Urn sh -c 'ip link add v0 type veth peer name v1; ip link set v0 up; ip link set v1 up; timeout 5 /path/to/af69_test recv & sleep 1; /path/to/af69_test send 0 00.00.00.00.02 1 1 "hi af69"; sleep 2'
```

Validated on WSL2 (patched kernel 6.6.87.2): the receiver prints the
frame with the 40-bit addresses and ports:

```text
listening on ifindex 0
sent 2 bytes
frame: src=0000000000000000 dst=0000000000000002 if=3 ports=1/1 payload(2)=oi
```

## Layout

| user space          | kernel                          |
|---------------------|---------------------------------|
| `socket(AF_69, ...)`| `sock_register()` → AF_69      |
| `sendto(...)`       | `ipv69_sendmsg` → `dev_queue_xmit` (Ethernet frame) |
| `recvfrom(...)`     | `packet_type` 0x6969 → `ipv69_rcv` → socket queue |

## Pitfalls

- **packet_type handlers get the skb with the Ethernet header already
  pulled**: `eth_type_trans()` (called on receive, e.g. by `veth_xmit` via
  `__dev_forward_skb`) removes the 14 Ethernet bytes before the handler
  runs. `skb->data` points at the IPv69 header and `skb->len` excludes the
  Ethernet header — do not add `ETH_HLEN` again. AF_PACKET sockets differ:
  they deliver the full frame.
- Building the module against a kernel built with `make vmlinux` only:
  copy `vmlinux.symvers` to `Module.symvers` first, otherwise modpost
  reports every symbol as unresolved.
- Adding a new address family trips SELinux: update
  `security/selinux/include/classmap.h` (new class + `PF_MAX` check) and
  `socket_type_to_security_class()` in `security/selinux/hooks.c`.

## Current status / next steps

- [x] AF_69 family registered (SOCK_DGRAM, 253 datagram) — validated
- [x] TX: full Ethernet frame build (broadcast dst, interface src MAC)
- [x] RX: EtherType 0x6969 hook, validation, fan-out to sockets
- [x] Auto-detect interface on send (pure L2: first Ethernet up with carrier)
- [ ] L2 address resolution (neighbor discovery) instead of broadcast
- [ ] Destination-address demux (today: fan-out to all sockets)
- [ ] SOCK_STREAM / 254 stream transport
- [ ] Hop Limit decrement + drop at 0 (forwarding path)
