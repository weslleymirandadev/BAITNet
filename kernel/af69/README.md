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
- `../../tests/af69_test.c` — userspace test (recv/send/ping).

Addresses are 40 bits (5 octets, textual form `ff.ff.ff.ff.ff`); the
`struct sockaddr_69` fields `src`/`dst` carry the 40-bit value. The header
keeps 3 reserved bytes per address field for future 64-bit expansion.

## Stack (v0.3)

- **Demux**: RX delivers to sockets matching the dst address and, for
  dgram, the bound port. Unbound sockets (src=0) are promiscuous.
- **Neighbor discovery**: 40-bit → MAC cache learned from every RX frame;
  sending to an unknown dst emits a broadcast ND request (ARP-like) and
  the owner answers with an ND reply (unicast).
- **Hop limit**: 64 at send; decremented on every forward; dropped at 0
  with a TIME_EXCEEDED control message (original header attached).
- **Forwarding**: frames with a non-local dst are relayed on another up
  interface of the same netns (simple route — no routing table yet).
- **Control** (`next_header` 255): ND request/reply, echo request/reply
  (kernel answers ping), dest unreachable, time exceeded.
- `next_header` 254 (STREAM) is **reserved** for a future SCTP-derived
  transport protocol — not implemented here.

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
make af69_test   # or: gcc -Iinclude -o build/af69_test tests/af69_test.c
```

Sender and receiver on the same interface see each other via the kernel's
own L2 loopback; a veth pair in a user namespace works on WSL without root:

```sh
unshare -Urn sh -c 'ip link add v0 type veth peer name v1; ip link set v0 up; ip link set v1 up; timeout 5 /path/to/af69_test recv 0 00.00.00.00.02 7 & sleep 1; /path/to/af69_test send 0 00.00.00.00.02 1 7 "hi af69"; sleep 2'
```

Validated on WSL2 (patched kernel 6.6.87.2): the receiver prints the
frame with the 40-bit addresses, ports and next_header:

```text
listening on ifindex 0 src=0000000000000002 port=0007
frame: src=0000000000000000 dst=0000000000000002 if=3 nh=253 ports=1/7 payload(7)=hi af69
```

### Ping (echo request/reply, kernel answers)

```sh
unshare -Urn sh -c 'ip link add v0 type veth peer name v1; ip link set v0 up; ip link set v1 up; timeout 5 /path/to/af69_test recv 0 00.00.00.00.02 7 & sleep 1; /path/to/af69_test ping 0 00.00.00.00.02 "teste echo"; sleep 2'
# reply from 0000000000000002: ctrl=echo-reply(4) payload(10)=teste echo
```

### Forwarding across 3 netns (A → relay R → C)

```sh
unshare -Urn sh -c '
unshare -n sh -c "while ! ip link show vA >/dev/null 2>&1; do sleep 0.1; done; ip link set vA up; sleep 1; /path/to/af69_test send 0 00.00.00.00.06 1 7 roteado3netns 2; sleep 2" > /tmp/A.log 2>&1 &
PIDA=$!
unshare -n sh -c "while ! ip link show vB >/dev/null 2>&1; do sleep 0.1; done; ip link set vB up; /path/to/af69_test recv 0 00.00.00.00.06 7" > /tmp/C.log 2>&1 &
PIDC=$!
sleep 0.3
unshare -n sh -c "ip link add vA type veth peer name vR1; ip link add vB type veth peer name vR2; ip link set vA netns $PIDA; ip link set vB netns $PIDC; ip link set vR1 up; ip link set vR2 up; sleep 8" &
sleep 5; cat /tmp/A.log; cat /tmp/C.log; kill $PIDA $PIDC 2>/dev/null'
```

The relay (netns R, no sockets) decrements the hop limit and re-emits the
frame on vR2; C receives it. Sending to an unknown address with
`hop_limit 1` yields a TIME_EXCEEDED control message back to the sender.

## Layout

| user space          | kernel                          |
|---------------------|---------------------------------|
| `socket(AF_69, ...)`| `sock_register()` → AF_69      |
| `sendto(...)`       | `ipv69_sendmsg` → `dev_queue_xmit` (Ethernet frame) |
| `recvfrom(...)`     | `packet_type` 0x6969 → `ipv69_rcv` → demux/forward → socket queue |

## Pitfalls

- **packet_type handlers get the skb with the Ethernet header already
  pulled**: `eth_type_trans()` (called on receive, e.g. by `veth_xmit` via
  `__dev_forward_skb`) removes the 14 Ethernet bytes before the handler
  runs. `skb->data` points at the IPv69 header and `skb->len` excludes the
  Ethernet header — do not add `ETH_HLEN` again. AF_PACKET sockets differ:
  they deliver the full frame. (The sender MAC is still readable via
  `eth_hdr(skb)->h_source`, used by ND learning.)
- Building the module against a kernel built with `make vmlinux` only:
  copy `vmlinux.symvers` to `Module.symvers` first, otherwise modpost
  reports every symbol as unresolved.
- Adding a new address family trips SELinux: update
  `security/selinux/include/classmap.h` (new class + `PF_MAX` check) and
  `socket_type_to_security_class()` in `security/selinux/hooks.c`.
- The ND cache is global to the module (not per netns) — tests must use
  fresh dst addresses, otherwise a stale entry from an earlier test skips
  the ND request.

## Current status / next steps

- [x] AF_69 family registered (SOCK_DGRAM, 253 datagram) — validated
- [x] TX: full Ethernet frame build (broadcast dst, interface src MAC)
- [x] RX: EtherType 0x6969 hook, validation, demux by addr/port
- [x] Auto-detect interface on send (pure L2: first Ethernet up with carrier)
- [x] Neighbor discovery: 40-bit → MAC cache + ND request/reply
- [x] Hop limit decrement + drop at 0 (TIME_EXCEEDED)
- [x] Forwarding between interfaces of a netns (3-netns relay validated)
- [x] Control plane: echo (ping), dest unreachable, time exceeded
- [ ] Routing table (dst → iface) instead of "first other up iface"
- [ ] L2 resolution for the forward path (uses cache or broadcast today)
- [ ] `next_header` 254 STREAM: SCTP-derived transport (reserved, planned)
- [ ] netdev integration (Phase 4: IPv69 network interface, drivers)
