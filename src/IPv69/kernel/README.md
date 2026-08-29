# af_ipv69 — IPv69 kernel module

Registers the `AF_IPV69` socket address family (`sock_register`) and the
`0x6969` EtherType (`dev_add_pack`) so the Linux kernel speaks IPv69 natively:
the kernel builds the frame (Ethernet + IPv69 header + datagram) on send and
validates/delivers on receive. No raw sockets needed in userspace.

```
userspace: socket(AF_IPV69, SOCK_DGRAM, 0) → sendto/recvfrom
              │
module:   sock_register(AF_IPV69)  →  proto_ops (create/bind/sendmsg/recvmsg)
              │
          dev_add_pack(0x6969)     →  receives frames from the NIC
```

## Constants

| name        | value | notes                                        |
|-------------|-------|----------------------------------------------|
| `AF_IPV69`  | 21    | free Linux family slot; FIXED for compatibility. The literal 69 requires a kernel rebuilt with `AF_MAX >= 70` (include/uapi/linux/socket.h) |
| EtherType   | 0x6969| experimental EtherType (same as the userspace tools) |
| `next_header` | 253 | datagram (src_port 2 + dst_port 2 + data)     |

The AF number does not affect wire communication — the EtherType `0x6969`
is what identifies the protocol on the wire. A host using `AF_IPV69` talks to
any host running the raw-socket tools.

## Requirements

- Kernel headers matching the RUNNING kernel (the module is not portable
  across kernel versions): `/lib/modules/$(uname -r)/build` must exist.
- If the distro has no prebuilt headers (e.g. WSL2): clone the matching
  kernel source and run `make modules_prepare` with the running config:
  ```sh
  git clone --depth 1 --branch <your-kernel-branch> \
      https://github.com/microsoft/WSL2-Linux-Kernel ~/WSL2-Linux-Kernel
  zcat /proc/config.gz > ~/WSL2-Linux-Kernel/.config
  make -C ~/WSL2-Linux-Kernel modules_prepare
  ```

## Build

Default (prebuilt headers):

```sh
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
```

Custom KERNELDIR (e.g. WSL2 source prepared with `modules_prepare`):

```sh
make KERNELDIR=~/WSL2-Linux-Kernel KBUILD_MODPOST_WARN=1
```

`KBUILD_MODPOST_WARN=1` is only needed when the kernel was not fully built
(no `Module.symvers`); all symbols used by this module are exported by the
running kernel, so the warnings are harmless. On a fully built kernel tree
it is unnecessary.

## Load / unload

```sh
sudo insmod af_ipv69.ko
sudo rmmod af_ipv69
```

Check it registered:

```sh
dmesg | grep IPv69
# IPv69: AF_IPV69 registrada (family 21), EtherType 0x6969
lsmod | grep ipv69
```

## Test (no network needed — loopback works)

Build the userspace test first (`make af69_ping` at the repo root), then:

```sh
./build/af69_ping recv lo     # terminal 1
./build/af69_ping send lo "hi" # terminal 2
```

Expected on terminal 1:

```
IPv69 frame received! (10 bytes)
src_port = 0001
dst_port = 0007
payload = hi
```

## Notes / pitfalls

- `skb->data` already points at the IPv69 header when `ipv69_rcv` runs:
  `eth_type_trans()` consumed the 14 Ethernet bytes before the EtherType
  dispatch — do not re-skip them.
- The module requires `CONFIG_MODULES=y`; machines without loadable-module
  support must build the code into the kernel (same constant `AF_IPV69 21`).
- Kernel 6.6 API notes: `skb_recv_datagram()` takes 3 args
  (`sk, flags, *err`), `packet_type.func` returns `int`, and the
  `proto_ops` has no `setsockopt/getsockopt/sendpage` members
  (omit them — NULL yields `EOPNOTSUPP`).
