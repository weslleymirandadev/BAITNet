# libipv69 — the IPv69/ICSP library (C API)

Plain C11, zero runtime dependencies (libc only; Npcap on Windows).
The CLI tools (`cmd_*`, the `ipv69` single binary) are **not** part of
the library — the library is the reusable protocol core: identity,
raw L2 transport, gateway tunnels, and the ICSP stream session layer.

```
make lib      # POSIX (AF_PACKET)  -> build/libipv69.a
make libwin   # MinGW  (Npcap)     -> build/libipv69_win.a
```

Link a program against it:

```bash
cc myapp.c build/libipv69.a -Iinclude -Ilib/ed25519/include
```

One `#include <ipv69.h>` pulls in the whole API. Each module also has
its own header under `include/IPv69/` and `include/ICSP/` when you
want a smaller surface.

---

## Module map

| Header | Contents |
|---|---|
| `IPv69/endian.h` | big-endian wire accessors (`ipv69_get_be16/32/64`, `ipv69_addr_get/put`) |
| `IPv69/header.h` | `struct ipv69_header` (32B), Ethernet header, version/flag constants |
| `IPv69/af69.h` | `next_header` values + control types (ND, ECHO, DHCP69, GW_*) |
| `IPv69/plat.h` | platform shims: `sock_t`, `plat_poll`, `plat_sleep_ms`, `plat_set_rcvtimeo` |
| `IPv69/l2.h` | raw L2 backend: `l2_open/send/recv/close`, `build_frame`, `raw_socket` |
| `IPv69/keyring.h` | `~/.hosts69` identity: load-or-create, generate, passphrase |
| `IPv69/mac1.h` | WireGuard-style pre-auth MAC filter (`mac1_key/compute/verify`) |
| `IPv69/ratelimit.h` | per-sender token bucket (`rate_allow`) |
| `IPv69/parse.h` | address parse/derive/class/range + frame print helpers |
| `IPv69/gwfile.h` | `~/.hosts69/gateways` file + built-in DNS resolution |
| `ICSP/icsp.h` | ICSP session layer — the chat/netcat building block |

The `ed25519` crypto (`lib/ed25519/include/ed25519.h`) is a standalone
library with its own include path; `keyring.h` and `ICSP/icsp.h` use it
internally, so most programs never include it directly.

---

## Typical call flows

### 1. ICSP chat server (L2 or tunnel)

```c
#include <ipv69.h>
#include <stdio.h>

static void on_data(struct icsp_assoc *a, uint16_t stream,
                    const uint8_t *data, size_t len, void *ud)
{
    (void)a; (void)stream; (void)ud;
    fwrite(data, 1, len, stdout);
    fputc('\n', stdout);
}

int main(void)
{
    struct icsp_assoc a;
    uint8_t sk[64];                       /* identity seed+pub */
    plat_sock_init();
    if (icsp_endpoint_open(&a, "auto", sk) < 0)   /* L2, or: */
        return 1;
    /* tunnel instead of L2:
     *   struct sockaddr_storage gw; socklen_t gwlen;
     *   if (gwfile_load(&gw, &gwlen, 1) > 0)
     *       icsp_endpoint_open_gw(&a, &gw, gwlen, sk);   */
    if (icsp_server_accept(&a, 6969, sk, NULL, 0, 0) < 0)
        return 1;
    a.hb_interval_s = 6;                  /* keepalive */
    a.dead_timeout_s = 18;                /* dead-peer detection */
    icsp_relay(&a, 1, 1, on_data, NULL);  /* stdin <-> stream 1 */
    return 0;
}
```

### 2. ICSP chat client

```c
#include <ipv69.h>

static void on_data(struct icsp_assoc *a, uint16_t s,
                    const uint8_t *d, size_t n, void *ud)
{
    (void)a; (void)s; (void)ud;
    fwrite(d, 1, n, stdout); fputc('\n', stdout);
}

int main(int argc, char **argv)
{
    struct icsp_assoc a;
    uint8_t sk[64];
    uint64_t dst;
    uint16_t port;
    plat_sock_init();
    if (argc < 2 || parse_ipv69_addr_port(argv[1], &dst, &port) < 0)
        return 1;
    if (icsp_endpoint_open(&a, "auto", sk) < 0)
        return 1;
    if (icsp_client_handshake(&a, dst, port, sk, NULL) < 0)
        return 1;
    a.hb_interval_s = 6;
    a.dead_timeout_s = 18;
    icsp_relay(&a, 1, 1, on_data, NULL);
    return 0;
}
```

### 3. Own poll loop (no relay) — customize the receive path

```c
#include <ipv69.h>

static void on_msg(struct icsp_assoc *a, uint16_t stream,
                   const uint8_t *data, size_t len, void *ud)
{
    (void)ud;
    printf("stream %u: %.*s\n", stream, (int)len, (const char *)data);
}

/* after icsp_client_handshake()/icsp_server_accept(): */
for (;;) {
    int r = icsp_poll(&a, 250, on_msg, NULL);
    if (r == ICSP_POLL_DEAD || r == ICSP_POLL_CLOSED || r == ICSP_POLL_ERR)
        break;
    /* your own logic here — timers, UI, other fds */
    if (user_wants_to_send)
        icsp_data_send(&a, 1, (const uint8_t *)"hi", 2);
}
```

### 4. Send a raw datagram on the L2

```c
#include <ipv69.h>

/* build + send one frame to a 40-bit destination */
uint8_t frame[14 + 32 + 1500];
l2_handle h;
int ifindex;
uint8_t mac[6];
uint8_t sk[64];

if (icsp_endpoint_open(&a, "eth0", sk) < 0)   /* loads identity too */
    return 1;
/* ... or open bare L2 without ICSP: l2_open("eth0", &h, &ifindex, mac) */
size_t flen = build_frame(frame, IPV69_BCAST_ADDR /*or peer mac*/, mac,
                          src_addr, dst_addr, IPV69_NEXT_DGRAM, 64,
                          src_port, dst_port, payload, plen);
l2_send(h, ifindex, dst_mac_or_bcast, frame, flen);
```

### 5. Gateway file + DNS (tunnel endpoints)

```c
#include <ipv69.h>

struct sockaddr_storage gws[GWFILE_MAX];
socklen_t gwlen[GWFILE_MAX];
int n = gwfile_load(gws, gwlen, GWFILE_MAX);   /* ~/.hosts69/gateways */
if (n > 0) {
    /* first gateway: open an ICSP tunnel endpoint to it */
    icsp_endpoint_open_gw(&a, &gws[0], gwlen[0], sk);
}
/* resolve a single "host[:port]" (domain or IP) yourself: */
gwfile_resolve("gw.example.com:6969", &sa, &salen);
```

---

## ICSP session API at a glance

Handshake (transport): `icsp_endpoint_open[_remote|_gw]`,
`icsp_client_handshake`, `icsp_server_accept`, `icsp_derive_key`,
`icsp_send_pkt`, `icsp_crc32c`, `icsp_announce_send` (tunnel servers).

Data path: `icsp_data_send`, `icsp_data_handle`, `icsp_sack_send`,
`icsp_data_retransmit`, `icsp_all_acked`.

Lifecycle: `icsp_heartbeat_send/ack`, `icsp_shutdown_send`,
`icsp_stream_reset`, `icsp_rekey_start/_client_step/_server_step`,
`icsp_life_handle`.

Session loop: `icsp_recv_frame`, `icsp_handle_frame`,
`icsp_keepalive_tick`, `icsp_poll`, `icsp_relay`. Callback type:
`icsp_data_cb(a, stream, data, len, ud)`. Return codes: `ICSP_POLL_DATA /
TIMEOUT / ERR / DEAD / CLOSED / EOF`.

The `struct icsp_assoc` carries the whole endpoint + session state;
tune keepalive with `a->hb_interval_s`, `a->dead_timeout_s` (seconds,
0 = off) and tunnel re-announce with `a->announce_s`.

---

## Customization notes

- **Transport backend**: the L2 API (`l2.h`) is the seam — the library
  uses `l2_open/send/recv` for everything; swap in your own transport
  (serial, UDP, virtio) behind the same calls.
- **Identity**: `keyring_load_or_create()` returns the Ed25519 seed +
  pub (`sk[64]`) that signs handshakes; the address is derived from the
  pub (`ipv69_addr_derive`) — bring your own key storage by filling
  `sk` before the handshake instead of calling `icsp_endpoint_open`.
- **Authentication policy**: `icsp_server_accept(peers, n_peers, ...)`
  takes an allowlist of trusted identity pubs; `NULL` accepts any valid
  signature (like `--learn`).
- **Fault injection** (tests): `a->sack_loss_pct`, `--loss`-style.
- **Threading**: the library is single-threaded; the only internal
  state is in the `struct icsp_assoc` you own (plus the fixed rate
  table `g_rate[]`). One assoc per thread is fine.

## C++?

Not needed — the C API is callable from C++, Rust, Python, Go, etc.
directly via FFI with no wrapper. If you want RAII ergonomics, write a
thin header-only C++ wrapper over these headers (the structs are plain
data, no opaque pointers to unwrap).
