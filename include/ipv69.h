/* ipv69.h - umbrella header: include everything the IPv69/ICSP library
 * exposes with a single #include.
 *
 * The library is plain C11, no dependencies beyond libc (and Npcap on
 * Windows). Every module keeps its own header so you can include just
 * what you need; this one is the "give me the whole API" convenience.
 * Module map (all under include/, include path -Iinclude):
 *
 *   IPv69/endian.h    big-endian wire accessors (be16/32/64, addr40)
 *   IPv69/header.h    Ethernet + IPv69 header structs (32B), constants
 *   IPv69/af69.h      next_header + control types (ND/DHCP/GW_*)
 *   IPv69/plat.h      platform shims: sock_t, poll, sleep, rcvtimeo
 *   IPv69/l2.h        portable raw-L2 backend (AF_PACKET / Npcap)
 *   IPv69/keyring.h   ~/.hosts69 identity: load, create, passphrase
 *   IPv69/mac1.h      WG-style cheap pre-auth MAC filter
 *   IPv69/ratelimit.h per-sender token bucket (anti-exhaustion)
 *   IPv69/parse.h     address parse/derive/class + frame print helpers
 *   IPv69/gwfile.h    ~/.hosts69/gateways file + built-in DNS resolver
 *   ICSP/icsp.h       the ICSP session layer (stream transport):
 *                     association, handshake, DATA/SACK, lifecycle,
 *                     poll/relay — the netcat/chat building block
 *
 * ed25519 (lib/ed25519, include path -Ilib/ed25519/include) is a
 * separate standalone crypto library: ed25519.h (sign/verify/derive)
 * and tweetnacl secretbox; the keyring and ICSP already use it.
 *
 * Build: make lib (POSIX) / make libwin (MinGW) -> build/libipv69.a.
 * Link:  $(CC) app.c build/libipv69.a -Iinclude -Ilib/ed25519/include
 * The CLI tools (cmd_*) are intentionally NOT in the library — they
 * live in the ipv69 single binary; the library is the reusable core.
 */
#ifndef IPV69_UMBRELLA_H
#define IPV69_UMBRELLA_H

#include "IPv69/af69.h"
#include "IPv69/endian.h"
#include "IPv69/header.h"
#include "IPv69/plat.h"
#include "IPv69/l2.h"
#include "IPv69/keyring.h"
#include "IPv69/mac1.h"
#include "IPv69/ratelimit.h"
#include "IPv69/parse.h"
#include "IPv69/gwfile.h"
#include "ICSP/icsp.h"

#endif
