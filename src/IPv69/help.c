/* help.c - per-subcommand help for the ipv69 single binary.
 *
 *   ipv69 help            general usage
 *   ipv69 help <cmd>      detailed help for one subcommand
 *   ipv69 <cmd> --help    same (also -h)
 */
#include <stdio.h>
#include <string.h>

static void usage_general(void)
{
    fprintf(stderr,
        "Usage: ipv69 <subcommand> [args]\n"
        "  use 'ipv69 help <subcommand>' for details\n"
        "\n"
        "  gw          tunnel gateway (UDP, multi-peer)\n"
        "  tun         hold address + create TAP interface\n"
        "  addr        print identity-derived 40-bit address\n"
        "  keygen      generate Ed25519 key pairs (keyring ~/.hosts69)\n"
        "  dhcpd       DHCP69 server (private networks)\n"
        "  dhcp        DHCP69 client (get a lease)\n"
        "  net up      bring the device up (keygen + DHCP lease)\n"
        "  send        send a datagram (src is auto, anti-spoofing)\n"
        "  recv        listen for datagrams\n"
        "  ping        echo request\n"
        "  lease       show the lease held by the tun daemon\n"
        "  renew       renew the lease\n"
        "  status      tun daemon status\n"
        "  icsp        ICSP stream handshake + data (nh=2)\n"
        "\n"
        "Ports are DECIMAL and glued to the address (addr:16 = port 16).\n");
}

static void usage_gw(void)
{
    fprintf(stderr,
        "ipv69 gw - tunnel gateway\n"
        "\n"
        "Usage: ipv69 gw [--port N] [--iface eth0] [--private] [--announce IP:PORT]\n"
        "\n"
        "Relays IPv69 datagrams over UDP so hosts behind different L2 networks\n"
        "can talk (the 'internet' path). Also answers QUERY with the peer's\n"
        "endpoint so hosts can connect P2P (direct) instead of relaying.\n"
        "\n"
        "Options:\n"
        "  --port N          UDP port to listen on (default 6969)\n"
        "  --iface eth0      announce the LAN IP of this interface\n"
        "  --private         also route class A/B (private) addresses\n"
        "  --announce IP:PORT  advertise a public endpoint for this host\n"
        "\n"
        "The gateway itself is addressed as 00.00.00.00.01.\n");
}

static void usage_tun(void)
{
    fprintf(stderr,
        "ipv69 tun - hold the address alive and expose it as a TAP interface\n"
        "\n"
        "Usage: ipv69 tun <ifname> [--tap NAME] [--remote gw:port]\n"
        "                   [--server-pub HEX] [--key HEX]\n"
        "\n"
        "Keeps a DHCP69 lease alive (so the kernel binding for your MAC stays\n"
        "registered) and, with --tap, creates a virtual interface where IPv69\n"
        "frames appear like normal Ethernet frames.\n"
        "\n"
        "Options:\n"
        "  --tap NAME      create a TAP interface named NAME (needs root)\n"
        "  --remote gw:port  reach the DHCP server through a gateway (tunnel)\n"
        "  --server-pub HEX  only accept a DHCP server with this pubkey\n"
        "  --key HEX       private seed (default: ~/.hosts69 keyring)\n");
}

static void usage_addr(void)
{
    fprintf(stderr,
        "ipv69 addr - identity-derived address\n"
        "\n"
        "Usage: ipv69 addr [--class A-E] [--dad [ifname]]\n"
        "\n"
        "The 40-bit IPv69 address is derived deterministically from your\n"
        "identity: SHA-512(public key) truncated to the class range. Same\n"
        "key = same address, anywhere. Classes: A 00-3f (private LAN),\n"
        "B 40-7f (private VPN), C 80-bf (public, default), D c0-df\n"
        "(multicast), E e0-ff (reserved).\n"
        "\n"
        "Options:\n"
        "  --class A-E     choose the class (default C)\n"
        "  --dad [ifname]  duplicate-address detection: probe the address\n"
        "\n"
        "The identity comes from ~/.hosts69/key (created by 'ipv69 keygen').\n");
}

static void usage_keygen(void)
{
    fprintf(stderr,
        "ipv69 keygen - Ed25519 identity key pair (ssh-keygen style)\n"
        "\n"
        "Usage: ipv69 keygen [-f PATH] [-C COMMENT] [-N PASS] [--force]\n"
        "       ipv69 keygen [count]              (stdout batch mode)\n"
        "\n"
        "Creates ~/.hosts69/key (private seed, 0600) + key.pub\n"
        "('<pubhex> <comment>'). The address and the DHCP signature derive\n"
        "from this identity. A passphrase encrypts the private key (secretbox,\n"
        "magic H69E1); without -N it prompts twice. Without a tty, empty.\n"
        "\n"
        "Options:\n"
        "  -f PATH         key file (default ~/.hosts69/key)\n"
        "  -C COMMENT      comment stored in key.pub (default: hostname)\n"
        "  -N PASS         passphrase (else prompt)\n"
        "  --force         overwrite an existing key without asking\n"
        "  count           print N keypairs to stdout, nothing saved\n"
        "\n"
        "Existing keys are NEVER overwritten without confirmation (y/N).\n");
}

static void usage_dhcpd(void)
{
    fprintf(stderr,
        "ipv69 dhcpd - DHCP69 server (private networks)\n"
        "\n"
        "Usage: ipv69 dhcpd <ifname> [--allow MAC] [--peer HEX]\n"
        "                      [--peer-file F] [--learn] [--key HEX]\n"
        "                      [pool_start pool_end lease_sec]\n"
        "\n"
        "Serves IPv69 addresses on a local L2 network (class A pool, default\n"
        ".10-.fe, lease 300s). Every OFFER/ACK is signed with the server\n"
        "identity (anti rogue server). Clients must present a signed DISCOVER\n"
        "when the server has a peer allowlist.\n"
        "\n"
        "Options:\n"
        "  --allow MAC     only serve this MAC (repeatable)\n"
        "  --peer HEX      accept this client pubkey (repeatable)\n"
        "  --peer-file F   load client pubkeys from file (one per line)\n"
        "  --learn         auto-register new pubkeys (append to --peer-file)\n"
        "  --key HEX       server seed (default: ~/.hosts69 keyring)\n"
        "  pool_start pool_end lease_sec   pool range + lease time\n"
        "\n"
        "Run it on the machine of the local network (e.g. your router/VM).\n");
}

static void usage_dhcp(void)
{
    fprintf(stderr,
        "ipv69 dhcp - DHCP69 client (get a lease)\n"
        "\n"
        "Usage: ipv69 dhcp <ifname> [--server-pub HEX] [--key HEX]\n"
        "                   [--remote gw:port]\n"
        "\n"
        "Discovers a DHCP69 server, gets an address for your MAC, prints the\n"
        "flow and holds the lease for a few seconds. send/recv do this\n"
        "silently on their own (the src is never user-chosen).\n"
        "\n"
        "Options:\n"
        "  --server-pub HEX  only accept this DHCP server's pubkey\n"
        "  --key HEX       client seed (default: ~/.hosts69 keyring)\n"
        "  --remote gw:port  get the lease through a gateway (tunnel)\n");
}

static void usage_send(void)
{
    fprintf(stderr,
        "ipv69 send - send a datagram (nh=1)\n"
        "\n"
        "Usage: ipv69 send <ifname> <dst[:porta]> <src_port> [payload]\n"
        "                  [--remote gw1,gw2:port]\n"
        "\n"
        "The source address is ALWAYS automatic (anti-spoofing): local nets\n"
        "use a silent DHCP lease (which also registers the kernel binding),\n"
        "tunnels derive it from the identity. A manual [src] is rejected.\n"
        "\n"
        "Examples:\n"
        "  ipv69 send eth0 00.00.00.00.02:16 1 \"ola\"\n"
        "  ipv69 send wlan0 b4.0b.0f.b8.78:16 1 oi --remote gw.bait.net.br:6969\n"
        "\n"
        "Ports are decimal. 'ipv69 recv' must be running on the peer.\n");
}

static void usage_recv(void)
{
    fprintf(stderr,
        "ipv69 recv - listen for datagrams (nh=1)\n"
        "\n"
        "Usage: ipv69 recv <ifname> [addr[:porta]] [--remote gw:port]\n"
        "\n"
        "Without an address, the lease is discovered silently via DHCP.\n"
        "With --remote, the address is derived from the identity (class C)\n"
        "and announced periodically so the gateway learns it.\n"
        "\n"
        "Examples:\n"
        "  ipv69 recv eth0                      (lease, any port)\n"
        "  ipv69 recv wlan0 00.00.00.00.10:16   (listen on lease .10:16)\n"
        "  ipv69 recv wlan0 --remote gw.bait.net.br:6969\n");
}

static void usage_ping(void)
{
    fprintf(stderr,
        "ipv69 ping - echo request/reply (nh=0 control)\n"
        "\n"
        "Usage: ipv69 ping <ifname> <dst> [payload] [--remote gw:port]\n"
        "\n"
        "Sends an echo request and waits for the reply, printing the RTT.\n");
}

static void usage_ip69(void)
{
    fprintf(stderr,
        "ipv69 lease|renew|status - talk to the tun daemon\n"
        "\n"
        "Usage: ipv69 <lease|renew|status> [-s PATH]\n"
        "\n"
        "Queries the ip69 tun daemon through its unix socket (default\n"
        "~/.ipv69/ip69.sock or the af69 kernel module).\n"
        "\n"
        "  lease    show the current address and lease time\n"
        "  renew    renew the lease\n"
        "  status   daemon status\n");
}

static void usage_icsp(void)
{
    fprintf(stderr,
        "ipv69 icsp - ICSP stream transport (nh=2, SCTP-derived)\n"
        "\n"
        "Usage: ipv69 icsp <server|client> <ifname> [port|:port]\n"
        "        [--peer HEX] [--peer-file F] [--echo] [--loss N]\n"
        "        ipv69 icsp client <ifname> <dst:porta> [msg] [--echo]\n"
        "        [--hb] [--reset]\n"
        "\n"
        "Authenticated 4-way handshake (INIT->INIT-ACK cookie->COOKIE-ECHO->\n"
        "COOKIE-ACK) with Ed25519 identity + X25519 ECDH: both sides derive\n"
        "the same session key, printed on connect. After that, DATA chunks\n"
        "are secretbox-encrypted with a TSN-derived nonce, ordered per\n"
        "stream, with SACK + retransmission.\n"
        "\n"
        "Examples:\n"
        "  ipv69 icsp server eth0 6969 --peer <pub_hex>\n"
        "  ipv69 icsp client wlan0 00.00.00.00.01:6969\n"
        "\n"
        "Options:\n"
        "  --peer HEX      allowlist: accept only this identity (repeatable)\n"
        "  --peer-file F   load allowed identities from file\n"
        "  --echo          echo received DATA back (test mode)\n"
        "  --loss N        drop N%% of DATA replies (synthetic loss test)\n"
        "\n"
        "A real chat example lives in examples/icsp_chat.c (make chat).\n");
}

int cmd_help(int argc, char **argv)
{
    if (argc < 2) {
        usage_general();
        return 1;
    }
    const char *c = argv[1];

    if (!strcmp(c, "gw"))         usage_gw();
    else if (!strcmp(c, "tun"))   usage_tun();
    else if (!strcmp(c, "addr"))  usage_addr();
    else if (!strcmp(c, "keygen")) usage_keygen();
    else if (!strcmp(c, "dhcpd")) usage_dhcpd();
    else if (!strcmp(c, "dhcp"))  usage_dhcp();
    else if (!strcmp(c, "send"))  usage_send();
    else if (!strcmp(c, "recv"))  usage_recv();
    else if (!strcmp(c, "ping"))  usage_ping();
    else if (!strcmp(c, "lease") || !strcmp(c, "renew") ||
             !strcmp(c, "status")) usage_ip69();
    else if (!strcmp(c, "icsp"))   usage_icsp();
    else {
        fprintf(stderr, "IPv69: no help for '%s'\n", c);
        usage_general();
        return 1;
    }
    return 0;
}

/* dispatch 'ipv69 <cmd> --help' / '-h' */
int help_for(const char *cmd)
{
    const char *av[2] = { "help", cmd };
    return cmd_help(2, (char **)av);
}
