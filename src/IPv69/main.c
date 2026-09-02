/* ipv69 - single binary, git-style subcommands.
 *
 * Unifies every IPv69 tool into one executable. Each subcommand is a
 * cmd_* function from the project sources; argv[1] dispatches:
 *
 *   ipv69 gw       tunnel gateway (was ipv69gw)      [--port N] [--iface eth0]
 *   ipv69 net up   bring the device up: lease + keepalive daemon (Linux)
 *   ipv69 tun      same daemon as `net up` (alias, --tap optional)
 *   ipv69 addr     identity-derived address          [--dad]
 *   ipv69 keygen   generate Ed25519 key pairs
 *   ipv69 dhcpd    DHCP69 server (private nets)
 *   ipv69 dhcp     DHCP69 client (one-shot, for scripts)
 *   ipv69 send/recv/ping
 *   ipv69 lease/renew/status                         (Linux only)
 *
 * Windows build: the same binary minus the Linux-only commands
 * (net up/tun/lease/status need TAP, unix sockets or a daemon).
 */
#include <stdio.h>
#include <string.h>
#include "IPv69/plat.h"

int cmd_gw(int argc, char **argv);
int cmd_keygen(int argc, char **argv);
int cmd_dhcpd(int argc, char **argv);
int cmd_raw(int argc, char **argv);
int cmd_icsp(int argc, char **argv);
int cmd_help(int argc, char **argv);
int help_for(const char *cmd);
#ifndef _WIN32
int cmd_tun(int argc, char **argv);
int cmd_ip69(int argc, char **argv);
#endif

static void usage(void)
{
    fprintf(stderr,
        "Usage: ipv69 <subcommand> [args]\n"
        "\n"
        "  gw     [--port N] [--iface eth0]   tunnel gateway (UDP, multi-peer)\n"
        "  net up <ifname> [--tap NAME]       bring the device up: acquire a\n"
        "                                       lease and keep it alive (Linux)\n"
        "  tun    <ifname> [--tap NAME]       alias of `net up`\n"
        "  addr   [--dad]                      print identity-derived 40-bit address\n"
        "  keygen [count]                      generate Ed25519 key pairs\n"
        "  dhcpd  <ifname> [--allow MAC] [--peer HEX] [--peer-file F]\n"
        "         [--learn] [--key HEX] [pool_start pool_end lease_sec]\n"
        "                                       DHCP69 server (private networks)\n"
        "  dhcp   <ifname> [--server-pub HEX] [--key HEX] [--remote gw:port]\n"
        "                                       DHCP69 client (one-shot lease)\n"
        "  send   <ifname> <dst[:port]> [src_port] [payload] [--remote gws]\n"
        "  recv   <ifname> [addr[:port]] [--remote gws]   listen for dgrams\n"
        "  ping   <ifname> <dst> [payload]      echo request\n"
        "  lease | renew | status [-s PATH]     query the bring-up daemon (Linux)\n"
        "  icsp   <server|client> <ifname> [dst:port]    stream handshake (nh=2)\n"
        "\n"
        "Ports are DECIMAL and glued to the address (addr:16 = port 16).\n"
        "The keepalive daemon (net up/tun/lease/status) is Linux only;\n"
        "on Windows 'net up' is a one-shot lease.\n");
}

int main(int argc, char **argv)
{
    const char *cmd;

    if (plat_sock_init() < 0) {
        fprintf(stderr, "ipv69: winsock init failed\n");
        return 1;
    }
    if (argc < 2) {
        usage();
        return 1;
    }
    cmd = argv[1];

    /* `help` and `<cmd> --help|-h` */
    if (!strcmp(cmd, "help") || !strcmp(cmd, "--help") || !strcmp(cmd, "-h"))
        return cmd_help(argc - 1, argv + 1);
    if (argc > 2 && (!strcmp(argv[2], "--help") || !strcmp(argv[2], "-h")))
        return help_for(cmd);

    /* canonical subcommands. cmd_raw expects argv[1] = the
       sub-subcommand (recv/send/...), so pass argv undislocated */
    if (!strcmp(cmd, "gw"))        return cmd_gw(argc - 1, argv + 1);
    if (!strcmp(cmd, "addr"))      return cmd_raw(argc, argv);
    if (!strcmp(cmd, "keygen"))    return cmd_keygen(argc - 1, argv + 1);
    if (!strcmp(cmd, "dhcpd"))     return cmd_dhcpd(argc - 1, argv + 1);
    if (!strcmp(cmd, "dhcp"))      return cmd_raw(argc, argv);
    if (!strcmp(cmd, "net")) {
#ifndef _WIN32
        /* `net up <ifname>` = the bring-up daemon (same as `tun`): the
           one-shot lease code below is then only the Windows path. */
        if (argc >= 4 && !strcmp(argv[2], "up"))
            return cmd_tun(argc - 2, argv + 2);   /* [up, ifname, ...] */
#endif
        return cmd_raw(argc, argv);
    }
    if (!strcmp(cmd, "send"))      return cmd_raw(argc, argv);
    if (!strcmp(cmd, "recv"))      return cmd_raw(argc, argv);
    if (!strcmp(cmd, "ping"))      return cmd_raw(argc, argv);
    if (!strcmp(cmd, "icsp"))      return cmd_icsp(argc - 1, argv + 1);
    if (!strcmp(cmd, "chat"))      return help_for("icsp");
#ifdef _WIN32
    if (!strcmp(cmd, "tun") || !strcmp(cmd, "lease") || !strcmp(cmd, "renew") ||
        !strcmp(cmd, "status")) {
        fprintf(stderr, "ipv69: '%s' is not supported on Windows\n", cmd);
        return 1;
    }
#else
    if (!strcmp(cmd, "tun"))       return cmd_tun(argc - 1, argv + 1);
    if (!strcmp(cmd, "lease") || !strcmp(cmd, "renew") ||
        !strcmp(cmd, "status"))    return cmd_ip69(argc, argv);
#endif

    fprintf(stderr, "IPv69: unknown subcommand '%s'\n", cmd);
    usage();
    return 1;
}
