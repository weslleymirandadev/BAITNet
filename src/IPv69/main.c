/* ipv69 - single binary, git-style subcommands.
 *
 * Unifies every IPv69 tool into one executable. Each subcommand is a
 * cmd_* function from the project sources; argv[1] dispatches:
 *
 *   ipv69 gw       tunnel gateway (was ipv69gw)      [--port N] [--iface eth0]
 *   ipv69 tun      interface daemon: TAP + address   (Linux only)
 *   ipv69 addr     identity-derived address          [--dad]
 *   ipv69 keygen   generate Ed25519 key pairs
 *   ipv69 dhcpd    DHCP69 server (private nets)
 *   ipv69 dhcp     DHCP69 client
 *   ipv69 send/recv/ping
 *   ipv69 lease/renew/status                         (Linux only)
 *
 * Windows build: the same binary minus the Linux-only commands
 * (tun/lease/status need TAP or unix sockets).
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
        "  tun    <ifname> [--raw] [--tap NAME] [--remote gw:port] [--server-pub HEX]\n"
        "                                       hold address + create TAP (Linux)\n"
        "  addr   [--dad]                      print identity-derived 40-bit address\n"
        "  keygen [count]                      generate Ed25519 key pairs\n"
        "  dhcpd  <ifname> [--raw] [--allow MAC] [--peer HEX] [--peer-file F]\n"
        "         [--learn] [--key HEX] [pool_start pool_end lease_sec]\n"
        "                                       DHCP69 server (private networks)\n"
        "  dhcp   <ifname> [--server-pub HEX] [--key HEX] [--remote gw:port]\n"
        "                                       DHCP69 client (get a lease)\n"
        "  send   <ifname> <dst[:port]> <src_port> [payload] [--remote gws]\n"
        "  recv   <ifname> [addr[:port]] [--remote gws]   listen for dgrams\n"
        "  ping   <ifname> <dst> [payload]      echo request\n"
        "  lease | renew | status [-s PATH]     query the tun daemon (Linux)\n"
        "  icsp   <server|client> <ifname> [dst:porta]   stream handshake (nh=2)\n"
        "\n"
        "Ports are DECIMAL and glued to the address (addr:16 = port 16).\n"
        "On Windows, tun/lease/status are not available.\n");
}

int main(int argc, char **argv)
{
    const char *cmd;

    if (plat_sock_init() < 0) {
        fprintf(stderr, "ipv69: winsock init falhou\n");
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
    if (!strcmp(cmd, "net"))       return cmd_raw(argc, argv);
    if (!strcmp(cmd, "send"))      return cmd_raw(argc, argv);
    if (!strcmp(cmd, "recv"))      return cmd_raw(argc, argv);
    if (!strcmp(cmd, "ping"))      return cmd_raw(argc, argv);
    if (!strcmp(cmd, "icsp"))      return cmd_icsp(argc - 1, argv + 1);
    if (!strcmp(cmd, "chat"))      return help_for("icsp");
#ifdef _WIN32
    if (!strcmp(cmd, "tun") || !strcmp(cmd, "lease") || !strcmp(cmd, "renew") ||
        !strcmp(cmd, "status")) {
        fprintf(stderr, "ipv69: '%s' nao e suportado no Windows\n", cmd);
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
