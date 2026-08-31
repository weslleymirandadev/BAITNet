/* ipv69 - single binary, git-style subcommands.
 *
 * Unifies every IPv69 tool into one executable. Each subcommand is a
 * cmd_* function from the project sources; argv[1] dispatches:
 *
 *   ipv69 gw       tunnel gateway (was ipv69gw)      [--port N] [--iface eth0]
 *   ipv69 tun      interface daemon: TAP + address   (was ip69d)
 *   ipv69 addr     identity-derived address          [--dad]
 *   ipv69 keygen   generate Ed25519 key pairs        (was ipv69-keygen)
 *   ipv69 dhcpd    DHCP69 server (private nets)      (was af69d)
 *   ipv69 dhcp     DHCP69 client                     (was af69_raw dhcp)
 *   ipv69 send/recv/ping                             (was af69_raw)
 *   ipv69 lease/renew/status                         (was ip69)
 *   ipv69 test     AF_69 socket client               (was af69_test)
 *
 * Any of the legacy names also work as an alias (ipv69 af69_raw ...).
 */
#include <stdio.h>
#include <string.h>

int cmd_gw(int argc, char **argv);
int cmd_tun(int argc, char **argv);
int cmd_keygen(int argc, char **argv);
int cmd_dhcpd(int argc, char **argv);
int cmd_raw(int argc, char **argv);
int cmd_ip69(int argc, char **argv);
int cmd_test(int argc, char **argv);

static void usage(void)
{
    fprintf(stderr,
        "Usage: ipv69 <subcommand> [args]\n"
        "\n"
        "  gw     [--port N] [--iface eth0]   tunnel gateway (UDP, multi-peer)\n"
        "  tun    <ifname> [--raw] [--tap NAME] [--remote gw:port] [--server-pub HEX]\n"
        "                                       hold address + create TAP\n"
        "  addr   [--dad]                      print identity-derived 40-bit address\n"
        "  keygen [count]                      generate Ed25519 key pairs\n"
        "  dhcpd  <ifname> [--raw] [--allow MAC] [--peer HEX] [--peer-file F]\n"
        "         [--learn] [--key HEX] [pool_start pool_end lease_sec]\n"
        "                                       DHCP69 server (private networks)\n"
        "  dhcp   <ifname> [--server-pub HEX] [--key HEX] [--remote gw:port]\n"
        "                                       DHCP69 client (get a lease)\n"
        "  send   <ifname> <dst> <sport> <dport> [payload] [src] [--remote gws]\n"
        "  recv   <ifname> [src] [sport] [--remote gws]   listen for dgrams\n"
        "  ping   <ifname> <dst> [payload]      echo request\n"
        "  lease | renew | status [-s PATH]     query the tun daemon (ip69)\n"
        "  test   <ifindex> <recv|send|ping|dhcp> ...   AF_69 socket client\n"
        "\n"
        "Legacy binary names also work as aliases (af69_raw, af69d, ip69d,\n"
        "ip69, ipv69gw, ipv69-keygen, af69_test). Ports are hex.\n");
}

int main(int argc, char **argv)
{
    const char *cmd;

    if (argc < 2) {
        usage();
        return 1;
    }
    cmd = argv[1];

    /* canonical subcommands. cmd_raw/cmd_ip69 expect argv[1] = the
       sub-subcommand (recv/send/...), so pass argv undislocated */
    if (!strcmp(cmd, "gw"))        return cmd_gw(argc - 1, argv + 1);
    if (!strcmp(cmd, "tun"))       return cmd_tun(argc - 1, argv + 1);
    if (!strcmp(cmd, "addr"))      return cmd_raw(argc, argv);
    if (!strcmp(cmd, "keygen"))    return cmd_keygen(argc - 1, argv + 1);
    if (!strcmp(cmd, "dhcpd"))     return cmd_dhcpd(argc - 1, argv + 1);
    if (!strcmp(cmd, "dhcp"))      return cmd_raw(argc, argv);
    if (!strcmp(cmd, "send"))      return cmd_raw(argc, argv);
    if (!strcmp(cmd, "recv"))      return cmd_raw(argc, argv);
    if (!strcmp(cmd, "ping"))      return cmd_raw(argc, argv);
    if (!strcmp(cmd, "lease") || !strcmp(cmd, "renew") ||
        !strcmp(cmd, "status"))    return cmd_ip69(argc, argv);
    if (!strcmp(cmd, "test"))      return cmd_test(argc - 1, argv + 1);

    /* legacy aliases: ipv69 af69_raw recv ... = ipv69 recv ... */
    if (!strcmp(cmd, "af69_raw"))  return cmd_raw(argc - 1, argv + 1);
    if (!strcmp(cmd, "af69d"))     return cmd_dhcpd(argc - 1, argv + 1);
    if (!strcmp(cmd, "ip69d"))     return cmd_tun(argc - 1, argv + 1);
    if (!strcmp(cmd, "ip69"))      return cmd_ip69(argc - 1, argv + 1);
    if (!strcmp(cmd, "ipv69gw"))   return cmd_gw(argc - 1, argv + 1);
    if (!strcmp(cmd, "ipv69-keygen")) return cmd_keygen(argc - 1, argv + 1);
    if (!strcmp(cmd, "af69_test")) return cmd_test(argc - 1, argv + 1);

    fprintf(stderr, "IPv69: Unkown subcommand '%s'\n", cmd);
    usage();
    return 1;
}
