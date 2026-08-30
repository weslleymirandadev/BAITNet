#!/usr/bin/env python3
"""Apply the AF_69 kernel changes to the running Kali source tree (7.1.5).
Equivalent to af69-kernel.patch, adapted to the 7.1 classmap layout."""
import re, sys

def patch_file(path, subs):
    with open(path) as f:
        s = f.read()
    for old, new in subs:
        if old not in s:
            print(f"MISSING in {path}: {old!r}")
            sys.exit(1)
        s = s.replace(old, new, 1)
    with open(path, "w") as f:
        f.write(s)
    print(f"patched {path}")

# include/linux/socket.h
patch_file("include/linux/socket.h", [
    ("#define AF_MAX\t\t46\t/* For now.. */",
     "#define AF_69\t\t69\t/* IPv69 experimental protocol\n\t\t\t\t */\n#define AF_MAX\t\t70\t/* For now.. */"),
    ("#define PF_MCTP\t\tAF_MCTP\n#define PF_MAX\t\tAF_MAX",
     "#define PF_MCTP\t\tAF_MCTP\n#define PF_69\t\tAF_69\n#define PF_MAX\t\tAF_MAX"),
])

# security/selinux/hooks.c
patch_file("security/selinux/hooks.c", [
    ("\t\tcase PF_MCTP:\n\t\t\treturn SECCLASS_MCTP_SOCKET;\n#if PF_MAX > 46",
     "\t\tcase PF_MCTP:\n\t\t\treturn SECCLASS_MCTP_SOCKET;\n\t\tcase PF_69:\n\t\t\treturn SECCLASS_IPV69_SOCKET;\n#if PF_MAX > 70"),
])

# security/selinux/include/classmap.h
patch_file("security/selinux/include/classmap.h", [
    ("\t{ \"mctp_socket\", { COMMON_SOCK_PERMS, NULL } },\n\t{ \"perf_event\",",
     "\t{ \"mctp_socket\", { COMMON_SOCK_PERMS, NULL } },\n\t{ \"ipv69_socket\", { COMMON_SOCK_PERMS, NULL } },\n\t{ \"perf_event\","),
    ("#if PF_MAX > 46\n#error New address family defined, please update secclass_map.",
     "#if PF_MAX > 70\n#error New address family defined, please update secclass_map."),
])

print("ALL OK")
