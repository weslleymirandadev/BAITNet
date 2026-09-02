/* IPv69/gwfile.h - the ~/.hosts69/gateways file + host resolution.
 *
 * gateways: one connection gateway per line. A line is either a domain
 * (resolved via the built-in DNS A query, port 6969) or an IP:port
 * literal. Lines starting with '#' and empty lines are ignored.
 *
 * The binary links glibc statically, where getaddrinfo() cannot load
 * the NSS dns module, so domains are resolved by a small built-in DNS
 * client (UDP query to the first nameserver of /etc/resolv.conf).
 * On Windows the native GetAddrInfoW is used instead.
 */
#ifndef IPV69_GWFILE_H
#define IPV69_GWFILE_H

#include <stddef.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#define GWFILE_MAX 8            /* max gateways read from the file */

/* Resolve "host[:port]" (IP literal or domain) into a sockaddr.
 * Port defaults to 6969 when absent. Returns 0 on success, -1 on
 * error (unknown host, no nameserver, malformed input). */
int gwfile_resolve(const char *hostport, struct sockaddr_storage *sa,
                   socklen_t *salen);

/* Load ~/.hosts69/gateways into sa[]/salen[] (up to max entries).
 * Returns the number of gateways (0 when the file is missing or
 * empty — callers then keep their L2-only behavior). */
int gwfile_load(struct sockaddr_storage *sa, socklen_t *salen, int max);

/* The path of the gateways file (~/.hosts69/gateways). */
void gwfile_path(char *buf, size_t bufsz);

#endif
