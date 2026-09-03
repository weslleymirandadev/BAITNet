/* gwfile.c - the ~/.hosts69/gateways file + built-in DNS resolution.
 * See include/IPv69/gwfile.h. The keyring dir comes from keyring_paths.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#endif
#include "IPv69/gwfile.h"
#include "IPv69/keyring.h"

#ifndef _WIN32
/* ---- built-in DNS A-record query ----------------------------------
 * glibc -static cannot dlopen nss_dns, so getaddrinfo() only sees
 * /etc/hosts. This sends one UDP query to the first nameserver of
 * /etc/resolv.conf and parses the reply (skipping CNAMEs). */

#define DNS_PORT 53
#define DNS_HDR 12
#define DNS_MAX_NAME 255

static int dns_parse_name(const uint8_t *msg, size_t msglen, size_t *off,
                          char *out, size_t outsz)
{
    size_t o = *off, dst = 0;
    int jumps = 0;
    for (;;) {
        if (o >= msglen)
            return -1;
        uint8_t len = msg[o];
        if (len == 0) {         /* root label: end of name */
            o++;
            break;
        }
        if ((len & 0xc0) == 0xc0) {  /* compression pointer */
            if (o + 1 >= msglen)
                return -1;
            size_t ptr = ((size_t)(len & 0x3f) << 8) | msg[o + 1];
            if (++jumps > 8 || ptr >= msglen)
                return -1;
            if (dst == 0)       /* only the FIRST pointer advances o */
                o += 2;
            o = ptr;
            continue;
        }
        if ((len & 0xc0) || o + 1 + len >= msglen)
            return -1;
        if (dst + 1 + len >= outsz)
            return -1;
        if (dst)
            out[dst++] = '.';
        memcpy(out + dst, msg + o + 1, len);
        dst += len;
        o += 1 + len;
    }
    out[dst] = 0;
    *off = o;
    return 0;
}

/* query A for `name`; on success fills *a4 and returns 0 */
static int dns_query_a(const char *name, struct in_addr *a4)
{
    /* nameserver from /etc/resolv.conf (first "nameserver" line) */
    struct in_addr ns = { 0 };
    FILE *f = fopen("/etc/resolv.conf", "r");
    char line[256];
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            char nsstr[64];
            if (sscanf(line, "nameserver %63s", nsstr) == 1 &&
                inet_pton(AF_INET, nsstr, &ns) == 1)
                break;
        }
        fclose(f);
    }
    if (ns.s_addr == 0)
        inet_pton(AF_INET, "127.0.0.53", &ns);   /* systemd-resolved */
    if (ns.s_addr == 0)
        return -1;

    /* build the query: header + QNAME + QTYPE A + QCLASS IN */
    uint8_t q[512];
    size_t o = 0;
    /* random transaction ID from /dev/urandom: rand() without srand()
       repeats the same ID, and real routers/firewalls drop DNS
       queries with a recently-seen ID (anti cache-poisoning) — the
       built-in resolver failed against a physical router while dig
       (random IDs) worked. */
    uint16_t id = 0;
    int rfd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (rfd >= 0) {
        if (read(rfd, &id, sizeof(id)) != (ssize_t)sizeof(id))
            id = 0;
        close(rfd);
    }
    if (id == 0)
        id = (uint16_t)(0x6969u ^ (uint16_t)(size_t)time(NULL));
    q[o++] = (uint8_t)(id >> 8);
    q[o++] = (uint8_t)id;
    q[o++] = 0x01;              /* RD */
    q[o++] = 0;
    q[o++] = 0; q[o++] = 1;     /* QDCOUNT 1 */
    q[o++] = 0; q[o++] = 0;     /* ANCOUNT 0 */
    q[o++] = 0; q[o++] = 0;     /* NSCOUNT 0 */
    q[o++] = 0; q[o++] = 0;     /* ARCOUNT 0 */
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        if (l == 0 || l > 63 || o + 1 + l + 1 > sizeof(q))
            return -1;
        q[o++] = (uint8_t)l;
        memcpy(q + o, p, l);
        o += l;
        p += l + (dot ? 1 : 0);
    }
    q[o++] = 0;                 /* root */
    q[o++] = 0; q[o++] = 1;     /* QTYPE A */
    q[o++] = 0; q[o++] = 1;     /* QCLASS IN */

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    struct timeval tv = { 3, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(DNS_PORT);
    to.sin_addr = ns;
    int ret = -1;

    for (int attempt = 0; attempt < 2 && ret < 0; attempt++) {
        if (sendto(fd, q, o, 0, (struct sockaddr *)&to, sizeof(to)) < 0)
            break;
        uint8_t r[1024];
        ssize_t n = recv(fd, r, sizeof(r), 0);
        if (n < (ssize_t)DNS_HDR)
            continue;
        if ((uint16_t)((r[0] << 8) | r[1]) != id)
            continue;           /* reply of another query */
        if ((r[2] & 0x80) == 0 || (r[3] & 0x0f) != 0)
            continue;           /* not a reply, or error (NXDOMAIN..) */
        size_t ancount = (size_t)((r[6] << 8) | r[7]);
        /* skip the question section */
        size_t off = DNS_HDR;
        char tmp[DNS_MAX_NAME];
        for (size_t i = 0; i < ((size_t)((r[4] << 8) | r[5])); i++)
            if (dns_parse_name(r, (size_t)n, &off, tmp, sizeof(tmp)) < 0 ||
                off + 4 > (size_t)n)
                goto done;
            else
                off += 4;       /* QTYPE + QCLASS */
        /* walk answers: follow CNAMEs until an A record */
        for (size_t i = 0; i < ancount; i++) {
            if (dns_parse_name(r, (size_t)n, &off, tmp, sizeof(tmp)) < 0 ||
                off + 10 > (size_t)n)
                goto done;
            uint16_t type = (uint16_t)((r[off] << 8) | r[off + 1]);
            uint16_t rdlen = (uint16_t)((r[off + 8] << 8) | r[off + 9]);
            off += 10;
            if (type == 1 && rdlen == 4 && off + 4 <= (size_t)n) {
                memcpy(&a4->s_addr, r + off, 4);
                ret = 0;
                goto done;
            }
            off += rdlen;       /* CNAME rdata (or other) */
        }
    }
done:
    close(fd);
    return ret;
}
#endif /* !_WIN32 */

/* ---- host:port resolution ------------------------------------------ */

void gwfile_path(char *buf, size_t bufsz)
{
    char dir[256], key[512], kpub[512];
    keyring_paths(dir, sizeof(dir), key, sizeof(key), kpub, sizeof(kpub));
    snprintf(buf, bufsz, "%s/gateways", dir);
}

int gwfile_resolve(const char *hostport, struct sockaddr_storage *sa,
                   socklen_t *salen)
{
    char hp[256];
    snprintf(hp, sizeof(hp), "%s", hostport);
    char *colon = strrchr(hp, ':');
    char *host = hp;
    int port = 6969;            /* default: the well-known gw port */
    if (colon && colon != hp && *(colon - 1) != ']') {
        *colon = 0;
        port = atoi(colon + 1);
    } else if (colon && colon == hp) {
        return -1;              /* ":port" alone is not a gateway */
    }
    if (host[0] == '[') {       /* [v6]:port */
        host++;
        char *rb = strchr(host, ']');
        if (rb) {
            *rb = 0;
            char *p2 = strchr(rb + 1, ':');
            if (p2)
                port = atoi(p2 + 1);
        }
    }
    if (port <= 0 || port > 65535)
        return -1;

    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;
    if (inet_pton(AF_INET, host, &sa4.sin_addr) == 1) {
        sa4.sin_family = AF_INET;
        sa4.sin_port = htons((uint16_t)port);
        memcpy(sa, &sa4, sizeof(sa4));
        *salen = sizeof(sa4);
        return 0;
    }
    if (inet_pton(AF_INET6, host, &sa6.sin6_addr) == 1) {
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons((uint16_t)port);
        memcpy(sa, &sa6, sizeof(sa6));
        *salen = sizeof(sa6);
        return 0;
    }
#ifdef _WIN32
    /* Windows: native resolver (ws2_32, no NSS problem) */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    char svc[16];
    snprintf(svc, sizeof(svc), "%d", port);
    if (getaddrinfo(host, svc, &hints, &res) != 0 || !res)
        return -1;
    memcpy(sa, res->ai_addr, res->ai_addrlen);
    *salen = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
#else
    /* Linux: built-in A query (static glibc has no NSS) */
    struct in_addr a4;
    if (dns_query_a(host, &a4) < 0)
        return -1;
    memset(&sa4, 0, sizeof(sa4));
    sa4.sin_family = AF_INET;
    sa4.sin_port = htons((uint16_t)port);
    sa4.sin_addr = a4;
    memcpy(sa, &sa4, sizeof(sa4));
    *salen = sizeof(sa4);
    return 0;
#endif
}

/* ---- ~/.hosts69/gateways file -------------------------------------- */

int gwfile_load(struct sockaddr_storage *sa, socklen_t *salen, int max)
{
    char path[512];
    gwfile_path(path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;               /* no file: L2-only, like today */
    char line[256];
    int n = 0;
    while (n < max && fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == 0)
            continue;
        line[strcspn(line, "\r\n")] = 0;
        if (gwfile_resolve(p, &sa[n], &salen[n]) == 0)
            n++;
        else
            fprintf(stderr, "gwfile: ignoring bad gateway line: %s\n", p);
    }
    fclose(f);
    return n;
}
