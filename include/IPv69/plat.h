/* plat.h - platform layer for the IPv69 tools (POSIX vs Windows).
 * The L2 backend abstraction lives in l2.h; this header covers the
 * UDP/socket plumbing that differs between POSIX and Winsock:
 * socket type, init (WSAStartup), close, errno, poll (WSAPoll).
 */
#ifndef IPV69_PLAT_H
#define IPV69_PLAT_H

#include <stdio.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

typedef SOCKET sock_t;
#define SOCK_INVALID    INVALID_SOCKET
#define SOCK_EWOULDBLOCK WSAEWOULDBLOCK
#define sock_errno()    ((int)WSAGetLastError())
#define sock_close(s)   closesocket(s)

/* call once at startup (idempotent: WSAStartup is refcounted) */
static inline int plat_sock_init(void)
{
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0 ? 0 : -1;
}

static inline int plat_poll(struct pollfd *fds, int n, int tmo)
{
    return WSAPoll(fds, (ULONG)n, tmo);
}

static inline void perror_sock(const char *s)
{
    fprintf(stderr, "%s: winsock error %d\n", s, (int)WSAGetLastError());
}
#else
#include <errno.h>
#include <poll.h>
#include <unistd.h>

typedef int sock_t;
#define SOCK_INVALID    (-1)
#define SOCK_EWOULDBLOCK EWOULDBLOCK
#define sock_errno()    errno
#define sock_close(s)   close(s)

static inline int plat_sock_init(void) { return 0; }

static inline int plat_poll(struct pollfd *fds, int n, int tmo)
{
    return poll(fds, n, tmo);
}

static inline void perror_sock(const char *s) { perror(s); }
#endif

#endif
