/* ip69 - query the ip69d daemon (like `ip addr` for IPv69).
 *
 * Usage:
 *   ip69 addr show    print the leased 40-bit address + TAP state
 *   ip69 lease        seconds remaining until renewal
 *   ip69 renew        force a lease renewal (SIGUSR1 to the daemon)
 *   ip69 -s <path>    use a different control socket (default /tmp/ip69.sock)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

static const char *sockpath = "/tmp/ip69.sock";

static int query(const char *cmd, char *out, size_t outsz)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sun;
    ssize_t n;

    if (fd < 0) { perror("socket"); return 1; }
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, sockpath, sizeof(sun.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
        perror("connect (is ip69d running?)");
        close(fd);
        return 1;
    }
    ssize_t w = write(fd, cmd, strlen(cmd));
    (void)w;
    n = read(fd, out, outsz - 1);
    if (n > 0)
        out[n] = 0;
    close(fd);
    return n > 0 ? 0 : 1;
}

int cmd_ip69(int argc, char **argv)
{
    char buf[512];

    if (argc >= 3 && !strcmp(argv[1], "-s")) {
        sockpath = argv[2];
        argc -= 2;
        argv += 2;
    }
    if (argc < 2) {
        fprintf(stderr,
                "Usage: %s [-s <sock>] {addr show|lease|renew}\n", argv[0]);
        return 1;
    }
    if (!strcmp(argv[1], "addr")) {
        if (query("show", buf, sizeof(buf)) == 0)
            fputs(buf, stdout);
        else
            return 1;
    } else if (!strcmp(argv[1], "lease")) {
        if (query("lease", buf, sizeof(buf)) == 0) {
            buf[strcspn(buf, "\n")] = 0;   /* daemon appends \n */
            printf("lease: %s seconds\n", buf);
        } else
            return 1;
    } else if (!strcmp(argv[1], "renew")) {
        if (query("renew", buf, sizeof(buf)) == 0)
            fputs(buf, stdout);
        else
            return 1;
    } else {
        fprintf(stderr, "unknown command: %s\n", argv[1]);
        return 1;
    }
    return 0;
}
