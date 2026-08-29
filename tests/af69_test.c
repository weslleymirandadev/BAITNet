#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "IPv69/af69.h"
#include "IPv69/parse.h"

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s recv [ifindex]\n"
            "       %s send [ifindex] <dst> <src_port> <dst_port> <payload>\n"
            "  ifindex 0 or omitted = auto-detect (pure L2)\n"
            "  dst: 40-bit address as ff.ff.ff.ff.ff or raw hex\n",
            prog, prog);
}

int main(int argc, char **argv)
{
    struct sockaddr_69 sa;
    int fd;

    setvbuf(stdout, NULL, _IONBF, 0);   /* real-time log (timeout kills lose buffers) */

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_family = AF_69;
    if (argc > 2)
        sa.ifindex = (uint16_t)atoi(argv[2]);

    fd = socket(AF_69, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket(AF_69)");
        return 1;
    }

    if (!strcmp(argv[1], "recv")) {
        if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("bind");
            return 1;
        }
        printf("listening on ifindex %u\n", sa.ifindex);
        for (;;) {
            struct sockaddr_69 from;
            socklen_t flen = sizeof(from);
            char buf[1500];
            ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&from, &flen);
            if (n < 0) {
                perror("recvfrom");
                return 1;
            }
            printf("frame: src=%016llx dst=%016llx if=%u ports=%u/%u payload(%zd)=",
                   (unsigned long long)from.src, (unsigned long long)from.dst,
                   from.ifindex, from.src_port, from.dst_port, n);
            for (ssize_t i = 0; i < n; i++)
                putchar((buf[i] >= 0x20 && buf[i] <= 0x7e) ? buf[i] : '.');
            putchar('\n');
        }
    }

    if (!strcmp(argv[1], "send")) {
        if (argc < 6) {
            usage(argv[0]);
            return 1;
        }
        if (parse_ipv69_addr(argv[3], &sa.dst) < 0) {
            fprintf(stderr, "invalid dst address: %s\n", argv[3]);
            return 1;
        }
        sa.src_port = (uint16_t)strtoul(argv[4], NULL, 16);
        sa.dst_port = (uint16_t)strtoul(argv[5], NULL, 16);
        const char *payload = argc > 6 ? argv[6] : "hello af69";
        if (sendto(fd, payload, strlen(payload), 0,
                   (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("sendto(AF_69)");
            return 1;
        }
        printf("sent %zu bytes\n", strlen(payload));
        return 0;
    }

    usage(argv[0]);
    return 1;
}
