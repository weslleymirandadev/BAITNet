#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "IPv69/af69.h"
#include "IPv69/parse.h"

static const char *ctrl_name(uint8_t t)
{
    switch (t) {
    case IPV69_CTRL_ND_REQUEST:    return "nd-request";
    case IPV69_CTRL_ND_REPLY:      return "nd-reply";
    case IPV69_CTRL_ECHO_REQUEST:  return "echo-request";
    case IPV69_CTRL_ECHO_REPLY:    return "echo-reply";
    case IPV69_CTRL_UNREACHABLE:   return "unreachable";
    case IPV69_CTRL_TIME_EXCEEDED: return "time-exceeded";
    default:                       return "?";
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s recv [ifindex] [src_addr] [src_port]\n"
            "       %s send [ifindex] <dst> <src_port> <dst_port> [payload]\n"
            "       %s ping [ifindex] <dst> [payload]\n"
            "  ifindex 0 or omitted = auto-detect (pure L2)\n"
            "  src_addr: local 40-bit address to bind (ff.ff.ff.ff.ff or raw hex);\n"
            "            omitted = promiscuous (receives everything)\n"
            "  src_port: local port filter (hex); omitted = any port\n"
            "  dst: 40-bit address as ff.ff.ff.ff.ff or raw hex\n",
            prog, prog, prog);
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
        if (argc > 3 && parse_ipv69_addr(argv[3], &sa.src) < 0) {
            fprintf(stderr, "invalid src_addr: %s\n", argv[3]);
            return 1;
        }
        if (argc > 4)
            sa.dst_port = (uint16_t)strtoul(argv[4], NULL, 16);
        if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("bind");
            return 1;
        }
        printf("listening on ifindex %u src=%016llx port=%04x\n",
               sa.ifindex, (unsigned long long)sa.src, sa.dst_port);
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
            printf("frame: src=%016llx dst=%016llx if=%u nh=%u",
                   (unsigned long long)from.src, (unsigned long long)from.dst,
                   from.ifindex, from.next_header);
            if (from.next_header == IPV69_NEXT_DGRAM)
                printf(" ports=%u/%u", from.src_port, from.dst_port);
            else
                printf(" ctrl=%s(%u)", ctrl_name((uint8_t)buf[0]),
                       (uint8_t)buf[0]);
            printf(" payload(%zd)=", n);
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
        sa.next_header = IPV69_NEXT_DGRAM;
        const char *payload = argc > 6 ? argv[6] : "hello af69";
        if (argc > 7)
            sa.hop_limit = (uint8_t)atoi(argv[7]);
        if (sendto(fd, payload, strlen(payload), 0,
                   (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("sendto(AF_69)");
            return 1;
        }
        printf("sent %zu bytes\n", strlen(payload));
        return 0;
    }

    if (!strcmp(argv[1], "ping")) {
        if (argc < 4) {
            usage(argv[0]);
            return 1;
        }
        if (parse_ipv69_addr(argv[3], &sa.dst) < 0) {
            fprintf(stderr, "invalid dst address: %s\n", argv[3]);
            return 1;
        }
        /* bind a local address so replies are addressed to us (otherwise
           the socket is promiscuous and may pick up our own request) */
        sa.src = 1;
        sa.dst_port = 7;
        if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("bind(ping)");
            return 1;
        }
        const char *data = argc > 4 ? argv[4] : "ping";
        char req[1 + 512], rsp[1 + 512];
        size_t dlen = strlen(data);
        struct timeval tv = { 1, 0 };
        struct sockaddr_69 from;
        socklen_t flen = sizeof(from);

        req[0] = IPV69_CTRL_ECHO_REQUEST;
        memcpy(req + 1, data, dlen);
        sa.next_header = IPV69_NEXT_CONTROL;
        sa.src_port = 1;
        sa.dst_port = 7;
        if (argc > 5)
            sa.hop_limit = (uint8_t)atoi(argv[5]);
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (sendto(fd, req, 1 + dlen, 0, (struct sockaddr *)&sa,
                   sizeof(sa)) < 0) {
            perror("sendto(echo request)");
            return 1;
        }
        /* wait for the echo reply, skipping anything else (e.g. our own
           ND request looping back on the same link) */
        for (;;) {
            ssize_t n = recvfrom(fd, rsp, sizeof(rsp), 0,
                                 (struct sockaddr *)&from, &flen);
            if (n < 0) {
                perror("recvfrom(echo reply): timeout?");
                return 1;
            }
            if (n > 0 && rsp[0] == IPV69_CTRL_ECHO_REPLY) {
                printf("reply from %016llx: ctrl=%s(%u) payload(%zd)=",
                       (unsigned long long)from.src, ctrl_name((uint8_t)rsp[0]),
                       (uint8_t)rsp[0], n - 1);
                for (ssize_t i = 1; i < n; i++)
                    putchar((rsp[i] >= 0x20 && rsp[i] <= 0x7e) ? rsp[i] : '.');
                putchar('\n');
                return 0;
            }
        }
    }

    usage(argv[0]);
    return 1;
}
