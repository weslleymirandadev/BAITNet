/* af69_ping.c - teste do socket AF_IPV69 (modulo af_ipv69.ko)
 * Uso:
 *   ./af69_ping recv <iface>              # escuta e imprime datagramas
 *   ./af69_ping send <iface> <payload>    # envia datagrama (portas 1/7)
 * Precisa de root para o modulo carregado e o socket.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "IPv69/af69.h"

static void dump(const uint8_t *d, size_t n)
{
    printf("src_port = %04x\ndst_port = %04x\npayload = ",
           (d[0] << 8) | d[1], (d[2] << 8) | d[3]);
    for (size_t i = 4; i < n; i++) {
        uint8_t c = d[i];
        putchar((c >= 0x20 && c <= 0x7e) ? c : '.');
    }
    putchar('\n');
}

int main(int argc, char **argv)
{
    struct sockaddr_ipv69 sa;
    int fd, ifindex;
    uint8_t buf[1500];

    if (argc < 3) {
        fprintf(stderr, "Usage: %s recv|send <iface> [payload]\n", argv[0]);
        return 1;
    }
    ifindex = if_nametoindex(argv[2]);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    fd = socket(AF_IPV69, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket(AF_IPV69)");
        return 1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.family = AF_IPV69;
    sa.ifindex = ifindex;
    memset(sa.dst_mac, 0xff, 6);
    sa.dest = 2;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        return 1;
    }

    if (!strcmp(argv[1], "recv")) {
        for (;;) {
            ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
            if (n < 0) {
                perror("recvfrom");
                break;
            }
            printf("IPv69 frame received! (%zd bytes)\n", n);
            dump(buf, (size_t)n);
            fflush(stdout);
        }
    } else if (!strcmp(argv[1], "send")) {
        const char *payload = argc > 3 ? argv[3] : "hello from af69";
        size_t plen = strlen(payload);
        buf[0] = 0; buf[1] = 1;             /* src_port = 1 */
        buf[2] = 0; buf[3] = 7;             /* dst_port = 7 */
        memcpy(buf + 4, payload, plen);
        ssize_t n = sendto(fd, buf, 4 + plen, 0, (struct sockaddr *)&sa, sizeof(sa));
        if (n < 0) {
            perror("sendto");
            return 1;
        }
        printf("sent %zd bytes\n", n);
    } else {
        fprintf(stderr, "modo invalido\n");
        return 1;
    }
    return 0;
}
