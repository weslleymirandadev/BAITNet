/* btls_test.c - bTLS test: handshake + name check + AEAD app records.
 *
 *   ipv69 btls server <ifname> [port|:port] [--peer HEX] [--peer-file F]
 *   ipv69 btls client <ifname> <dst:port> [msg] [--label LABEL32]
 *
 * Runs the bTLS handshake (docs/btls-spec.md) over an ICSP association
 * (stream 1): the transport below is the same session layer the chat
 * uses, so the test exercises the real path of a future BITE service —
 * ICSP reliability/encryption underneath, bTLS on top. After the
 * handshake:
 *   - the client verifies the server certificate against --label (the
 *     server key's .bait label; without --label the name check is
 *     skipped), sends the msg and prints the server's reply;
 *   - the server replies with an ack record (also encrypted).
 *
 * A wrong --label must fail the handshake on the client — the name is
 * the pin. Identity = the ~/.hosts69 keyring (same as DHCP/ICSP); the
 * server's certificate is its keyring public key.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include "IPv69/plat.h"
#else
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#endif
#include "IPv69/parse.h"
#include "IPv69/l2.h"
#include "IPv69/gwfile.h"
#include "ed25519.h"
#include "ICSP/icsp.h"
#include "BITE/baitname.h"
#include "BITE/btls.h"

/* per-association bTLS context + pending inbound record (one message
 * per poll, processed after icsp_poll returns — no sends from inside
 * the data callback). */
struct bctx {
    struct btls btls;
    int done;               /* bTLS handshake complete */
    int fail;
    uint8_t pend[BTLS_MAX_REC];
    size_t pendlen;
    int got_app;
    uint8_t msg[BTLS_MAX_MSG];      /* app message (re)assembly buffer */
    char label[BAIT_LABEL_LEN + 1];   /* client: expected cert label */
};

/* ICSP DATA callback: buffer one inbound bTLS record for processing */
static void btls_data_cb(struct icsp_assoc *a, uint16_t stream,
                         const uint8_t *data, size_t len, void *ud)
{
    struct bctx *c = (struct bctx *)ud;

    (void)a; (void)stream;
    if (c->pendlen) {
        fprintf(stderr, "btls: dropped an inbound record (queue full)\n");
        return;
    }
    if (len > sizeof(c->pend))
        len = sizeof(c->pend);
    memcpy(c->pend, data, len);
    c->pendlen = len;
}

/* send one whole app message (btls fragments it across records) */
static int app_send(struct icsp_assoc *a, struct btls *t,
                    const uint8_t *msg, size_t len)
{
    uint8_t rec[BTLS_MAX_REC];
    size_t reclen;
    int r;

    do {
        r = btls_send_app(t, msg, len, rec, &reclen);
        if (r < 0)
            return -1;
        if (icsp_data_send(a, 1, rec, reclen) == -1)
            return -1;
    } while (r == 1);
    return 0;
}

/* feed the pending record; flush outbound handshake records (pump);
 * then act on the phase (handshake done / app record). */
static int bctx_process(struct bctx *c, struct icsp_assoc *a, int is_server)
{
    uint8_t rec[BTLS_MAX_REC];
    size_t reclen;
    int rr;

    if (c->done) {
        /* application phase: decrypt + reassemble one whole message */
        size_t msglen = 0;

        rr = btls_recv_app(&c->btls, c->pend, c->pendlen,
                           c->msg, sizeof(c->msg), &msglen);
        c->pendlen = 0;
        if (rr < 0)
            return -1;
        if (rr == 0)
            return 0;           /* mid-message fragment: keep going */
        c->got_app = 1;
        printf("btls: app message received (%zu bytes): \"%.*s\"\n",
               msglen, (int)msglen, (char *)c->msg);
        if (is_server) {
            /* reply with one ack message — encrypted, like everything */
            static const char ack[] = "btls ack";
            if (app_send(a, &c->btls, (const uint8_t *)ack,
                         sizeof(ack) - 1) < 0)
                return -1;
        }
        return 0;
    }

    rr = btls_feed(&c->btls, c->pend, c->pendlen);
    c->pendlen = 0;
    if (rr < 0)
        return -1;
    /* flush whatever the state machine wants to send (server flight
     * after ClientHello, client Finished after the server's).
     * data_send returns the TSN (uint32 — negative is valid); only
     * -1 means failure. */
    while (btls_pump(&c->btls, rec, sizeof(rec), &reclen) == 1)
        if (icsp_data_send(a, 1, rec, reclen) == -1)
            return -1;
    if (c->btls.state == BTLS_ST_DONE) {
        c->done = 1;
        if (is_server) {
            printf("btls: handshake ok — peer certificate %02x%02x...\n",
                   c->btls.cert_pub[0], c->btls.cert_pub[1]);
        } else if (c->btls.expect_label[0]) {
            printf("btls: handshake ok — certificate matches %s.bait\n",
                   c->btls.expect_label);
        } else {
            printf("btls: handshake ok (no name check — no --label)\n");
        }
    }
    return 0;
}

/* ---- client ------------------------------------------------------- */

static int run_client(int argc, char **argv, struct icsp_assoc *a,
                      uint8_t sk[64])
{
    uint64_t dst;
    uint16_t port;
    const char *msg = "hello btls";
    static struct bctx c;       /* 256 KiB reassembly buffer: static */
    uint8_t rec[BTLS_MAX_REC];
    size_t reclen;
    time_t deadline;
    int sent = 0;

    memset(&c, 0, sizeof(c));
    for (int i = 4; i < argc; i++) {
        if (!strcmp(argv[i], "--label") && i + 1 < argc) {
            if (strlen(argv[i + 1]) != BAIT_LABEL_LEN) {
                fprintf(stderr, "btls: --label must be %d base32 chars "
                                "(see 'ipv69 addr --bait' on the server)\n",
                        BAIT_LABEL_LEN);
                return 1;
            }
            snprintf(c.label, sizeof(c.label), "%s", argv[++i]);
        } else {
            msg = argv[i];
        }
    }
    if (argc < 4 || parse_ipv69_addr_port(argv[3], &dst, &port) < 0) {
        fprintf(stderr, "btls client: requires <dst:port> [msg] [--label L]\n");
        return 1;
    }
    if (port == 0)
        port = 6969;
    printf("btls: client -> %016llx:%u (label %s)\n",
           (unsigned long long)dst, port,
           c.label[0] ? c.label : "none");

    if (icsp_client_handshake(a, dst, port, sk, NULL) < 0)
        return 1;

    /* bTLS handshake over the association (stream 1) */
    btls_init(&c.btls, BTLS_CLIENT, sk, c.label[0] ? c.label : NULL);
    if (btls_client_start(&c.btls, rec, &reclen) < 0 ||
        icsp_data_send(a, 1, rec, reclen) == -1) {
        fprintf(stderr, "btls: could not send ClientHello\n");
        return 1;
    }
    printf("btls: ClientHello sent\n");

    deadline = time(NULL) + 8;
    while (time(NULL) < deadline) {
        int r = icsp_poll(a, 200, btls_data_cb, &c);
        if (r == ICSP_POLL_ERR) {
            fprintf(stderr, "btls: error in the association\n");
            return 1;
        }
        if (c.pendlen) {
            if (bctx_process(&c, a, 0) < 0) {
                fprintf(stderr, "btls: handshake failed — the server "
                                "certificate does not match the expected "
                                "name (or the flight was tampered)\n");
                return 1;
            }
        }
        if (c.done && !sent) {
            if (app_send(a, &c.btls, (const uint8_t *)msg,
                         strlen(msg)) < 0) {
                fprintf(stderr, "btls: app send failed\n");
                return 1;
            }
            printf("btls: app message sent (%zu bytes)\n", strlen(msg));
            sent = 1;
        }
        if (c.done && c.got_app) {
            printf("btls: ok (server reply received)\n");
            icsp_shutdown_send(a);
            return 0;
        }
        if (r == ICSP_POLL_CLOSED)
            break;
        if (r == ICSP_POLL_TIMEOUT)
            icsp_data_retransmit(a, 1);
    }
    fprintf(stderr, "btls: timeout waiting for the handshake/reply\n");
    return 1;
}

/* ---- server ------------------------------------------------------- */

static int run_server(int argc, char **argv, struct icsp_assoc *a,
                      uint8_t sk[64])
{
    uint8_t peers[64][32];
    int n_peers = 0;
    uint16_t port = 6969;

    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--peer") && i + 1 < argc) {
            if (hex_decode(argv[++i], peers[n_peers], 32) != 32) {
                fprintf(stderr, "btls: invalid --peer\n");
                return 1;
            }
            n_peers++;
        } else if (!strcmp(argv[i], "--peer-file") && i + 1 < argc) {
            FILE *f = fopen(argv[++i], "r");
            char line[128];
            if (!f) {
                perror("btls: peer-file");
                return 1;
            }
            while (fgets(line, sizeof(line), f)) {
                line[strcspn(line, "\r\n")] = 0;
                if (line[0] && n_peers < 64 &&
                    hex_decode(line, peers[n_peers], 32) == 32)
                    n_peers++;
            }
            fclose(f);
        } else if (!strcmp(argv[i], "--remote") && i + 1 < argc) {
            i++;                /* handled by cmd_btls (tunnel mode) */
        } else if (argv[i][0] == ':' && argv[i][1]) {
            port = (uint16_t)atoi(argv[i] + 1);
        } else if (argv[i][0] != '-') {
            port = (uint16_t)atoi(argv[i]);
        }
    }
    printf("btls: server on port %u (peers=%d)\n", port, n_peers);

    if (a->tunnel) {
        a->announce_s = 2;
        icsp_announce_send(a);
    }

    /* serve association after association; each one gets a fresh bTLS
       session (the certificate is our keyring key) */
    for (;;) {
        static struct bctx c;   /* 256 KiB reassembly buffer: static */
        time_t idle = time(NULL) + 20;

        memset(&c, 0, sizeof(c));
        btls_init(&c.btls, BTLS_SERVER, sk, NULL);
        if (icsp_server_accept(a, port, sk, peers, n_peers, 30) < 0)
            return 1;
        printf("btls: association accepted — bTLS handshake...\n");

        while (time(NULL) < idle) {
            int r = icsp_poll(a, 200, btls_data_cb, &c);
            if (r == ICSP_POLL_ERR) {
                perror("btls: poll");
                return 1;
            }
            if (c.pendlen) {
                if (bctx_process(&c, a, 1) < 0) {
                    fprintf(stderr, "btls: handshake/session failed — "
                                    "closing, waiting for the next one\n");
                    icsp_shutdown_send(a);
                    break;
                }
            }
            if (c.done && c.got_app) {
                idle = time(NULL) + 5;      /* keep serving more msgs */
                c.got_app = 0;
            }
            if (r == ICSP_POLL_CLOSED) {
                printf("btls: SHUTDOWN received — association closed, "
                       "waiting for the next one...\n");
                break;
            }
            if (r == ICSP_POLL_TIMEOUT)
                icsp_data_retransmit(a, 1);
        }
    }
    return 0;
}

/* ---- dispatcher --------------------------------------------------- */

int cmd_btls(int argc, char **argv)
{
    uint8_t sk[64];
    struct icsp_assoc a;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* ifname omitted (`btls server :6969` / `btls client <dst:port>`):
       insert "auto" so the endpoint resolves the default-route iface */
    if (argc >= 3 && argc < 30 && parse_looks_like_addr(argv[2])) {
        char *na[32];
        int nargc = parse_insert_auto_ifname(argc, argv, na);
        return cmd_btls(nargc, na);     /* re-dispatch normalized */
    }
    if (argc < 3) {
        fprintf(stderr, "btls: requires <server|client> <ifname> [args]\n");
        return 1;
    }
    const char *remote = NULL;
    for (int i = 3; i < argc; i++)
        if (!strcmp(argv[i], "--remote") && i + 1 < argc)
            remote = argv[++i];
    /* endpoint: --remote gw wins; otherwise the ~/.hosts69/gateways
       file (any gateway = tunnel); without either, plain local L2. */
    int n_gw = 0;
    struct sockaddr_storage gws[GWFILE_MAX];
    socklen_t gwlen[GWFILE_MAX];
    if (!remote)
        n_gw = gwfile_load(gws, gwlen, GWFILE_MAX);
    if (remote) {
        if (icsp_endpoint_open_remote(&a, remote, sk) < 0) {
            fprintf(stderr, "btls: invalid --remote (%s)\n", remote);
            return 1;
        }
        printf("btls: tunnel via --remote %s\n", remote);
    } else if (n_gw > 0) {
        if (icsp_endpoint_open_gw(&a, &gws[0], gwlen[0], sk) < 0) {
            fprintf(stderr, "btls: cannot open the gateway tunnel\n");
            return 1;
        }
        printf("btls: tunnel via ~/.hosts69/gateways (%d gateway(s))\n",
               n_gw);
    } else if (icsp_endpoint_open(&a, argv[2], sk) < 0) {
        fprintf(stderr, "btls: no identity (create one with ipv69 keygen)\n");
        return 1;
    }

    if (!strcmp(argv[1], "server"))
        return run_server(argc, argv, &a, sk);
    if (!strcmp(argv[1], "client"))
        return run_client(argc, argv, &a, sk);

    fprintf(stderr, "btls: unknown mode '%s' (server|client)\n", argv[1]);
    return 1;
}
