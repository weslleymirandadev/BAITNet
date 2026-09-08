/* bite.c - BITE: the IPv69 web protocol (docs/bait-names-spec.md).
 *
 *   bite server [ifname] [port|:port] [--root DIR] [--peer HEX]...
 *   bite fetch [ifname] <URL> [--head] [--remote gw:port]
 *
 * The first web tool on the stack: BITE over bTLS over ICSP.
 *   - the server serves static files from --root (default ".") over
 *     bTLS; its keyring key is the certificate, so a client that
 *     dials name.bait verifies the name against the certificate (the
 *     name IS the pin — no CA);
 *   - fetch resolves name.bait locally (label -> class-C address),
 *     runs the bTLS handshake and prints the response body.
 *
 * bTLS messages are fragmented across AEAD records, so files bigger
 * than one ICSP message work; BTLS_MAX_MSG is the ceiling.
 *
 * URL: [bite://]name.bait[:port][/path]   (name = the site's .bait
 *      label, 32 chars; port default 8080)
 *      [bite://]addr[:port][/path]         (numeric address: no name
 *      check)
 *
 * Identity = the ~/.hosts69 keyring (--key-file works like the other
 * tools). Build: make bite.
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

#define BITE_PORT 8080          /* default ICSP port of a BITE service */
#define BITE_HDR_MAX 2048       /* room for the response head */

/* per-association context (256 KiB static buffers: message assembly) */
struct bctx {
    struct btls btls;
    int done;
    uint8_t pend[BTLS_MAX_REC];
    size_t pendlen;
    uint8_t msg[BTLS_MAX_MSG];  /* inbound request / outbound response */
    const char *root;           /* server: filesystem root */
};

/* ---- ICSP plumbing (mirrors cmd_icsp/cmd_btls) -------------------- */

static void bite_data_cb(struct icsp_assoc *a, uint16_t stream,
                         const uint8_t *data, size_t len, void *ud)
{
    struct bctx *c = (struct bctx *)ud;

    (void)a; (void)stream;
    if (c->pendlen || len > sizeof(c->pend))
        return;
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

/* ---- request parsing ---------------------------------------------- */

struct breq {
    char method[8];             /* BITE / GET / HEAD */
    char path[512];             /* decoded, safe, starts with '/' */
    int  is_head;
};

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* bounded memmem (portable — no GNU extension on Windows) */
static const char *mem_find(const uint8_t *h, size_t hlen,
                            const char *needle, size_t nlen)
{
    if (nlen > hlen)
        return NULL;
    for (size_t i = 0; i + nlen <= hlen; i++)
        if (!memcmp(h + i, needle, nlen))
            return (const char *)(h + i);
    return NULL;
}

/* percent-decode + sanitize a request target into rq->path. The query
 * string is dropped ('?'); only absolute paths are accepted and ".."
 * segments are rejected, so the result stays under the server root. */
static int req_target(const char *tgt, size_t len, char *out, size_t outsz)
{
    size_t o = 0;

    for (size_t i = 0; i < len && o + 1 < outsz; i++) {
        char ch = tgt[i];
        if (ch == '?')
            break;                      /* query dropped */
        if (ch == '%' && i + 2 < len) {
            int hi = hexval(tgt[i + 1]), lo = hexval(tgt[i + 2]);
            if (hi < 0 || lo < 0)
                return -1;
            ch = (char)((hi << 4) | lo);
            i += 2;
            if (ch == '/' || ch == 0)   /* encoded separators/NUL: no */
                return -1;
        }
        out[o++] = ch;
    }
    out[o] = 0;
    if (o == 0 || out[0] != '/')
        return -1;
    /* reject any ".." segment (path traversal) */
    for (char *p = out; (p = strstr(p, "..")) != NULL; p++) {
        char before = p == out ? '/' : p[-1];
        char after = p[2];
        if ((before == '/' || before == 0) &&
            (after == '/' || after == 0))
            return -1;
    }
    return 0;
}

/* parse "METHOD target BITE/1.0\r\n...headers...\r\n\r\n[body]" */
static int req_parse(const uint8_t *m, size_t len, struct breq *rq)
{
    const char *s = (const char *)m;
    size_t n = len < BITE_HDR_MAX ? len : BITE_HDR_MAX;
    const char *eol = memchr(s, '\n', n);
    const char *he;
    size_t tl;

    memset(rq, 0, sizeof(*rq));
    if (!eol)
        return -1;
    /* method */
    const char *sp = memchr(s, ' ', (size_t)(eol - s));
    if (!sp || sp == s || (size_t)(sp - s) >= sizeof(rq->method))
        return -1;
    memcpy(rq->method, s, (size_t)(sp - s));
    rq->method[sp - s] = 0;
    /* target (up to the next space or EOL) */
    const char *t0 = sp + 1;
    const char *t1 = memchr(t0, ' ', (size_t)(eol - t0));
    if (!t1)
        t1 = eol - 1 >= t0 ? eol - 1 : t0;      /* strip the CR */
    if (t1 <= t0)
        return -1;
    tl = (size_t)(t1 - t0);
    if (req_target(t0, tl, rq->path, sizeof(rq->path)) < 0)
        return -1;
    /* headers run to the empty line; anything after is the body */
    he = mem_find(m, n, "\r\n\r\n", 4);
    if (!he)
        return -1;
    rq->is_head = !strcmp(rq->method, "HEAD");
    return 0;
}

/* ---- static file serving ------------------------------------------ */

static const char *mime_of(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (!dot)
        return "application/octet-stream";
    if (!strcmp(dot, ".html") || !strcmp(dot, ".htm")) return "text/html";
    if (!strcmp(dot, ".css")) return "text/css";
    if (!strcmp(dot, ".js")) return "application/javascript";
    if (!strcmp(dot, ".json")) return "application/json";
    if (!strcmp(dot, ".txt") || !strcmp(dot, ".md")) return "text/plain";
    if (!strcmp(dot, ".png")) return "image/png";
    if (!strcmp(dot, ".jpg") || !strcmp(dot, ".jpeg")) return "image/jpeg";
    if (!strcmp(dot, ".gif")) return "image/gif";
    if (!strcmp(dot, ".svg")) return "image/svg+xml";
    if (!strcmp(dot, ".ico")) return "image/x-icon";
    if (!strcmp(dot, ".pdf")) return "application/pdf";
    return "application/octet-stream";
}

/* open the file behind a sanitized path, under root. "/" -> index.html */
static FILE *open_doc(const char *root, const char *path, long *size)
{
    char full[1024];
    FILE *f;

    if (!strcmp(path, "/"))
        path = "/index.html";
    snprintf(full, sizeof(full), "%s%s", root, path);
    f = fopen(full, "rb");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    *size = ftell(f);
    if (*size < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    return f;
}

/* build the response for one request into c->msg; returns its length,
 * -1 on error. head-first so Content-Length is known up front. */
static long serve(struct bctx *c, const struct breq *rq)
{
    char head[BITE_HDR_MAX];
    FILE *f;
    long fsize = 0, hn, total;
    int status = 200;
    const char *reason = "OK", *ctype = "text/html";

    if (strcmp(rq->method, "BITE") && strcmp(rq->method, "GET") &&
        strcmp(rq->method, "HEAD")) {
        /* v1 serves documents; the rest is Method Not Allowed */
        status = 405;
        reason = "Method Not Allowed";
        ctype = "text/plain";
        hn = snprintf(head, sizeof(head),
                      "BITE/1.0 405 Method Not Allowed\r\n"
                      "Allow: BITE, GET, HEAD\r\n"
                      "Content-Length: 0\r\nServer: BITE/1.0\r\n\r\n");
        memcpy(c->msg, head, (size_t)hn);
        return hn;
    }

    f = open_doc(c->root, rq->path, &fsize);
    if (!f) {
        status = 404;
        reason = "Not Found";
        ctype = "text/plain";
        hn = snprintf(head, sizeof(head),
                      "BITE/1.0 404 Not Found\r\n"
                      "Content-Type: text/plain\r\nContent-Length: 0\r\n"
                      "Server: BITE/1.0\r\n\r\n");
        memcpy(c->msg, head, (size_t)hn);
        return hn;
    }
    if (fsize > (long)(BTLS_MAX_MSG - BITE_HDR_MAX)) {
        fclose(f);
        hn = snprintf(head, sizeof(head),
                      "BITE/1.0 500 Internal Error\r\n"
                      "Content-Type: text/plain\r\nContent-Length: 0\r\n"
                      "Server: BITE/1.0\r\n\r\n");
        memcpy(c->msg, head, (size_t)hn);
        return hn;
    }
    ctype = mime_of(rq->path);
    hn = snprintf(head, sizeof(head),
                  "BITE/1.0 200 OK\r\nContent-Type: %s\r\n"
                  "Content-Length: %ld\r\nServer: BITE/1.0\r\n\r\n",
                  ctype, fsize);
    if (hn < 0 || hn >= (long)sizeof(head)) {
        fclose(f);
        return -1;
    }
    memcpy(c->msg, head, (size_t)hn);
    total = hn;
    if (!rq->is_head) {
        size_t got = fread(c->msg + total, 1,
                           (size_t)(BTLS_MAX_MSG - total), f);
        if (got != (size_t)fsize) {
            fclose(f);
            return -1;
        }
        total += (long)got;
    }
    fclose(f);
    printf("bite: %s %s -> %d (%ld bytes%s)\n", rq->method, rq->path,
           status, fsize, rq->is_head ? ", HEAD" : "");
    return total;
}

/* ---- server -------------------------------------------------------- */

static int run_server(int argc, char **argv, struct icsp_assoc *a,
                      uint8_t sk[64])
{
    static struct bctx c;
    const char *root = ".";
    uint16_t port = BITE_PORT;

    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--root") && i + 1 < argc)
            root = argv[++i];
        else if (!strcmp(argv[i], "--remote") && i + 1 < argc)
            i++;                /* handled by the endpoint opener */
        else if (argv[i][0] == ':' && argv[i][1])
            port = (uint16_t)atoi(argv[i] + 1);
        else if (argv[i][0] != '-')
            port = (uint16_t)atoi(argv[i]);
    }
    printf("bite: server on port %u (root: %s)\n", port, root);

    if (a->tunnel) {
        a->announce_s = 2;
        icsp_announce_send(a);
    }

    for (;;) {
        time_t idle = time(NULL) + 20;

        memset(&c, 0, sizeof(c));
        c.root = root;
        btls_init(&c.btls, BTLS_SERVER, sk, NULL);
        if (icsp_server_accept(a, port, sk, NULL, 0, 30) < 0)
            return 1;
        printf("bite: association accepted — bTLS handshake...\n");

        while (time(NULL) < idle) {
            int r = icsp_poll(a, 200, bite_data_cb, &c);
            if (r == ICSP_POLL_ERR) {
                perror("bite: poll");
                return 1;
            }
            if (c.pendlen) {
                uint8_t rec[BTLS_MAX_REC];
                size_t reclen;
                int rr;

                if (!c.done) {
                    rr = btls_feed(&c.btls, c.pend, c.pendlen);
                    c.pendlen = 0;
                    if (rr < 0)
                        goto assoc_fail;
                    while (btls_pump(&c.btls, rec, sizeof(rec), &reclen)
                           == 1)
                        if (icsp_data_send(a, 1, rec, reclen) == -1)
                            goto assoc_fail;
                    if (c.btls.state == BTLS_ST_DONE) {
                        c.done = 1;
                        printf("bite: bTLS up (peer certificate "
                               "%02x%02x...)\n",
                               c.btls.cert_pub[0], c.btls.cert_pub[1]);
                    }
                } else {
                    size_t msglen = 0;
                    struct breq rq;
                    long resp;

                    rr = btls_recv_app(&c.btls, c.pend, c.pendlen,
                                       c.msg, sizeof(c.msg), &msglen);
                    c.pendlen = 0;
                    if (rr < 0)
                        goto assoc_fail;
                    if (rr == 0)
                        continue;       /* mid-request fragment */
                    if (req_parse(c.msg, msglen, &rq) < 0) {
                        resp = snprintf((char *)c.msg, sizeof(c.msg),
                                        "BITE/1.0 400 Bad Request\r\n"
                                        "Content-Type: text/plain\r\n"
                                        "Content-Length: 0\r\n"
                                        "Server: BITE/1.0\r\n\r\n");
                    } else {
                        resp = serve(&c, &rq);
                        if (resp < 0)
                            goto assoc_fail;
                    }
                    if (app_send(a, &c.btls, c.msg, (size_t)resp) < 0)
                        goto assoc_fail;
                    idle = time(NULL) + 5;
                }
            }
            if (r == ICSP_POLL_CLOSED) {
                printf("bite: SHUTDOWN received — association closed, "
                       "waiting for the next one...\n");
                break;
            }
            if (r == ICSP_POLL_TIMEOUT)
                icsp_data_retransmit(a, 1);
            continue;
assoc_fail:
            fprintf(stderr, "bite: session failed — closing, waiting "
                            "for the next association\n");
            icsp_shutdown_send(a);
            break;
        }
    }
    return 0;
}

/* ---- fetch --------------------------------------------------------- */

static int run_fetch(int argc, char **argv, struct icsp_assoc *a,
                     uint8_t sk[64])
{
    static struct bctx c;
    const char *url;
    uint64_t dst = 0;
    uint16_t port = BITE_PORT;
    char host[128], path[512];
    char label[BAIT_LABEL_LEN + 1];
    const char *pathp = "/";
    const char *meth = "BITE";
    time_t deadline;
    int sent = 0, got = 0;

    memset(&c, 0, sizeof(c));
    label[0] = 0;
    if (argc < 4) {
        fprintf(stderr, "bite fetch: requires <URL> (name.bait[/path] "
                        "or addr[:port][/path])\n");
        return 1;
    }
    url = argv[3];
    for (int i = 4; i < argc; i++)
        if (!strcmp(argv[i], "--head"))
            meth = "HEAD";
    if (!strncmp(url, "bite://", 7))
        url += 7;
    /* split host[:port] from /path */
    const char *slash = strchr(url, '/');
    size_t hlen = slash ? (size_t)(slash - url) : strlen(url);
    const char *colon = memchr(url, ':', hlen);
    if (colon) {
        hlen = (size_t)(colon - url);
        port = (uint16_t)atoi(colon + 1);
        if (!port)
            port = BITE_PORT;
    }
    if (!hlen || hlen >= sizeof(host)) {
        fprintf(stderr, "bite fetch: bad URL (%s)\n", url);
        return 1;
    }
    memcpy(host, url, hlen);
    host[hlen] = 0;
    if (slash)
        pathp = slash;
    snprintf(path, sizeof(path), "%s", pathp);

    /* .bait name? derive addr + expected label locally (no DNS) */
    size_t hl = strlen(host);
    if (hl > 5 && !strcmp(host + hl - 5, ".bait")) {
        char lb[BAIT_LABEL_LEN + 1];
        uint8_t a5[5];
        if (hl != BAIT_LABEL_LEN + 5) {
            fprintf(stderr, "bite fetch: invalid .bait name (%s)\n",
                    host);
            return 1;
        }
        memcpy(lb, host, BAIT_LABEL_LEN);
        lb[BAIT_LABEL_LEN] = 0;
        if (!bait_label_valid(lb) || bait_label_to_addr(a5, lb) < 0) {
            fprintf(stderr, "bite fetch: invalid .bait name (%s)\n",
                    host);
            return 1;
        }
        memcpy(label, lb, BAIT_LABEL_LEN + 1);
        dst = ((uint64_t)a5[0] << 32) | ((uint64_t)a5[1] << 24) |
              ((uint64_t)a5[2] << 16) | ((uint64_t)a5[3] << 8) | a5[4];
    } else if (parse_ipv69_addr_port(host, &dst, &port) < 0 || !dst) {
        fprintf(stderr, "bite fetch: bad address (%s)\n", host);
        return 1;
    }
    if (!port)
        port = BITE_PORT;
    printf("bite: fetch %s://%s%s (%s)\n",
           label[0] ? "bite" : "addr", host, path,
           label[0] ? label : "no name check");

    if (icsp_client_handshake(a, dst, port, sk, NULL) < 0)
        return 1;
    btls_init(&c.btls, BTLS_CLIENT, sk, label[0] ? label : NULL);
    {
        uint8_t rec[BTLS_MAX_REC];
        size_t reclen;
        if (btls_client_start(&c.btls, rec, &reclen) < 0 ||
            icsp_data_send(a, 1, rec, reclen) == -1)
            return 1;
    }

    deadline = time(NULL) + 8;
    while (time(NULL) < deadline) {
        int r = icsp_poll(a, 200, bite_data_cb, &c);
        if (r == ICSP_POLL_ERR) {
            fprintf(stderr, "bite: error in the association\n");
            return 1;
        }
        if (c.pendlen) {
            uint8_t rec[BTLS_MAX_REC];
            size_t reclen;
            int rr;

            if (!c.done) {
                rr = btls_feed(&c.btls, c.pend, c.pendlen);
                c.pendlen = 0;
                if (rr < 0) {
                    if (label[0])
                        fprintf(stderr, "bite: bTLS handshake failed — "
                                        "the certificate does not match "
                                        "%s.bait\n", label);
                    else
                        fprintf(stderr, "bite: bTLS handshake failed — "
                                        "invalid certificate/signature\n");
                    return 1;
                }
                while (btls_pump(&c.btls, rec, sizeof(rec), &reclen) == 1)
                    if (icsp_data_send(a, 1, rec, reclen) == -1)
                        return 1;
                if (c.btls.state == BTLS_ST_DONE) {
                    c.done = 1;
                    if (label[0])
                        printf("bite: certificate matches %s.bait\n",
                               label);
                    else
                        printf("bite: handshake ok (no name check)\n");
                }
            } else {
                size_t msglen = 0;

                rr = btls_recv_app(&c.btls, c.pend, c.pendlen,
                                   c.msg, sizeof(c.msg), &msglen);
                c.pendlen = 0;
                if (rr < 0) {
                    fprintf(stderr, "bite: bad response record\n");
                    return 1;
                }
                if (rr == 1) {
                    /* split head (status + headers) from the body */
                    int code = 0;
                    const char *body = NULL;
                    size_t blen = 0;
                    const char *he = mem_find(c.msg, msglen,
                                              "\r\n\r\n", 4);
                    if (he) {
                        body = he + 4;
                        blen = msglen - (size_t)(body - (char *)c.msg);
                    } else {
                        body = (const char *)c.msg + msglen;
                    }
                    sscanf((const char *)c.msg, "BITE/1.0 %d", &code);
                    fprintf(stderr, "bite: status %d%s\n", code,
                            code == 200 ? "" : " (error)");
                    if (!strcmp(meth, "HEAD"))
                        fwrite(c.msg, 1, msglen, stdout);
                    else if (body)
                        fwrite(body, 1, blen, stdout);
                    fflush(stdout);
                    got = 1;
                    break;
                }
            }
        }
        if (c.done && !sent) {
            char req[BITE_HDR_MAX];
            int n = snprintf(req, sizeof(req), "%s %s BITE/1.0\r\n\r\n",
                             meth, path);
            if (n < 0 || n >= (int)sizeof(req)) {
                fprintf(stderr, "bite: request too long\n");
                return 1;
            }
            if (app_send(a, &c.btls, (const uint8_t *)req, (size_t)n) < 0) {
                fprintf(stderr, "bite: request send failed\n");
                return 1;
            }
            sent = 1;
        }
        if (r == ICSP_POLL_CLOSED)
            break;
        if (r == ICSP_POLL_TIMEOUT)
            icsp_data_retransmit(a, 1);
    }
    if (!got) {
        fprintf(stderr, "bite: timeout waiting for the response\n");
        return 1;
    }
    icsp_shutdown_send(a);
    return 0;
}

/* ---- main ----------------------------------------------------------- */

static void usage(void)
{
    fprintf(stderr,
        "Usage: bite server [ifname] [port|:port] [--root DIR]\n"
        "       bite fetch [ifname] <URL> [--head] [--remote gw:port]\n"
        "\n"
        "BITE over bTLS over ICSP (docs/bait-names-spec.md).\n"
        "URL: name.bait[/path] (name = the site .bait label) or\n"
        "addr[:port][/path]. Default port 8080. If [ifname] is an\n"
        "address/URL it is omitted and 'auto' is used.\n");
}

int main(int argc, char **argv)
{
    uint8_t sk[64];
    struct icsp_assoc a;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 2) {
        usage();
        return 1;
    }
    argc = parse_strip_keyfile(argc, argv, 1);
    /* ifname omitted (`bite fetch name.bait/x`, `bite server :8080`):
       insert "auto" so the endpoint resolves the default-route iface */
    if (argc >= 3 && argc < 30 && parse_looks_like_addr(argv[2])) {
        char *na[32];
        int nargc = parse_insert_auto_ifname(argc, argv, na);
        return main(nargc, na);     /* re-dispatch normalized */
    }
    if (argc < 3) {
        usage();
        return 1;
    }
    const char *remote = NULL;
    for (int i = 3; i < argc; i++)
        if (!strcmp(argv[i], "--remote") && i + 1 < argc)
            remote = argv[++i];
    int n_gw = 0;
    struct sockaddr_storage gws[GWFILE_MAX];
    socklen_t gwlen[GWFILE_MAX];
    if (!remote)
        n_gw = gwfile_load(gws, gwlen, GWFILE_MAX);
    if (remote) {
        if (icsp_endpoint_open_remote(&a, remote, sk) < 0) {
            fprintf(stderr, "bite: invalid --remote (%s)\n", remote);
            return 1;
        }
    } else if (n_gw > 0) {
        if (icsp_endpoint_open_gw(&a, &gws[0], gwlen[0], sk) < 0) {
            fprintf(stderr, "bite: cannot open the gateway tunnel\n");
            return 1;
        }
    } else if (icsp_endpoint_open(&a, argv[2], sk) < 0) {
        fprintf(stderr, "bite: no identity (create one with ipv69 "
                        "keygen)\n");
        return 1;
    }

    if (!strcmp(argv[1], "server"))
        return run_server(argc, argv, &a, sk);
    if (!strcmp(argv[1], "fetch"))
        return run_fetch(argc, argv, &a, sk);
    usage();
    return 1;
}
