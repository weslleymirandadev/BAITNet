/* icsp_session.c - ICSP session layer: endpoint, receive, poll.
 *
 * What the tools used to hand-roll on top of the transport: open the
 * endpoint (identity + raw socket), parse the L2 frame, refresh the
 * peer MAC, answer heartbeats, send SACKs, detect a dead peer and a
 * graceful SHUTDOWN. icsp_poll() wraps all of it in a select loop, so
 * a service (or a netcat) just registers a DATA callback.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#include <errno.h>
#include "IPv69/header.h"
#include "IPv69/l2.h"
#include "IPv69/keyring.h"
#include "ed25519.h"
#include "ICSP/icsp.h"

int icsp_endpoint_open(struct icsp_assoc *a, const char *ifname,
                       uint8_t sk[64])
{
    char key[512], kpub[512], dir[256], comment[128];
    uint8_t pub[32];

    memset(a, 0, sizeof(*a));
    keyring_paths(dir, sizeof(dir), key, sizeof(key), kpub, sizeof(kpub));
    if (keyring_load_or_create(key, kpub, sk, pub, comment,
                               sizeof(comment)) < 0)
        return -1;
    memcpy(a->id_pub, pub, 32);
    a->fd = raw_socket(ifname, &a->ifindex, a->src_mac);
    if (a->fd < 0)
        perror("icsp: raw_socket");
    return a->fd;
}

ssize_t icsp_recv_frame(struct icsp_assoc *a, uint8_t *frame,
                        const uint8_t **payload, size_t *plen,
                        uint64_t *src_addr)
{
    ssize_t n = recv(a->fd, frame, 1600, 0);
    if (n < 0)
        return -1;
    if (n < 14 + IPV69_HEADER_LEN + ICSP_HEADER_LEN)
        return 0;               /* noise: not ours */
    const struct ipv69_header *h =
        (const struct ipv69_header *)(frame + 14);
    if (h->next_header != IPV69_NEXT_STREAM)
        return 0;
    if (payload)
        *payload = frame + 14 + IPV69_HEADER_LEN;
    if (plen)
        *plen = (size_t)(n - 14 - IPV69_HEADER_LEN);
    if (src_addr)
        *src_addr = get_addr40(h->source);
    memcpy(a->peer_mac, frame + 6, 6);   /* reply unicast to the sender */
    a->has_peer_mac = 1;
    a->last_rx = time(NULL);            /* peer is alive */
    return n;
}

int icsp_handle_frame(struct icsp_assoc *a, const uint8_t *frame, ssize_t n,
                      icsp_data_cb on_data, void *ud)
{
    if (n < 14 + IPV69_HEADER_LEN + ICSP_HEADER_LEN)
        return 0;
    const struct ipv69_header *h =
        (const struct ipv69_header *)(frame + 14);
    if (h->next_header != IPV69_NEXT_STREAM)
        return 0;
    const uint8_t *payload = frame + 14 + IPV69_HEADER_LEN;
    size_t plen = (size_t)(n - 14 - IPV69_HEADER_LEN);

    memcpy(a->peer_mac, frame + 6, 6);
    a->has_peer_mac = 1;
    a->last_rx = time(NULL);

    /* answer HEARTBEAT automatically (keepalive is transport business) */
    if (plen >= ICSP_HEADER_LEN + ICSP_CHUNK_HDR &&
        payload[ICSP_HEADER_LEN] == ICSP_CHUNK_HEARTBEAT)
        icsp_heartbeat_ack(a);

    uint32_t cum_before = a->cum_tsn;
    uint8_t out[ICSP_MAX_PAYLOAD];
    size_t olen = sizeof(out);
    uint16_t ostream = 0;
    int m = icsp_data_handle(a, payload, plen, out, &olen, &ostream);
    if (m < 0)
        return ICSP_POLL_ERR;           /* bad MAC: drop the association */
    if (m > 0 && on_data)
        on_data(a, ostream, out, (size_t)m, ud);
    /* SACK when new data arrived (a->sack_loss_pct = test fault injection) */
    if (a->cum_tsn != cum_before &&
        (a->sack_loss_pct <= 0 || rand() % 100 >= a->sack_loss_pct))
        icsp_sack_send(a);
    if (icsp_life_handle(a, payload, plen))
        return ICSP_POLL_CLOSED;
    return m > 0 ? ICSP_POLL_DATA : 0;
}

int icsp_keepalive_tick(struct icsp_assoc *a)
{
    time_t now = time(NULL);
    if (a->dead_timeout_s > 0 && now - a->last_rx >= a->dead_timeout_s)
        return 1;                       /* peer silent too long */
    if (a->hb_interval_s > 0 && now - a->last_hb >= a->hb_interval_s) {
        icsp_heartbeat_send(a);
        a->last_hb = now;
    }
    return 0;
}

int icsp_poll(struct icsp_assoc *a, int timeout_ms,
              icsp_data_cb on_data, void *ud)
{
    struct pollfd pfd = { a->fd, POLLIN, 0 };
    uint8_t frame[1600];

    int r = poll(&pfd, 1, timeout_ms);
    if (r < 0) {
        if (errno == EINTR)
            return icsp_keepalive_tick(a) ? ICSP_POLL_DEAD : ICSP_POLL_TIMEOUT;
        return ICSP_POLL_ERR;
    }
    if (r == 0 || !(pfd.revents & POLLIN))
        return icsp_keepalive_tick(a) ? ICSP_POLL_DEAD : ICSP_POLL_TIMEOUT;
    ssize_t n = recv(a->fd, frame, sizeof(frame), 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return icsp_keepalive_tick(a) ? ICSP_POLL_DEAD : ICSP_POLL_TIMEOUT;
        return ICSP_POLL_ERR;
    }
    return icsp_handle_frame(a, frame, n, on_data, ud);
}

int icsp_relay(struct icsp_assoc *a, uint16_t stream_id, int use_stdin,
               icsp_data_cb on_data, void *ud)
{
    uint8_t frame[1600];
    char line[ICSP_MAX_PAYLOAD];

    for (;;) {
        struct pollfd pfds[2];
        int n = 0;

        if (use_stdin) {
            pfds[n].fd = 0;
            pfds[n].events = POLLIN;
            pfds[n].revents = 0;
            n++;
        }
        pfds[n].fd = a->fd;
        pfds[n].events = POLLIN;
        pfds[n].revents = 0;
        int nsock = n;          /* the socket is the last slot */
        n++;

        int r = poll(pfds, n, 500);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return ICSP_POLL_ERR;
        }
        if (r == 0) {
            if (icsp_keepalive_tick(a))
                return ICSP_POLL_DEAD;
            continue;
        }

        if (use_stdin && (pfds[0].revents & POLLIN)) {
            if (!fgets(line, sizeof(line), stdin)) {
                if (isatty(0)) {
                    icsp_shutdown_send(a);  /* Ctrl-D: graceful close */
                    return ICSP_POLL_EOF;
                }
                use_stdin = 0;  /* pipe/daemon EOF: keep receiving only */
                continue;
            }
            size_t len = strlen(line);
            while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
                line[--len] = 0;
            if (len && icsp_data_send(a, stream_id,
                                      (const uint8_t *)line, len) < 0)
                return ICSP_POLL_ERR;
        }
        if (pfds[nsock].revents & POLLIN) {
            ssize_t n = recv(a->fd, frame, sizeof(frame), 0);
            if (n < 0)
                continue;
            int pr = icsp_handle_frame(a, frame, n, on_data, ud);
            if (pr == ICSP_POLL_CLOSED || pr == ICSP_POLL_DEAD ||
                pr == ICSP_POLL_ERR)
                return pr;
        }
    }
}
