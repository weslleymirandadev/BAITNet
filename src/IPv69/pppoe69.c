/* pppoe69 - PPPoE69 access sessions (spec: docs/pppoe69-spec.md).
 *
 * The improved PPPoE: RFC 2516's session discipline - discover an
 * access concentrator on a shared L2 segment, negotiate a private
 * session (16-bit id), then exchange frames only inside it - without
 * PPP/IP: admission is the Ed25519 identity (signed PADR), session
 * payloads are full native IPv69 frames, and everything runs on the
 * single 0x6969 EtherType (discovery = next_header 0 control codes
 * 17-21, session data = next_header IPV69_NEXT_PPPOE).
 *
 *   ipv69 pppoe ac [ifname] [--peer HEX]... [--peer-file F] [--learn]
 *                  [--key HEX] [--class A|B|C]
 *       Access concentrator: terminates sessions and bridges the
 *       dialed hosts onto its own L2 leg (transparent - the island
 *       sees each host's wire MAC), answers ND for them and relays
 *       session-to-session. Linux + Windows.
 *
 *   ipv69 pppoe host [ifname] [--ac ADDR] [--ac-pub HEX] [--tap NAME]
 *       Dials a session and exposes it as a TAP interface (ip69p0 by
 *       default) so the normal tools run unchanged over the session:
 *       ipv69 dhcp ip69p0, recv/send ip69p0, the chat example... The
 *       TAP leg is Linux-only (like `tun`).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include "IPv69/plat.h"        /* plat_sleep_ms / winsock (host dial loops) */
#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <linux/if_tun.h>
#endif
#include "IPv69/af69.h"
#include "IPv69/header.h"
#include "IPv69/parse.h"
#include "IPv69/l2.h"
#include "IPv69/mac1.h"
#include "IPv69/ratelimit.h"
#include "ed25519.h"
#include "IPv69/keyring.h"

#define MAX_SESSIONS 64
#define MAX_PEERS    64
#define SESSION_IDLE 300         /* reap sessions idle this many seconds */
#define BCAST_MAC    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
#define PUB_LEN      32
#define SIG_LEN      64

static const uint8_t g_bcast[6] = BCAST_MAC;

static void mac_str(const uint8_t *m, char out[18])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void pub_str(const uint8_t *p, char out[65])
{
    for (int i = 0; i < 32; i++)
        snprintf(out + 2 * i, 3, "%02x", p[i]);
    out[64] = 0;
}

/* append pub + sig over msg[0..plen) (repo convention: the signature
 * covers every byte before the appended pub). Returns the new length. */
static size_t sign_append(uint8_t *msg, size_t plen, const uint8_t sk[64])
{
    memcpy(msg + plen, sk + 32, PUB_LEN);
    if (ed25519_sign(msg + plen + PUB_LEN, msg, plen, sk) < 0)
        return plen;
    return plen + PUB_LEN + SIG_LEN;
}

/* load the ~/.hosts69 keyring (auto-create). Returns 0 with sk filled
 * (sk[0..31]=seed, sk[32..63]=pub). */
static int load_auto_key(uint8_t sk[64])
{
    char dir[256], key[512], kpub[512], comment[128];
    uint8_t pub[32];
    keyring_paths(dir, sizeof(dir), key, sizeof(key), kpub, sizeof(kpub));
    if (keyring_load_or_create(key, kpub, sk, pub, comment,
                               sizeof(comment)) < 0) {
        fprintf(stderr, "could not load/create key at %s\n", key);
        return -1;
    }
    return 0;
}

/* =====================================================================
 * access concentrator
 * =================================================================== */

struct pppoe_session {
    uint16_t sid;
    uint8_t  used;
    uint8_t  cmac[6];           /* control MAC (the dial socket's) */
    uint8_t  wmac[6];           /* wire MAC, learned from inner frames */
    uint64_t addr;              /* 40-bit address, learned from inner frames */
    time_t   last;              /* last activity (idle reaping) */
};

struct ac_ctx {
    l2_handle fd;
    int ifindex;
    uint8_t mac[6];             /* own MAC on the L2 leg */
    uint64_t addr;              /* own identity-derived address */
    char cls;
    uint8_t sk[64];
    uint8_t peers[MAX_PEERS][PUB_LEN];
    int n_peers;
    int auth_enabled;
    int learn;
    const char *peer_file;
    struct pppoe_session sess[MAX_SESSIONS];
};

/* ---- pubkey allowlist (dhcpd conventions: --peer/--peer-file/--learn) */

static void peer_file_load(struct ac_ctx *c, const char *path)
{
    FILE *f = fopen(path, "r");
    char line[96];

    if (!f) {
        fprintf(stderr, "ac: peer-file %s: %s\n", path, strerror(errno));
        return;
    }
    c->n_peers = 0;
    while (c->n_peers < MAX_PEERS && fgets(line, sizeof(line), f)) {
        char *p = line;
        uint64_t base;
        int prefix;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == 0)
            continue;
        line[strcspn(line, "\n")] = 0;
        if (ipv69_addr_parse_peer(p, c->peers[c->n_peers], &base,
                                  &prefix) == 0)
            c->n_peers++;
        else
            fprintf(stderr, "ac: peer-file: ignoring invalid line: %s\n", p);
    }
    fclose(f);
    printf("ac: peer-file %s: %d pubkey(s)\n", path, c->n_peers);
}

static void learn_pub(struct ac_ctx *c, const uint8_t *pub, const uint8_t *mac)
{
    char ps[65], ms[18];

    for (int i = 0; i < c->n_peers; i++)
        if (!memcmp(c->peers[i], pub, PUB_LEN))
            return;
    if (c->n_peers >= MAX_PEERS) {
        fprintf(stderr, "ac: learn: peer table full (%d)\n", MAX_PEERS);
        return;
    }
    memcpy(c->peers[c->n_peers], pub, PUB_LEN);
    c->n_peers++;
    if (c->peer_file) {
        FILE *f = fopen(c->peer_file, "a");
        if (f) {
            pub_str(pub, ps);
            fprintf(f, "%s\n", ps);
            fclose(f);
        }
    }
    mac_str(mac, ms);
    pub_str(pub, ps);
    printf("ac: learned pub %s from MAC %s -> registered%s\n", ps, ms,
           c->peer_file ? " to peer-file" : " (memory only)");
}

/* PADR [19][mac 6][pub 32][sig 64][mac1 16]: mac1 was already verified;
 * check the pub against the allowlist (or learn it) and the signature
 * over [19][mac]. Returns 1 when the host may dial. */
static int check_padr(struct ac_ctx *c, const uint8_t *p, size_t plen,
                      const uint8_t *hmac)
{
    const uint8_t *pub = p + 7, *sig = p + 39;
    char ps[65];

    if (plen != 1 + 6 + PUB_LEN + SIG_LEN + MAC1_LEN)
        return 0;
    if (!c->auth_enabled)
        return 1;
    pub_str(pub, ps);
    for (int i = 0; i < c->n_peers; i++)
        if (!memcmp(c->peers[i], pub, PUB_LEN)) {
            if (ed25519_verify(p, 7, sig, pub) == 0)
                return 1;
            printf("ac: invalid signature from %s\n", ps);
            return 0;
        }
    if (c->learn && ed25519_verify(p, 7, sig, pub) == 0) {
        learn_pub(c, pub, hmac);
        return 1;
    }
    printf("ac: pub %s not in allowlist -> session refused\n", ps);
    return 0;
}

/* ---- session table -------------------------------------------------- */

static struct pppoe_session *sess_by_cmac(struct ac_ctx *c,
                                          const uint8_t *mac)
{
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (c->sess[i].used && !memcmp(c->sess[i].cmac, mac, 6))
            return &c->sess[i];
    return NULL;
}

static struct pppoe_session *sess_by_sid(struct ac_ctx *c, uint16_t sid)
{
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (c->sess[i].used && c->sess[i].sid == sid)
            return &c->sess[i];
    return NULL;
}

static struct pppoe_session *sess_by_addr(struct ac_ctx *c, uint64_t addr)
{
    /* addr 0 = not yet learned: never match an unconfigured frame dst */
    if (!addr)
        return NULL;
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (c->sess[i].used && c->sess[i].addr == addr)
            return &c->sess[i];
    return NULL;
}

static struct pppoe_session *sess_by_wmac(struct ac_ctx *c,
                                          const uint8_t *mac)
{
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (c->sess[i].used && !memcmp(c->sess[i].wmac, mac, 6))
            return &c->sess[i];
    return NULL;
}

static struct pppoe_session *sess_alloc(struct ac_ctx *c, uint16_t *sid)
{
    int slot = -1;

    for (int i = 0; i < MAX_SESSIONS; i++)
        if (!c->sess[i].used) {
            slot = i;
            break;
        }
    if (slot < 0)
        return NULL;
    for (uint32_t try = 1; try <= 0xffff; try++) {
        int taken = 0;
        for (int i = 0; i < MAX_SESSIONS; i++)
            if (c->sess[i].used && c->sess[i].sid == (uint16_t)try) {
                taken = 1;
                break;
            }
        if (!taken) {
            memset(&c->sess[slot], 0, sizeof(c->sess[slot]));
            c->sess[slot].used = 1;
            c->sess[slot].sid = (uint16_t)try;
            c->sess[slot].last = time(NULL);
            *sid = (uint16_t)try;
            return &c->sess[slot];
        }
    }
    return NULL;
}

static void sess_free(struct ac_ctx *c, struct pppoe_session *s)
{
    char ms[18];
    mac_str(s->cmac, ms);
    printf("ac: session %u (%s) closed\n", s->sid, ms);
    memset(s, 0, sizeof(*s));
}

/* ---- tx -------------------------------------------------------------- */

/* send one control payload on the L2 leg. Replies follow the DHCP69
 * server convention: IPv69 dst broadcast, Ethernet unicast to the host. */
static int ac_send(struct ac_ctx *c, const uint8_t *eth_dst,
                   uint8_t nh, const uint8_t *payload, size_t plen)
{
    uint8_t frame[2048];

    size_t l = build_frame(frame, eth_dst, c->mac, c->addr,
                           IPV69_BCAST_ADDR, nh, 64, 0, 0, payload, plen);
    return l2_send(c->fd, c->ifindex, eth_dst, frame, l);
}

/* wrap a full inner frame into session s and send it to the host */
static int ac_session_send(struct ac_ctx *c, struct pppoe_session *s,
                           const uint8_t *inner, size_t ilen)
{
    uint8_t buf[2048], frame[2048];

    if (ilen > sizeof(buf) - 2)
        return -1;
    ipv69_put_be16(buf, s->sid);
    memcpy(buf + 2, inner, ilen);
    size_t l = build_frame(frame, s->cmac, c->mac, c->addr,
                           IPV69_BCAST_ADDR, IPV69_NEXT_PPPOE,
                           64, 0, 0, buf, 2 + ilen);
    return l2_send(c->fd, c->ifindex, s->cmac, frame, l);
}

static void ac_pado(struct ac_ctx *c, const uint8_t *hmac)
{
    uint8_t p[1 + 6 + 6 + 5 + PUB_LEN + SIG_LEN];
    size_t len = 1 + 6 + 6 + 5;

    p[0] = IPV69_CTRL_PADO;
    memcpy(p + 1, hmac, 6);
    memcpy(p + 7, c->mac, 6);
    put_addr40(p + 13, c->addr);
    len = sign_append(p, len, c->sk);
    ac_send(c, hmac, IPV69_NEXT_CONTROL, p, len);
}

static void ac_pads(struct ac_ctx *c, struct pppoe_session *s)
{
    uint8_t p[1 + 6 + 2 + PUB_LEN + SIG_LEN];
    size_t len = 1 + 6 + 2;

    p[0] = IPV69_CTRL_PADS;
    memcpy(p + 1, s->cmac, 6);
    ipv69_put_be16(p + 7, s->sid);
    len = sign_append(p, len, c->sk);
    ac_send(c, s->cmac, IPV69_NEXT_CONTROL, p, len);
}

static void ac_padt(struct ac_ctx *c, struct pppoe_session *s)
{
    uint8_t p[1 + 2];

    p[0] = IPV69_CTRL_PADT;
    ipv69_put_be16(p + 1, s->sid);
    ac_send(c, s->cmac, IPV69_NEXT_CONTROL, p, sizeof(p));
}

/* ND_REPLY claiming `target` is at `owner_mac`, sent as an Ethernet
 * frame to `eth_dst` (unicast to an island asker) - the stack's ND
 * responder, so duplicate-address detection works for dialed hosts. */
static void ac_nd_reply(struct ac_ctx *c, uint64_t target,
                        const uint8_t *owner_mac, const uint8_t *eth_dst)
{
    uint8_t p[1 + 5 + 6] = { IPV69_CTRL_ND_REPLY };
    uint8_t frame[512];

    put_addr40(p + 1, target);
    memcpy(p + 7, owner_mac, 6);
    size_t l = build_frame(frame, eth_dst, owner_mac, target,
                           IPV69_BCAST_ADDR, IPV69_NEXT_CONTROL,
                           64, 0, 0, p, sizeof(p));
    l2_send(c->fd, c->ifindex, eth_dst, frame, l);
}

/* ---- rx -------------------------------------------------------------- */

/* bridge an inner frame from session s onto the L2 leg: the Ethernet
 * src is rewritten to the session's wire MAC, so the island sees the
 * host as that MAC (DHCP binds the lease to it, peers reply to it). */
static void ac_bridge(struct ac_ctx *c, struct pppoe_session *s,
                      const uint8_t *inner, size_t ilen)
{
    uint8_t out[2048];

    if (ilen > sizeof(out))
        return;
    memcpy(out, inner, ilen);
    memcpy(out + 6, s->wmac, 6);
    l2_send(c->fd, c->ifindex, out, out, ilen);
}

/* process one full inner frame received inside session s */
static void ac_inner(struct ac_ctx *c, struct pppoe_session *s,
                     const uint8_t *inner, size_t ilen)
{
    const struct ethernet_header *ie;
    const struct ipv69_header *ih;
    const uint8_t *ip;
    uint64_t isrc, idst;
    size_t iplen;
    int eth_bcast, dst_bcast;

    if (ilen < 14 + IPV69_HEADER_LEN + 1)
        return;
    ie = (const struct ethernet_header *)inner;
    ih = (const struct ipv69_header *)(inner + 14);
    ip = inner + 14 + IPV69_HEADER_LEN;
    iplen = ilen - 14 - IPV69_HEADER_LEN;
    isrc = get_addr40(ih->source);
    idst = get_addr40(ih->dest);
    eth_bcast = !memcmp(ie->dst_mac, g_bcast, 6);
    dst_bcast = idst == IPV69_BCAST_ADDR;

    /* learn the wire MAC and the address (inner src; the DHCP69
     * REQUEST/ACK snoop covers lease acquisition, when src is still 0) */
    memcpy(s->wmac, ie->src_mac, 6);
    s->last = time(NULL);
    if (isrc)
        s->addr = isrc;
    if (ih->next_header == IPV69_NEXT_CONTROL && iplen >= 12 &&
        (ip[0] == IPV69_CTRL_DHCP_REQUEST || ip[0] == IPV69_CTRL_DHCP_ACK))
        s->addr = get_addr40(ip + 7);

    /* ND lookup (src 0 = DAD/query) for an address this AC owns: answer
     * inside the session - never bridge the query to the island */
    if (ih->next_header == IPV69_NEXT_CONTROL && iplen >= 6 &&
        ip[0] == IPV69_CTRL_ND_REQUEST && isrc == 0) {
        uint64_t target = get_addr40(ip + 1);
        struct pppoe_session *owner = sess_by_addr(c, target);
        char ms[18];

        if (target == c->addr)
            owner = NULL;
        if (owner == s)
            owner = NULL;           /* asking about itself */
        if (owner) {
            uint8_t rep[512];
            uint8_t pp[1 + 5 + 6] = { IPV69_CTRL_ND_REPLY };
            mac_str(s->cmac, ms);
            put_addr40(pp + 1, target);
            memcpy(pp + 7, owner->wmac, 6);
            size_t rl = build_frame(rep, g_bcast, owner->wmac, target,
                                    IPV69_BCAST_ADDR, IPV69_NEXT_CONTROL,
                                    64, 0, 0, pp, sizeof(pp));
            printf("ac: ND %s -> session %u (addr %016llx at %02x:%02x..)\n",
                   ms, s->sid, (unsigned long long)target,
                   owner->wmac[0], owner->wmac[1]);
            ac_session_send(c, s, rep, rl);
            return;
        }
        if (target == c->addr) {
            uint8_t rep[512];
            uint8_t pp[1 + 5 + 6] = { IPV69_CTRL_ND_REPLY };
            put_addr40(pp + 1, target);
            memcpy(pp + 7, c->mac, 6);
            size_t rl = build_frame(rep, g_bcast, c->mac, target,
                                    IPV69_BCAST_ADDR, IPV69_NEXT_CONTROL,
                                    64, 0, 0, pp, sizeof(pp));
            ac_session_send(c, s, rep, rl);
            return;
        }
        /* not ours: let it reach the island (nothing answers ND there
         * today, but a future responder would) */
        if (eth_bcast || dst_bcast)
            ac_bridge(c, s, inner, ilen);
        return;
    }

    /* broadcast inner (DHCP DISCOVER, signed ND announces for an island
     * gateway, bcast dgrams...): bridge to the island */
    if (eth_bcast || dst_bcast) {
        ac_bridge(c, s, inner, ilen);
        return;
    }

    /* unicast inner */
    {
        struct pppoe_session *peer = sess_by_addr(c, idst);
        if (peer && peer != s) {
            printf("ac: session %u -> session %u (addr %016llx)\n",
                   s->sid, peer->sid, (unsigned long long)idst);
            ac_session_send(c, peer, inner, ilen);
        } else if (idst == c->addr) {
            printf("ac: session %u addressed the AC itself (ignored in v0.1)\n",
                   s->sid);
        } else {
            ac_bridge(c, s, inner, ilen);
        }
    }
}

/* classification of one received L2 frame (see spec section 4.2) */
static void ac_rx(struct ac_ctx *c, uint8_t *frame, size_t n)
{
    const struct ethernet_header *eth;
    const struct ipv69_header *h;
    const uint8_t *p;
    size_t plen;
    uint64_t frm_dst;
    uint8_t mkey[32];

    if (n < 14 + IPV69_HEADER_LEN + 1)
        return;
    eth = (const struct ethernet_header *)frame;
    h = (const struct ipv69_header *)(frame + 14);
    p = frame + 14 + IPV69_HEADER_LEN;
    plen = n - 14 - IPV69_HEADER_LEN;
    frm_dst = get_addr40(h->dest);

    if (!memcmp(eth->src_mac, c->mac, 6))
        return;                     /* own TX echo (Npcap loopback) */

    /* session data from a dialed host: unicast to us, demux by the
     * outer Ethernet src (the session's control MAC) */
    if (h->next_header == IPV69_NEXT_PPPOE) {
        struct pppoe_session *s;
        uint16_t sid;

        if (memcmp(eth->dst_mac, c->mac, 6) || plen < 2 + 14 + IPV69_HEADER_LEN)
            return;
        s = sess_by_cmac(c, eth->src_mac);
        if (!s)
            return;
        sid = ipv69_get_be16(p);
        if (sid != s->sid)
            return;
        ac_inner(c, s, frame + 14 + IPV69_HEADER_LEN + 2, plen - 2);
        return;
    }

    /* PPPoE69 discovery (control codes 17-21) */
    if (h->next_header == IPV69_NEXT_CONTROL && plen >= 1 &&
        p[0] >= IPV69_CTRL_PADI && p[0] <= IPV69_CTRL_PADT) {
        uint8_t rid[8] = { 0 };
        char ms[18];
        struct pppoe_session *s;

        if (p[0] == IPV69_CTRL_PADI) {
            /* host discovery probe (broadcast) */
            if (plen != 7 + MAC1_LEN)
                return;
            mac1_key(IPV69_BCAST_ADDR, mkey);
            if (mac1_verify(mkey, p, 7, p + 7) != 0)
                return;             /* silent drop */
            memcpy(rid, p + 1, 6);
            if (!rate_allow(rid, 10, 20, 1))
                return;
            mac_str(p + 1, ms);
            printf("ac: PADI %s -> PADO\n", ms);
            ac_pado(c, p + 1);
            return;
        }
        /* PADR/PADT are unicast to our address */
        if (frm_dst != c->addr || memcmp(eth->dst_mac, c->mac, 6))
            return;
        mac1_key(c->addr, mkey);
        if (p[0] == IPV69_CTRL_PADR) {
            if (plen != 7 + PUB_LEN + SIG_LEN + MAC1_LEN)
                return;
            if (mac1_verify(mkey, p, plen - MAC1_LEN,
                            p + plen - MAC1_LEN) != 0)
                return;
            memcpy(rid, p + 1, 6);
            if (!rate_allow(rid, 10, 20, 1))
                return;
            mac_str(p + 1, ms);
            if (!check_padr(c, p, plen, p + 1)) {
                printf("ac: PADR %s refused\n", ms);
                return;
            }
            s = sess_by_cmac(c, p + 1);
            if (!s) {
                uint16_t sid;
                s = sess_alloc(c, &sid);
                if (!s) {
                    printf("ac: PADR %s: session table full\n", ms);
                    return;
                }
                memcpy(s->cmac, p + 1, 6);
                printf("ac: PADR %s pub %02x%02x.. -> session %u\n",
                       ms, p[7], p[8], s->sid);
            }
            ac_pads(c, s);
            return;
        }
        if (p[0] == IPV69_CTRL_PADT) {
            uint16_t sid;
            if (plen != 3 + MAC1_LEN)
                return;
            if (mac1_verify(mkey, p, 3, p + 3) != 0)
                return;
            sid = ipv69_get_be16(p + 1);
            s = sess_by_sid(c, sid);
            if (s)
                sess_free(c, s);
            return;
        }
        return;                     /* 18/20: another AC's replies */
    }

    /* ND lookup from the island (DAD) for an address we own: answer on
     * the L2, unicast to the asker */
    if (h->next_header == IPV69_NEXT_CONTROL && plen >= 6 &&
        p[0] == IPV69_CTRL_ND_REQUEST &&
        get_addr40(h->source) == 0 && frm_dst == IPV69_BCAST_ADDR) {
        uint64_t target = get_addr40(p + 1);
        struct pppoe_session *owner = sess_by_addr(c, target);
        if (target == c->addr) {
            printf("ac: ND (DAD) for the AC itself\n");
            ac_nd_reply(c, target, c->mac, eth->src_mac);
            return;
        }
        if (owner) {
            printf("ac: ND (DAD) %016llx -> session %u wire MAC\n",
                   (unsigned long long)target, owner->sid);
            ac_nd_reply(c, target, owner->wmac, eth->src_mac);
            return;
        }
    }

    /* data-plane frames on the island (dgram, echo, DHCP replies...):
     * wrap what belongs to a session. 40-bit dst = session address
     * (dialed A <-> dialed B and island-peer unicast flows), or the
     * DHCP69 reply convention: Ethernet unicast to the wire MAC with a
     * broadcast 40-bit dst. */
    if (frm_dst != IPV69_BCAST_ADDR) {
        struct pppoe_session *s = sess_by_addr(c, frm_dst);
        if (s) {
            ac_session_send(c, s, frame, n);
            return;
        }
    }
    if (frm_dst == IPV69_BCAST_ADDR) {
        struct pppoe_session *s = sess_by_wmac(c, eth->dst_mac);
        if (s)
            ac_session_send(c, s, frame, n);
    }
}

/* ---- ac main --------------------------------------------------------- */

static int cmd_pppoe_ac(int argc, char **argv)
{
    struct ac_ctx c;
    uint8_t frame[2048], derived[5];
    time_t now;
    int has_sk = 0;
    struct stat pst = { 0 };

    setvbuf(stdout, NULL, _IONBF, 0);
    memset(&c, 0, sizeof(c));
    c.cls = 'A';

    /* argv: pppoe ac <ifname> [flags...] - parse flags in any position */
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--peer") && i + 1 < argc) {
            uint64_t base;
            int prefix;
            if (c.n_peers >= MAX_PEERS) {
                fprintf(stderr, "peer: limit %d\n", MAX_PEERS);
                return 1;
            }
            if (ipv69_addr_parse_peer(argv[++i], c.peers[c.n_peers],
                                      &base, &prefix) != 0) {
                fprintf(stderr, "peer: invalid pubkey (%s)\n", argv[i]);
                return 1;
            }
            c.n_peers++;
            c.auth_enabled = 1;
        } else if (!strcmp(argv[i], "--peer-file") && i + 1 < argc) {
            c.peer_file = argv[++i];
            c.auth_enabled = 1;
            peer_file_load(&c, c.peer_file);
        } else if (!strcmp(argv[i], "--learn")) {
            c.learn = 1;
        } else if (!strcmp(argv[i], "--class") && i + 1 < argc) {
            c.cls = (char)argv[++i][0];
        } else if (!strcmp(argv[i], "--key") && i + 1 < argc) {
            uint8_t seed[32];
            if (hex_decode(argv[++i], seed, 32) != 32) {
                fprintf(stderr, "key: invalid private key (32 bytes hex)\n");
                return 1;
            }
            memcpy(c.sk, seed, 32);
            ed25519_seed_to_pub(c.sk + 32, seed);
            has_sk = 1;
        }
    }
    if (c.cls != 'A' && c.cls != 'B' && c.cls != 'C') {
        fprintf(stderr, "ac: invalid class '%c' (A-C)\n", c.cls);
        return 1;
    }
    /* the AC must have a key: PADO/PADS are signed so the host can
       validate the concentrator it dialed */
    if (!has_sk && load_auto_key(c.sk) < 0)
        return 1;
    ipv69_addr_derive(derived, c.sk + 32, c.cls);
    c.addr = get_addr40(derived);

    if (l2_open(argv[2], &c.fd, &c.ifindex, c.mac) < 0)
        return 1;
    /* catch unicast replies addressed to the dialed hosts' wire MACs */
    l2_set_promisc(c.fd, c.ifindex, 1);

    printf("ac: raw L2 (%s), addr %02x.%02x.%02x.%02x.%02x (class %c), "
           "mac %02x:%02x:%02x:%02x:%02x:%02x\n",
           argv[2], derived[0], derived[1], derived[2], derived[3],
           derived[4], c.cls, c.mac[0], c.mac[1], c.mac[2],
           c.mac[3], c.mac[4], c.mac[5]);
    printf("ac: peers=%d pubkey(s), learn=%s\n",
           c.n_peers, c.learn ? "yes" : "no");
#ifndef _WIN32
    if (c.peer_file)
        signal(SIGHUP, SIG_IGN);
#endif
    if (c.peer_file)
        stat(c.peer_file, &pst);

    for (;;) {
        /* peer-file mtime poll + idle session reaping run on the 1s
           tick even without traffic */
        if (c.peer_file) {
            struct stat nst;
            if (stat(c.peer_file, &nst) == 0 &&
                (nst.st_mtime != pst.st_mtime || nst.st_size != pst.st_size)) {
                pst = nst;
                printf("ac: peer-file changed, reloading...\n");
                peer_file_load(&c, c.peer_file);
            }
        }
        now = time(NULL);
        for (int i = 0; i < MAX_SESSIONS; i++) {
            if (c.sess[i].used && now - c.sess[i].last > SESSION_IDLE) {
                printf("ac: session %u idle, sending PADT\n", c.sess[i].sid);
                ac_padt(&c, &c.sess[i]);
                sess_free(&c, &c.sess[i]);
            }
        }
        ssize_t n = l2_recv(c.fd, frame, sizeof(frame), 1000);
        if (n > 0)
            ac_rx(&c, frame, (size_t)n);
    }
    return 0;
}

/* =====================================================================
 * host (dial) - Linux only (TAP leg)
 * =================================================================== */

#ifndef _WIN32

struct host_ctx {
    l2_handle fd;
    int ifindex;
    uint8_t mac[6];             /* control MAC (the dial socket's) */
    uint8_t ac_mac[6];          /* the concentrator we dialed */
    uint64_t ac_addr;
    uint8_t ac_pub[PUB_LEN];    /* from PADO, validates PADS */
    const uint8_t *pin_pub;     /* --ac-pub (stricter, optional) */
    uint16_t sid;
    uint8_t sk[64];
    uint64_t want_ac;           /* --ac: only dial this concentrator */
    int tapfd;
};

static volatile sig_atomic_t g_quit = 0;

static void on_int(int sig)
{
    (void)sig;
    g_quit = 1;
}

/* ---- TAP ------------------------------------------------------------ */

static int tap_create(const char *name)
{
    int fd = open("/dev/net/tun", O_RDWR);
    struct ifreq ifr;

    if (fd < 0) { perror("open /dev/net/tun"); return -1; }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) { perror("TUNSETIFF"); close(fd); return -1; }
    return fd;
}

static void tap_up(const char *name)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;

    if (fd < 0) return;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        ioctl(fd, SIOCSIFFLAGS, &ifr);
    }
    close(fd);
}

/* ---- discovery tx ---------------------------------------------------- */

/* send one control payload: PADI goes to the Ethernet + 40-bit
 * broadcast with src 0 (unconfigured, like the DHCP DISCOVER); PADR and
 * PADT go unicast to the AC (eth + 40-bit) with the mac1 key bound to
 * the AC address. */
static int host_send_ctrl(struct host_ctx *h, const uint8_t *payload,
                          size_t plen, int to_ac)
{
    const uint8_t *edst = to_ac ? h->ac_mac : g_bcast;
    uint64_t daddr = to_ac ? h->ac_addr : IPV69_BCAST_ADDR;
    uint8_t frame[2048];

    size_t l = build_frame(frame, edst, h->mac, 0, daddr,
                           IPV69_NEXT_CONTROL, 64, 0, 0, payload, plen);
    return l2_send(h->fd, h->ifindex, edst, frame, l);
}

/* wait for a control frame with `code` whose payload MAC (at +1, when
 * mac_match is set) is ours; copies the payload out. 0 on timeout. */
static ssize_t host_wait_ctrl(struct host_ctx *h, uint8_t code,
                              int mac_match, uint8_t *out, size_t outsz,
                              int timeout_ms)
{
    uint8_t frame[2048];

    for (;;) {
        ssize_t n = l2_recv(h->fd, frame, sizeof(frame), timeout_ms);
        const struct ethernet_header *eth;
        const struct ipv69_header *ih;
        const uint8_t *p;
        size_t plen;

        if (n <= 0)
            return 0;               /* timeout */
        if (n < 14 + IPV69_HEADER_LEN + 1)
            continue;
        eth = (const struct ethernet_header *)frame;
        if (!memcmp(eth->src_mac, h->mac, 6))
            continue;               /* own TX echo */
        ih = (const struct ipv69_header *)(frame + 14);
        if (ih->next_header != IPV69_NEXT_CONTROL)
            continue;
        p = frame + 14 + IPV69_HEADER_LEN;
        plen = (size_t)n - 14 - IPV69_HEADER_LEN;
        if (plen < 1 || p[0] != code)
            continue;
        if (mac_match && (plen < 7 || memcmp(p + 1, h->mac, 6)))
            continue;
        if (plen > outsz)
            plen = outsz;
        memcpy(out, p, plen);
        return (ssize_t)plen;
    }
}

/* validate a signed AC message against the pub at `poff` whose
 * signature covers body bytes; pins --ac-pub when given. */
static int host_check_sig(struct host_ctx *h, const uint8_t *p,
                          size_t body, size_t poff)
{
    const uint8_t *pub = p + poff;
    const uint8_t *sig = pub + PUB_LEN;
    char ps[65];

    if (h->pin_pub && memcmp(pub, h->pin_pub, PUB_LEN)) {
        pub_str(pub, ps);
        printf("host: concentrator pub %s != --ac-pub, ignoring\n", ps);
        return 0;
    }
    return ed25519_verify(p, body, sig, pub) == 0;
}

static void host_padt(struct host_ctx *h)
{
    uint8_t p[1 + 2 + MAC1_LEN], mkey[32];

    p[0] = IPV69_CTRL_PADT;
    ipv69_put_be16(p + 1, h->sid);
    mac1_key(h->ac_addr, mkey);
    mac1_compute(mkey, p, 3, p + 3);
    host_send_ctrl(h, p, sizeof(p), 1);
}

/* dial: PADI -> PADO -> PADR -> PADS. Fills h->sid/ac_mac/ac_addr. */
static int host_dial(struct host_ctx *h, const char *ifname)
{
    uint8_t padi[1 + 6 + MAC1_LEN], padr[1 + 6 + PUB_LEN + SIG_LEN + MAC1_LEN];
    uint8_t rx[256], mkey[32];
    int attempt, got_pado = 0;
    ssize_t n;

    /* PADI [17][mac 6][mac1 16], mac1 keyed by the broadcast dst */
    padi[0] = IPV69_CTRL_PADI;
    memcpy(padi + 1, h->mac, 6);
    mac1_key(IPV69_BCAST_ADDR, mkey);
    mac1_compute(mkey, padi, 7, padi + 7);
    for (attempt = 0; attempt < 3 && !got_pado; attempt++) {
        if (attempt > 0) {
            plat_sleep_ms(300 * attempt);
            printf("host: PADI retry %d\n", attempt + 1);
        }
        if (host_send_ctrl(h, padi, sizeof(padi), 0) < 0) {
            perror("send PADI");
            return -1;
        }
        printf("host: PADI sent on %s, waiting for a concentrator...\n",
               ifname);
        for (;;) {
            n = host_wait_ctrl(h, IPV69_CTRL_PADO, 1, rx, sizeof(rx), 1500);
            if (n <= 0)
                break;              /* timeout: retry PADI */
            if (n != 1 + 6 + 6 + 5 + PUB_LEN + SIG_LEN)
                continue;
            if (h->want_ac && get_addr40(rx + 13) != h->want_ac)
                continue;           /* not the concentrator we want */
            if (!host_check_sig(h, rx, 18, 18))
                continue;           /* rogue/unknown AC: try another PADO */
            memcpy(h->ac_mac, rx + 7, 6);
            h->ac_addr = get_addr40(rx + 13);
            memcpy(h->ac_pub, rx + 18, PUB_LEN);
            got_pado = 1;
            break;
        }
    }
    if (!got_pado) {
        fprintf(stderr, "host: no concentrator answered (PADO timeout)\n");
        return -1;
    }
    printf("host: PADO from ac %02x:%02x:%02x:%02x:%02x:%02x addr "
           "%016llx pub %02x%02x..\n",
           h->ac_mac[0], h->ac_mac[1], h->ac_mac[2], h->ac_mac[3],
           h->ac_mac[4], h->ac_mac[5], (unsigned long long)h->ac_addr,
           h->ac_pub[0], h->ac_pub[1]);

    /* PADR [19][mac 6][pub 32][sig 64][mac1 16]: signed with our key,
     * mac1 keyed by the AC address (the frame's 40-bit dst) */
    padr[0] = IPV69_CTRL_PADR;
    memcpy(padr + 1, h->mac, 6);
    memcpy(padr + 7, h->sk + 32, PUB_LEN);
    if (ed25519_sign(padr + 7 + PUB_LEN, padr, 7, h->sk) < 0)
        return -1;
    mac1_key(h->ac_addr, mkey);
    mac1_compute(mkey, padr, 7 + PUB_LEN + SIG_LEN,
                 padr + 7 + PUB_LEN + SIG_LEN);
    if (host_send_ctrl(h, padr, sizeof(padr), 1) < 0) {
        perror("send PADR");
        return -1;
    }
    printf("host: PADR sent (pub %02x%02x..)\n", h->sk[32], h->sk[33]);

    for (attempt = 0; attempt < 3; attempt++) {
        if (attempt > 0) {
            plat_sleep_ms(300 * attempt);
            host_send_ctrl(h, padr, sizeof(padr), 1);   /* re-send PADR */
        }
        n = host_wait_ctrl(h, IPV69_CTRL_PADS, 1, rx, sizeof(rx), 1500);
        if (n <= 0)
            continue;
        if (n != 1 + 6 + 2 + PUB_LEN + SIG_LEN)
            continue;
        if (memcmp(rx + 9, h->ac_pub, PUB_LEN))
            continue;               /* not the AC we dialed */
        if (!host_check_sig(h, rx, 9, 9))
            continue;
        h->sid = ipv69_get_be16(rx + 7);
        printf("host: PADS sid=%u\n", h->sid);
        return 0;
    }
    fprintf(stderr, "host: session refused (PADS timeout)\n");
    return -1;
}

static int cmd_pppoe_host(int argc, char **argv)
{
    struct host_ctx h;
    const char *ifname = argv[2];
    const char *tapname = "ip69p0";
    uint8_t pin[PUB_LEN];
    int has_pin = 0;
    uint8_t frame[2048];

    memset(&h, 0, sizeof(h));
    h.tapfd = -1;
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--tap") && i + 1 < argc)
            tapname = argv[++i];
        else if (!strcmp(argv[i], "--ac-pub") && i + 1 < argc) {
            if (hex_decode(argv[++i], pin, PUB_LEN) != PUB_LEN) {
                fprintf(stderr, "ac-pub: invalid pubkey (32 bytes hex)\n");
                return 1;
            }
            has_pin = 1;
        } else if (!strcmp(argv[i], "--ac") && i + 1 < argc) {
            if (parse_ipv69_addr(argv[++i], &h.want_ac) < 0) {
                fprintf(stderr, "ac: invalid address %s\n", argv[i]);
                return 1;
            }
        }
    }
    if (has_pin)
        h.pin_pub = pin;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (load_auto_key(h.sk) < 0)
        return 1;
    if (l2_open(ifname, &h.fd, &h.ifindex, h.mac) < 0)
        return 1;
    printf("host: dial iface=%s mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
           ifname, h.mac[0], h.mac[1], h.mac[2], h.mac[3], h.mac[4],
           h.mac[5]);

    if (host_dial(&h, ifname) < 0)
        return 1;

    /* expose the session as a TAP: the normal tools run over ip69p0 */
    h.tapfd = tap_create(tapname);
    if (h.tapfd < 0) {
        fprintf(stderr, "host: session up but no TAP (need root?); "
                "sending PADT\n");
        host_padt(&h);
        return 1;
    }
    tap_up(tapname);
    printf("host: session %u up via %s - run the stack on it, e.g.\n"
           "      ipv69 dhcp %s / recv %s / send %s <dst>:16 msg\n",
           h.sid, tapname, tapname, tapname, tapname);

    signal(SIGINT, on_int);
    signal(SIGTERM, on_int);

    struct pollfd pfd[2];
    pfd[0].fd = (int)h.fd;
    pfd[0].events = POLLIN;
    pfd[1].fd = h.tapfd;
    pfd[1].events = POLLIN;
    for (;;) {
        if (g_quit) {
            printf("host: closing session %u (PADT)\n", h.sid);
            host_padt(&h);
            return 0;
        }
        if (poll(pfd, 2, 500) <= 0)
            continue;
        if (pfd[0].revents & POLLIN) {
            ssize_t n = l2_recv(h.fd, frame, sizeof(frame), 100);
            const struct ethernet_header *eth;
            const struct ipv69_header *ih;
            const uint8_t *p;
            uint16_t sid;

            if (n < 14 + IPV69_HEADER_LEN + 1)
                continue;
            eth = (const struct ethernet_header *)frame;
            if (!memcmp(eth->src_mac, h.mac, 6))
                continue;           /* own TX echo */
            ih = (const struct ipv69_header *)(frame + 14);
            p = frame + 14 + IPV69_HEADER_LEN;
            if (ih->next_header == IPV69_NEXT_CONTROL) {
                size_t plen = (size_t)n - 14 - IPV69_HEADER_LEN;
                if (plen >= 3 && p[0] == IPV69_CTRL_PADT) {
                    sid = ipv69_get_be16(p + 1);
                    if (sid == h.sid) {
                        printf("host: concentrator closed session %u\n",
                               h.sid);
                        return 0;
                    }
                }
                continue;
            }
            if (ih->next_header != IPV69_NEXT_PPPOE ||
                (size_t)n < 14 + IPV69_HEADER_LEN + 2 + 14 + IPV69_HEADER_LEN)
                continue;
            sid = ipv69_get_be16(p);
            if (sid != h.sid)
                continue;
            /* unwrap and hand the inner frame to the TAP */
            if (write(h.tapfd, frame + 14 + IPV69_HEADER_LEN + 2,
                      (size_t)n - 14 - IPV69_HEADER_LEN - 2) < 0) {
                perror("write tap");
                return 1;
            }
        }
        if (pfd[1].revents & POLLIN) {
            ssize_t r = read(h.tapfd, frame, sizeof(frame) - 2 -
                             14 - IPV69_HEADER_LEN);
            uint8_t buf[2048], out[2048];

            if (r <= 0)
                continue;
            if ((size_t)r > sizeof(buf) - 2)
                continue;
            /* wrap the app frame into the session and send to the AC */
            ipv69_put_be16(buf, h.sid);
            memcpy(buf + 2, frame, (size_t)r);
            size_t l = build_frame(out, h.ac_mac, h.mac, 0, h.ac_addr,
                                   IPV69_NEXT_PPPOE, 64, 0, 0, buf,
                                   2 + (size_t)r);
            if (l2_send(h.fd, h.ifindex, h.ac_mac, out, l) < 0)
                perror("session send");
        }
    }
    return 0;
}
#endif /* !_WIN32 */

/* =====================================================================
 * dispatcher
 * =================================================================== */

int cmd_pppoe(int argc, char **argv)
{
    const char *role;
    char *na[32];
    int n = argc;

    if (argc < 2) {
        fprintf(stderr,
                "Usage: ipv69 pppoe <ac|host> [ifname] [options]\n"
                "  ac    access concentrator: terminate sessions, bridge\n"
                "        the dialed hosts onto your L2 leg\n"
                "  host  dial a session and expose it as a TAP (Linux)\n"
                "  [ifname] is OPTIONAL: omit it (or write 'auto') to use\n"
                "  the default-route interface\n");
        return 1;
    }
    role = argv[1];
    if (strcmp(role, "ac") && strcmp(role, "host")) {
        fprintf(stderr, "pppoe: unknown role '%s' (ac|host)\n", role);
        return 1;
    }
    /* ifname omitted (nothing or an option in position 2): insert auto */
    if (n < 3 || argv[2][0] == '-') {
        if (n >= 31) {
            fprintf(stderr, "pppoe: too many arguments\n");
            return 1;
        }
        for (int i = 0; i < argc && i < 31; i++)
            na[i] = argv[i];
        for (int i = n; i > 2; i--)
            na[i] = na[i - 1];
        na[2] = "auto";
        n++;
        argv = na;
    }
#ifdef _WIN32
    if (!strcmp(role, "host")) {
        fprintf(stderr, "pppoe: 'host' is not supported on Windows "
                "(needs a TAP interface)\n");
        return 1;
    }
#else
    if (!strcmp(role, "host"))
        return cmd_pppoe_host(n, argv);
#endif
    return cmd_pppoe_ac(n, argv);
}
