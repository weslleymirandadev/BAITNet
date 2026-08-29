// SPDX-License-Identifier: GPL-2.0
/*
 * af69 - IPv69 socket address family (experimental protocol 0x6969).
 *
 * Registers the AF_69 socket family and a packet_type for EtherType
 * 0x6969. SOCK_DGRAM moves the 253 datagram (ports + payload) over raw
 * L2 Ethernet frames — no IPv4/IPv6 dependency anywhere.
 *
 * Stack (v0.3):
 *   - demux: RX delivers to sockets matching dst address (or bound port);
 *     unbound sockets (src=0) receive everything (promiscuous)
 *   - hop limit: decremented on forward, dropped at 0 (+ TIME_EXCEEDED)
 *   - forwarding: frames for a non-local dst are re-emitted on another
 *     up interface of the same netns (simple route, no table yet)
 *   - neighbor discovery: 40-bit -> MAC cache, learned from RX; ND
 *     request/reply resolves unknown destinations (ARP-like)
 *   - control (next_header 255): ND request/reply, echo request/reply
 *     (ping), dest unreachable, time exceeded
 *   - next_header 254 (STREAM) is RESERVED for a future transport
 *     protocol (SCTP-derived), not implemented here
 *
 * Usage: socket(AF_69, SOCK_DGRAM, 0)
 *   bind(sockaddr_69 { ifindex, src, dst_port })  — iface + local addr + port
 *   sendto(sockaddr_69 { dst, src_port, dst_port, next_header, hop_limit })
 *   recvfrom(sockaddr_69)                         — src/dst/ports/next_header
 *
 * Requires the kernel patch af69-kernel.patch (AF_69=69, AF_MAX=70).
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/uio.h>
#include <net/sock.h>

#define IPV69_ETHERTYPE     0x6969
#define IPV69_VERSION       6
#define IPV69_TRAFFIC_CLASS 9
#define IPV69_HEADER_LEN    32
#define IPV69_NEXT_DGRAM    253
#define IPV69_NEXT_STREAM   254     /* reserved (future SCTP-derived transport) */
#define IPV69_NEXT_CONTROL  255
#define IPV69_FLAG_NOFRAG   (1 << 0)
#define IPV69_MAX_PAYLOAD   1400
#define IPV69_DEFAULT_HOP   64
#define IPV69_BCAST_ADDR    0xFFFFFFFFFFULL
#define IPV69_ND_ENTRIES    16

/* control payload[0] types (next_header 255) */
#define IPV69_CTRL_ND_REQUEST    1
#define IPV69_CTRL_ND_REPLY      2
#define IPV69_CTRL_ECHO_REQUEST  3
#define IPV69_CTRL_ECHO_REPLY    4
#define IPV69_CTRL_UNREACHABLE   5
#define IPV69_CTRL_TIME_EXCEEDED 6

#define IPV69_AF AF_69

/* keep in sync with include/IPv69/af69.h (userspace) */
struct sockaddr_69 {
    __u16 sa_family;
    __u16 ifindex;
    __u64 src;
    __u64 dst;
    __u16 src_port;
    __u16 dst_port;
    __u16 next_header;  /* 0/253 dgram, 255 control; 254 reserved */
    __u8  hop_limit;    /* 0 = default (64) */
    __u8  reserved;
};

struct ipv69_hdr {
    __u8  ver_traffic;
    __u8  dscp_ecn;
    __be16 payload_len;
    __be16 flow_id;
    __u8  next_header;
    __u8  hop_limit;
    __u8  flags;
    __u8  reserved;
    __be16 reserved2;
    __be32 sequence;
    __u8  source[5];     /* 40-bit address */
    __u8  source_res[3];
    __u8  dest[5];       /* 40-bit address */
    __u8  dest_res[3];
};

struct ipv69_neigh {
    __u64 addr;                 /* 40-bit IPv69 address */
    u8    mac[ETH_ALEN];
    unsigned long used;
};

struct ipv69_sock {
    struct sock sk;
    struct list_head list;   /* all live AF_69 sockets (rx demux) */
    int ifindex;             /* bind(): 0 = auto-detect on send */
    __u64 src_addr;
    __u64 dst_addr;
    __u16 dst_port;          /* bind(): local port filter (0 = any) */
};

static LIST_HEAD(ipv69_socks);
static DEFINE_SPINLOCK(ipv69_lock);
static struct ipv69_neigh ipv69_nd_tab[IPV69_ND_ENTRIES];
static const u8 ipv69_bcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static inline struct ipv69_sock *ipv69_sk(struct sock *sk)
{
    return container_of(sk, struct ipv69_sock, sk);
}

/* 40-bit address helpers (wire: 5 octets, big-endian) */
static void ipv69_put_addr(u8 *dst, u64 v)
{
    dst[0] = (v >> 32) & 0xff;
    dst[1] = (v >> 24) & 0xff;
    dst[2] = (v >> 16) & 0xff;
    dst[3] = (v >> 8) & 0xff;
    dst[4] = v & 0xff;
}

static u64 ipv69_get_addr(const u8 *src)
{
    return ((u64)src[0] << 32) | ((u64)src[1] << 24) |
           ((u64)src[2] << 16) | ((u64)src[3] << 8) | src[4];
}

/* ---- neighbor discovery cache -------------------------------------- */

static bool ipv69_nd_lookup(u64 addr, u8 *mac)
{
    int i;
    bool found = false;

    spin_lock_bh(&ipv69_lock);
    for (i = 0; i < IPV69_ND_ENTRIES; i++) {
        if (ipv69_nd_tab[i].used && ipv69_nd_tab[i].addr == addr) {
            memcpy(mac, ipv69_nd_tab[i].mac, ETH_ALEN);
            found = true;
            break;
        }
    }
    spin_unlock_bh(&ipv69_lock);
    return found;
}

static void ipv69_nd_learn(u64 addr, const u8 *mac)
{
    int i, slot = -1, oldest = 0;
    unsigned long now = jiffies;

    if (!addr)
        return;
    spin_lock_bh(&ipv69_lock);
    for (i = 0; i < IPV69_ND_ENTRIES; i++) {
        if (ipv69_nd_tab[i].used && ipv69_nd_tab[i].addr == addr) {
            memcpy(ipv69_nd_tab[i].mac, mac, ETH_ALEN);
            ipv69_nd_tab[i].used = now;
            goto out;
        }
        if (!ipv69_nd_tab[i].used)
            slot = i;
        if (!ipv69_nd_tab[oldest].used ||
            ipv69_nd_tab[i].used < ipv69_nd_tab[oldest].used)
            oldest = i;
    }
    slot = (slot >= 0) ? slot : oldest;
    ipv69_nd_tab[slot].addr = addr;
    memcpy(ipv69_nd_tab[slot].mac, mac, ETH_ALEN);
    ipv69_nd_tab[slot].used = now;
out:
    spin_unlock_bh(&ipv69_lock);
}

static struct proto ipv69_proto = {
    .name     = "IPV69",
    .owner    = THIS_MODULE,
    .obj_size = sizeof(struct ipv69_sock),
};

static const struct proto_ops ipv69_ops;

static int ipv69_create(struct net *net, struct socket *sock, int protocol,
                        int kern)
{
    struct sock *sk;

    if (sock->type != SOCK_DGRAM)
        return -ESOCKTNOSUPPORT;
    if (protocol != 0)
        return -EPROTONOSUPPORT;

    sk = sk_alloc(net, IPV69_AF, GFP_KERNEL, &ipv69_proto, kern);
    if (!sk)
        return -ENOMEM;

    sock_init_data(sock, sk);
    sock->ops = &ipv69_ops;
    sk->sk_family = IPV69_AF;

    spin_lock_bh(&ipv69_lock);
    list_add_tail(&ipv69_sk(sk)->list, &ipv69_socks);
    spin_unlock_bh(&ipv69_lock);
    return 0;
}

static int ipv69_bind(struct socket *sock, struct sockaddr *addr, int addrlen)
{
    struct sockaddr_69 *sa = (struct sockaddr_69 *)addr;
    struct ipv69_sock *is = ipv69_sk(sock->sk);
    struct net *net = sock_net(sock->sk);

    if (addrlen < sizeof(struct sockaddr_69))
        return -EINVAL;
    if (sa->sa_family != IPV69_AF)
        return -EAFNOSUPPORT;
    if (sa->ifindex) {
        struct net_device *dev = dev_get_by_index(net, sa->ifindex);
        if (!dev)
            return -ENODEV;
        dev_put(dev);
    }
    is->ifindex = sa->ifindex;
    is->src_addr = sa->src;
    is->dst_port = sa->dst_port;
    if (sa->dst)
        is->dst_addr = sa->dst;
    return 0;
}

static int ipv69_connect(struct socket *sock, struct sockaddr *addr,
                         int addrlen, int flags)
{
    return ipv69_bind(sock, addr, addrlen);
}

/* auto-detect: first Ethernet (ARPHRD_ETHER) up with carrier; fallback any
 * up non-loopback interface with an L2 address. Pure layer 2. */
static int ipv69_default_ifindex(struct net *net)
{
    struct net_device *dev;
    int ifindex = 0;

    rcu_read_lock();
    for_each_netdev_rcu(net, dev) {
        if (dev->flags & IFF_LOOPBACK)
            continue;
        if (!(dev->flags & IFF_UP))
            continue;
        if (dev->type == ARPHRD_ETHER && netif_carrier_ok(dev)) {
            ifindex = dev->ifindex;
            break;
        }
    }
    if (!ifindex) {
        for_each_netdev_rcu(net, dev) {
            if (dev->flags & IFF_LOOPBACK)
                continue;
            if (!(dev->flags & IFF_UP))
                continue;
            if (dev->addr_len > 0) {
                ifindex = dev->ifindex;
                break;
            }
        }
    }
    rcu_read_unlock();
    return ifindex;
}

/* forwarding route: first up non-loopback interface != orig, carrier
 * preferred. No routing table yet — enough for a 2-interface relay. */
static struct net_device *ipv69_fwd_dev(struct net *net,
                                        struct net_device *orig)
{
    struct net_device *dev;
    struct net_device *fallback = NULL;

    rcu_read_lock();
    for_each_netdev_rcu(net, dev) {
        if (dev == orig || (dev->flags & IFF_LOOPBACK))
            continue;
        if (!(dev->flags & IFF_UP))
            continue;
        if (dev->addr_len > 0) {
            if (dev->type == ARPHRD_ETHER && netif_carrier_ok(dev)) {
                dev_hold(dev);
                rcu_read_unlock();
                return dev;
            }
            if (!fallback)
                fallback = dev;
        }
    }
    if (fallback)
        dev_hold(fallback);
    rcu_read_unlock();
    return fallback;
}

/* build + transmit one IPv69 frame. sk may be NULL (kernel-originated:
 * forwarding, ND/echo replies, errors). */
static int ipv69_xmit(struct sock *sk, struct net *net,
                      struct net_device *dev, const u8 *dst_mac,
                      u64 src_addr, u64 dst_addr, u8 next_header,
                      u8 hop_limit, const u8 *payload, size_t plen)
{
    struct sk_buff *skb;
    struct ipv69_hdr *h;
    int err;
    size_t total = LL_RESERVED_SPACE(dev) + IPV69_HEADER_LEN + plen;

    if (plen > IPV69_MAX_PAYLOAD)
        return -EMSGSIZE;

    if (sk)
        skb = sock_alloc_send_skb(sk, total, 1, &err);
    else
        skb = alloc_skb(total, GFP_ATOMIC);
    if (!skb)
        return sk ? err : -ENOMEM;

    skb_reserve(skb, LL_RESERVED_SPACE(dev));
    skb->dev = dev;
    skb->protocol = htons(IPV69_ETHERTYPE);

    err = dev_hard_header(skb, dev, IPV69_ETHERTYPE, dst_mac,
                          dev->dev_addr, IPV69_HEADER_LEN + plen);
    if (err < 0)
        goto out_free;

    h = skb_put(skb, IPV69_HEADER_LEN);
    memset(h, 0, IPV69_HEADER_LEN);
    h->ver_traffic = (IPV69_VERSION << 4) | IPV69_TRAFFIC_CLASS;
    h->payload_len = htons(plen);
    h->flow_id = htons(1);
    h->next_header = next_header;
    h->hop_limit = hop_limit ? hop_limit : IPV69_DEFAULT_HOP;
    h->flags = IPV69_FLAG_NOFRAG;
    h->sequence = htonl(1);
    ipv69_put_addr(h->source, src_addr);
    ipv69_put_addr(h->dest, dst_addr);
    memcpy(skb_put(skb, plen), payload, plen);

    err = dev_queue_xmit(skb);
    return err < 0 ? err : 0;

out_free:
    kfree_skb(skb);
    return err;
}

/* control error: [type][original ipv69 header 32B], unicast to the MAC
 * that sent the offending frame. src=0 (no router address yet). */
static void ipv69_send_err(struct net *net, struct net_device *dev,
                           const u8 *dst_mac, const struct ipv69_hdr *h,
                           u8 type)
{
    u8 buf[1 + IPV69_HEADER_LEN];

    buf[0] = type;
    memcpy(buf + 1, h, IPV69_HEADER_LEN);
    ipv69_xmit(NULL, net, dev, dst_mac, 0, ipv69_get_addr(h->source),
               IPV69_NEXT_CONTROL, IPV69_DEFAULT_HOP, buf, sizeof(buf));
}

static int ipv69_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
    struct ipv69_sock *is = ipv69_sk(sock->sk);
    struct net *net = sock_net(sock->sk);
    struct net_device *dev;
    __u64 dst = is->dst_addr, src = is->src_addr;
    __u16 src_port = 0, dst_port = 0;
    __u8 next_header = IPV69_NEXT_DGRAM, hop_limit = 0;
    u8 payload[IPV69_MAX_PAYLOAD];
    u8 dst_mac[ETH_ALEN];
    size_t plen;
    int ifindex = is->ifindex;
    int err;

    if (msg->msg_name) {
        struct sockaddr_69 *sa = msg->msg_name;
        if (msg->msg_namelen < sizeof(struct sockaddr_69))
            return -EINVAL;
        if (sa->sa_family != IPV69_AF)
            return -EAFNOSUPPORT;
        if (sa->ifindex)
            ifindex = sa->ifindex;
        if (sa->dst)
            dst = sa->dst;
        if (sa->src)
            src = sa->src;
        src_port = sa->src_port;
        dst_port = sa->dst_port;
        next_header = sa->next_header ? sa->next_header : IPV69_NEXT_DGRAM;
        hop_limit = sa->hop_limit;
    }
    if (next_header != IPV69_NEXT_DGRAM && next_header != IPV69_NEXT_CONTROL)
        return -EPROTONOSUPPORT;
    if (len > IPV69_MAX_PAYLOAD)
        return -EMSGSIZE;

    /* dgram: [src_port 2][dst_port 2][data]; control: [type][data] */
    if (next_header == IPV69_NEXT_DGRAM) {
        plen = 4 + len;
        if (plen > IPV69_MAX_PAYLOAD)
            return -EMSGSIZE;
        payload[0] = src_port >> 8;
        payload[1] = src_port & 0xff;
        payload[2] = dst_port >> 8;
        payload[3] = dst_port & 0xff;
    } else {
        plen = len;
    }
    if (!copy_from_iter_full(payload + plen - len, len, &msg->msg_iter))
        return -EFAULT;

    if (!ifindex) {
        ifindex = ipv69_default_ifindex(net);
        if (!ifindex)
            return -ENETDOWN;
    }
    dev = dev_get_by_index(net, ifindex);
    if (!dev)
        return -ENODEV;
    if (!(dev->flags & IFF_UP)) {
        err = -ENETDOWN;
        goto out_dev;
    }

    if (dst != IPV69_BCAST_ADDR && !ipv69_nd_lookup(dst, dst_mac)) {
        /* unknown neighbor: broadcast + ND request (ARP-like) */
        u8 req[1 + 5] = { IPV69_CTRL_ND_REQUEST };
        ipv69_put_addr(req + 1, dst);
        ipv69_xmit(NULL, net, dev, ipv69_bcast, src, dst,
                   IPV69_NEXT_CONTROL, hop_limit, req, sizeof(req));
        memcpy(dst_mac, ipv69_bcast, ETH_ALEN);
    }

    err = ipv69_xmit(sock->sk, net, dev,
                     dst == IPV69_BCAST_ADDR ? ipv69_bcast : dst_mac,
                     src, dst, next_header, hop_limit, payload, plen);
    dev_put(dev);
    return err < 0 ? err : (int)len;

out_dev:
    dev_put(dev);
    return err;
}

/* is there a live socket in this netns bound to addr? */
static bool ipv69_is_local(struct net *net, u64 addr)
{
    struct ipv69_sock *is;
    bool found = false;

    spin_lock_bh(&ipv69_lock);
    list_for_each_entry(is, &ipv69_socks, list) {
        if (sock_flag(&is->sk, SOCK_DEAD))
            continue;
        if (sock_net(&is->sk) != net)
            continue;
        if (is->src_addr == addr) {
            found = true;
            break;
        }
    }
    spin_unlock_bh(&ipv69_lock);
    return found;
}

static void ipv69_deliver(struct sk_buff *skb, const struct ipv69_hdr *h,
                          struct net_device *dev)
{
    struct ipv69_sock *is;
    struct sock *sk;
    __u64 dst = ipv69_get_addr(h->dest);
    __u16 fport = 0;

    if (h->next_header == IPV69_NEXT_DGRAM)
        fport = (skb->data[IPV69_HEADER_LEN + 2] << 8) |
                skb->data[IPV69_HEADER_LEN + 3];

    spin_lock_bh(&ipv69_lock);
    list_for_each_entry(is, &ipv69_socks, list) {
        struct sk_buff *skb2;

        sk = &is->sk;
        if (sock_flag(sk, SOCK_DEAD))
            continue;
        if (sock_net(sk) != dev_net(skb->dev))
            continue;   /* do not leak frames across net namespaces */
        if (atomic_read(&sk->sk_rmem_alloc) >= sk->sk_rcvbuf)
            continue;
        /* address demux: bound socket only gets its address or broadcast;
           unbound (src=0) is promiscuous */
        if (is->src_addr && is->src_addr != dst && dst != IPV69_BCAST_ADDR)
            continue;
        /* port demux (dgram only) */
        if (is->dst_port && fport && is->dst_port != fport)
            continue;
        skb2 = skb_clone(skb, GFP_ATOMIC);
        if (!skb2)
            continue;
        skb_set_owner_r(skb2, sk);
        skb_queue_tail(&sk->sk_receive_queue, skb2);
        sk->sk_data_ready(sk);
    }
    spin_unlock_bh(&ipv69_lock);
}

/* control plane: act on ND/echo, leave replies/errors to delivery */
static void ipv69_handle_ctrl(struct sk_buff *skb, const struct ipv69_hdr *h,
                              struct net_device *dev)
{
    struct net *net = dev_net(dev);
    u8 type = skb->data[IPV69_HEADER_LEN];
    u64 src = ipv69_get_addr(h->source);
    u64 dst = ipv69_get_addr(h->dest);
    const u8 *smac = eth_hdr(skb)->h_source;
    size_t plen = ntohs(h->payload_len);
    u8 buf[IPV69_MAX_PAYLOAD];
    const u8 *d = skb->data + IPV69_HEADER_LEN + 1;

    switch (type) {
    case IPV69_CTRL_ND_REQUEST:
        if (dst == 0 || dst == IPV69_BCAST_ADDR)
            return;
        if (!ipv69_is_local(net, dst))
            return;
        /* reply: [type][my addr 5][my mac 6] unicast to requester */
        buf[0] = IPV69_CTRL_ND_REPLY;
        ipv69_put_addr(buf + 1, dst);
        memcpy(buf + 6, dev->dev_addr, ETH_ALEN);
        ipv69_xmit(NULL, net, dev, smac, dst, src, IPV69_NEXT_CONTROL,
                   IPV69_DEFAULT_HOP, buf, 12);
        break;
    case IPV69_CTRL_ECHO_REQUEST:
        if (dst == 0 || dst == IPV69_BCAST_ADDR)
            return;
        if (!ipv69_is_local(net, dst))
            return;
        buf[0] = IPV69_CTRL_ECHO_REPLY;
        if (plen - 1 <= IPV69_MAX_PAYLOAD - 1)
            memcpy(buf + 1, d, plen - 1);
        ipv69_xmit(NULL, net, dev, smac, dst, src, IPV69_NEXT_CONTROL,
                   IPV69_DEFAULT_HOP, buf, plen);
        break;
    default:
        break;   /* ND_REPLY, ECHO_REPLY, errors: just delivered */
    }
}

static int ipv69_rcv(struct sk_buff *skb, struct net_device *dev,
                     struct packet_type *pt, struct net_device *orig_dev)
{
    struct ipv69_hdr *h;
    u64 dst;

    /* eth_type_trans() already pulled the Ethernet header: data points at
       the IPv69 header, len excludes the 14 Ethernet bytes */
    if (skb->len < IPV69_HEADER_LEN + 1)
        goto drop;
    if (!pskb_may_pull(skb, IPV69_HEADER_LEN + 1))
        goto drop;

    h = (struct ipv69_hdr *)skb->data;
    if ((h->ver_traffic >> 4) != IPV69_VERSION)
        goto drop;
    if (h->next_header != IPV69_NEXT_DGRAM &&
        h->next_header != IPV69_NEXT_CONTROL)
        goto drop;   /* 254 STREAM reserved */
    if (ntohs(h->payload_len) != skb->len - IPV69_HEADER_LEN)
        goto drop;
    if (h->next_header == IPV69_NEXT_DGRAM && skb->len < IPV69_HEADER_LEN + 4)
        goto drop;
    if (h->next_header == IPV69_NEXT_CONTROL && skb->len < IPV69_HEADER_LEN + 1)
        goto drop;

    /* learn the sender: 40-bit addr -> MAC (Ethernet header still in skb,
       pulled from skb->data but preserved via mac_header) */
    ipv69_nd_learn(ipv69_get_addr(h->source), eth_hdr(skb)->h_source);

    if (h->next_header == IPV69_NEXT_CONTROL)
        ipv69_handle_ctrl(skb, h, dev);

    ipv69_deliver(skb, h, dev);

    /* forwarding: not for us -> relay with decremented hop limit */
    dst = ipv69_get_addr(h->dest);
    if (dst != IPV69_BCAST_ADDR && dst != 0 &&
        !ipv69_is_local(dev_net(dev), dst)) {
        if (h->hop_limit <= 1) {
            ipv69_send_err(dev_net(dev), dev, eth_hdr(skb)->h_source, h,
                           IPV69_CTRL_TIME_EXCEEDED);
        } else {
            struct net_device *fwd = ipv69_fwd_dev(dev_net(dev), dev);
            u8 mac[ETH_ALEN];
            const u8 *dmac = ipv69_bcast;

            if (!fwd) {
                ipv69_send_err(dev_net(dev), dev, eth_hdr(skb)->h_source, h,
                               IPV69_CTRL_UNREACHABLE);
            } else {
                if (ipv69_nd_lookup(dst, mac))
                    dmac = mac;
                ipv69_xmit(NULL, dev_net(fwd), fwd, dmac,
                           ipv69_get_addr(h->source), dst, h->next_header,
                           h->hop_limit - 1,
                           skb->data + IPV69_HEADER_LEN,
                           ntohs(h->payload_len));
                dev_put(fwd);
            }
        }
    }

    kfree_skb(skb);
    return NET_RX_SUCCESS;

drop:
    kfree_skb(skb);
    return NET_RX_DROP;
}

static int ipv69_recvmsg(struct socket *sock, struct msghdr *msg, size_t len,
                         int flags)
{
    struct sock *sk = sock->sk;
    struct sk_buff *skb;
    struct ipv69_hdr *h;
    size_t plen, off, copylen;
    int err;

    skb = skb_recv_datagram(sk, flags, &err);
    if (!skb)
        return err;

    h = (struct ipv69_hdr *)skb->data;   /* Ethernet header already pulled */
    plen = ntohs(h->payload_len);
    if (h->next_header == IPV69_NEXT_DGRAM) {
        off = IPV69_HEADER_LEN + 4;      /* skip ports */
        copylen = plen > 4 ? min(len, plen - 4) : 0;
    } else {
        off = IPV69_HEADER_LEN;          /* control: [type][data] */
        copylen = min(len, plen);
    }

    if (msg->msg_name) {
        struct sockaddr_69 *sa = msg->msg_name;

        sa->sa_family = IPV69_AF;
        sa->ifindex = skb->dev ? skb->dev->ifindex : 0;
        sa->src = ipv69_get_addr(h->source);
        sa->dst = ipv69_get_addr(h->dest);
        sa->src_port = 0;
        sa->dst_port = 0;
        if (h->next_header == IPV69_NEXT_DGRAM) {
            const __be16 *ports =
                (const __be16 *)(skb->data + IPV69_HEADER_LEN);
            sa->src_port = ntohs(ports[0]);
            sa->dst_port = ntohs(ports[1]);
        }
        sa->next_header = h->next_header;
        sa->hop_limit = h->hop_limit;
        sa->reserved = 0;
        msg->msg_namelen = sizeof(struct sockaddr_69);
    }

    err = skb_copy_datagram_msg(skb, off, msg, copylen);
    skb_free_datagram(sk, skb);
    return err ? err : (int)copylen;
}

static int ipv69_release(struct socket *sock)
{
    struct sock *sk = sock->sk;

    if (!sk)
        return 0;
    spin_lock_bh(&ipv69_lock);
    list_del(&ipv69_sk(sk)->list);
    spin_unlock_bh(&ipv69_lock);
    sock_orphan(sk);
    sock->sk = NULL;
    skb_queue_purge(&sk->sk_receive_queue);
    sock_put(sk);
    return 0;
}

static const struct proto_ops ipv69_ops = {
    .family     = IPV69_AF,
    .owner      = THIS_MODULE,
    .release    = ipv69_release,
    .bind       = ipv69_bind,
    .connect    = ipv69_connect,
    .socketpair = sock_no_socketpair,
    .accept     = sock_no_accept,
    .getname    = sock_no_getname,
    .poll       = datagram_poll,
    .ioctl      = sock_no_ioctl,
    .listen     = sock_no_listen,
    .shutdown   = sock_no_shutdown,
    .sendmsg    = ipv69_sendmsg,
    .recvmsg    = ipv69_recvmsg,
    .mmap       = sock_no_mmap,
};

static struct net_proto_family ipv69_family_ops = {
    .family = IPV69_AF,
    .create = ipv69_create,
    .owner  = THIS_MODULE,
};

static struct packet_type ipv69_packet_type __read_mostly = {
    .type = htons(IPV69_ETHERTYPE),
    .func = ipv69_rcv,
};

static int __init ipv69_init(void)
{
    int err;

    err = sock_register(&ipv69_family_ops);
    if (err) {
        pr_err("af69: sock_register(%d) failed: %d\n", IPV69_AF, err);
        return err;
    }
    dev_add_pack(&ipv69_packet_type);
    pr_info("af69: AF_%d registered (ethertype 0x%04x)\n",
            IPV69_AF, IPV69_ETHERTYPE);
    return 0;
}

static void __exit ipv69_exit(void)
{
    dev_remove_pack(&ipv69_packet_type);
    sock_unregister(IPV69_AF);
    pr_info("af69: unloaded\n");
}

module_init(ipv69_init);
module_exit(ipv69_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("IPv69");
MODULE_DESCRIPTION("AF_69 - IPv69 socket family (pure L2, ND + forwarding)");
