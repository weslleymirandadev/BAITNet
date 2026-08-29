// SPDX-License-Identifier: GPL-2.0
/*
 * af69 - IPv69 socket address family (experimental protocol 0x6969).
 *
 * Registers the AF_69 socket family and a packet_type for EtherType
 * 0x6969. SOCK_DGRAM builds/unpacks the 253 datagram (ports + payload)
 * and moves raw L2 Ethernet frames — no IPv4/IPv6 dependency anywhere.
 *
 * Usage: socket(AF_69, SOCK_DGRAM, 0)
 *   bind(sockaddr_69 { ifindex, src })  — interface + local address
 *   sendto(sockaddr_69 { dst, ports })  — transmit; ifindex 0 = auto-detect
 *   recvfrom(sockaddr_69)               — src/dst/ports of received frame
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
#define IPV69_FLAG_NOFRAG   (1 << 0)
#define IPV69_MAX_PAYLOAD   1400

#define IPV69_AF AF_69

struct sockaddr_69 {
    __u16 sa_family;
    __u16 ifindex;
    __u64 src;
    __u64 dst;
    __u16 src_port;
    __u16 dst_port;
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

struct ipv69_sock {
    struct sock sk;
    struct list_head list;   /* all live AF_69 sockets (rx fan-out) */
    int ifindex;             /* bind(): 0 = auto-detect on send */
    __u64 src_addr;
    __u64 dst_addr;
};

static LIST_HEAD(ipv69_socks);
static DEFINE_SPINLOCK(ipv69_lock);
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

static int ipv69_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
    struct ipv69_sock *is = ipv69_sk(sock->sk);
    struct net *net = sock_net(sock->sk);
    struct net_device *dev;
    struct sk_buff *skb;
    struct ipv69_hdr *h;
    __u64 dst = is->dst_addr;
    __u16 src_port = 0, dst_port = 0;
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
        src_port = sa->src_port;
        dst_port = sa->dst_port;
    }
    if (len > IPV69_MAX_PAYLOAD)
        return -EMSGSIZE;

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

    skb = sock_alloc_send_skb(sock->sk,
            LL_RESERVED_SPACE(dev) + IPV69_HEADER_LEN + 4 + len, 1, &err);
    if (!skb)
        goto out_dev;

    skb_reserve(skb, LL_RESERVED_SPACE(dev));
    skb->dev = dev;
    skb->protocol = htons(IPV69_ETHERTYPE);

    err = dev_hard_header(skb, dev, IPV69_ETHERTYPE, ipv69_bcast,
                          dev->dev_addr, IPV69_HEADER_LEN + 4 + len);
    if (err < 0)
        goto out_free;

    h = skb_put(skb, IPV69_HEADER_LEN);
    memset(h, 0, IPV69_HEADER_LEN);
    h->ver_traffic = (IPV69_VERSION << 4) | IPV69_TRAFFIC_CLASS;
    h->payload_len = htons(4 + len);
    h->flow_id = htons(1);
    h->next_header = IPV69_NEXT_DGRAM;
    h->hop_limit = 64;
    h->flags = IPV69_FLAG_NOFRAG;
    h->sequence = htonl(1);
    ipv69_put_addr(h->source, is->src_addr);
    ipv69_put_addr(h->dest, dst);

    {
        __be16 *ports = skb_put(skb, 4);
        ports[0] = htons(src_port);
        ports[1] = htons(dst_port);
    }
    if (!copy_from_iter_full(skb_put(skb, len), len, &msg->msg_iter)) {
        err = -EFAULT;
        goto out_free;
    }

    err = dev_queue_xmit(skb);
    skb = NULL;
    if (err < 0)
        goto out_dev;
    dev_put(dev);
    return len;

out_free:
    kfree_skb(skb);
out_dev:
    dev_put(dev);
    return err;
}

static int ipv69_rcv(struct sk_buff *skb, struct net_device *dev,
                     struct packet_type *pt, struct net_device *orig_dev)
{
    struct ipv69_hdr *h;
    struct ipv69_sock *is;
    struct sock *sk;

    /* eth_type_trans() already pulled the Ethernet header: data points at
       the IPv69 header, len excludes the 14 Ethernet bytes */
    if (skb->len < IPV69_HEADER_LEN + 4)
        goto drop;
    if (!pskb_may_pull(skb, IPV69_HEADER_LEN + 4))
        goto drop;

    h = (struct ipv69_hdr *)skb->data;
    if ((h->ver_traffic >> 4) != IPV69_VERSION)
        goto drop;
    if (h->next_header != IPV69_NEXT_DGRAM)
        goto drop;
    if (ntohs(h->payload_len) != skb->len - IPV69_HEADER_LEN)
        goto drop;

    spin_lock_bh(&ipv69_lock);
    list_for_each_entry(is, &ipv69_socks, list) {
        struct sk_buff *skb2;

        sk = &is->sk;
        if (sock_flag(sk, SOCK_DEAD))
            continue;
        if (sock_net(sk) != dev_net(skb->dev))
            continue;   /* do not leak frames across net namespaces */
        if (sk_rmem_alloc_get(sk) >= sk->sk_rcvbuf)
            continue;
        skb2 = skb_clone(skb, GFP_ATOMIC);
        if (!skb2)
            continue;
        skb_set_owner_r(skb2, sk);
        skb_queue_tail(&sk->sk_receive_queue, skb2);
        sk->sk_data_ready(sk);
    }
    spin_unlock_bh(&ipv69_lock);

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
    size_t plen, copylen;
    int err;

    skb = skb_recv_datagram(sk, flags, &err);
    if (!skb)
        return err;

    h = (struct ipv69_hdr *)skb->data;   /* Ethernet header already pulled */
    plen = ntohs(h->payload_len);
    if (plen < 4)
        plen = 4;
    copylen = min(len, plen - 4);

    if (msg->msg_name) {
        struct sockaddr_69 *sa = msg->msg_name;
        const __be16 *ports =
            (const __be16 *)(skb->data + IPV69_HEADER_LEN);

        sa->sa_family = IPV69_AF;
        sa->ifindex = skb->dev ? skb->dev->ifindex : 0;
        sa->src = ipv69_get_addr(h->source);
        sa->dst = ipv69_get_addr(h->dest);
        sa->src_port = ntohs(ports[0]);
        sa->dst_port = ntohs(ports[1]);
        msg->msg_namelen = sizeof(struct sockaddr_69);
    }

    err = skb_copy_datagram_msg(skb, IPV69_HEADER_LEN + 4, msg, copylen);
    skb_free_datagram(sk, skb);
    return err ? err : copylen;
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
MODULE_DESCRIPTION("AF_69 - IPv69 socket family (pure L2)");
