// SPDX-License-Identifier: GPL-2.0
/*
 * af_ipv69.c - address family do protocolo IPv69
 *
 * Registra AF_IPV69 (sock_register) e o EtherType 0x6969 (dev_add_pack).
 * O kernel monta o frame (ethernet + header IPv69 + datagrama) no sendmsg
 * e valida/entrega na recepcao - o userspace usa socket(AF_IPV69, SOCK_DGRAM, 0).
 *
 * Uso (root):
 *   insmod af_ipv69.ko
 *   socket(AF_IPV69, SOCK_DGRAM, 0)
 *   bind(sockaddr_ipv69{ ifindex, dst_mac, dest })
 *   sendto: buffer = src_port(2) + dst_port(2) + dados
 *   recvfrom: datagrama recebido (portas + dados)
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <net/sock.h>

#define AF_IPV69          21      /* slot livre; vira 69 com AF_MAX patchado */
#define ETH_P_IPV69       0x6969
#define IPV69_HEADER_LEN  32
#define IPV69_VERSION     6
#define IPV69_NEXT_DGRAM  253
#define IPV69_MAX_PAYLOAD 1400

struct sockaddr_ipv69 {
    sa_family_t     family;
    int             ifindex;
    unsigned char   dst_mac[6];
    uint64_t        dest;
};

struct ipv69_sock {
    struct sock     sk;
    int             ifindex;
    unsigned char   dst_mac[6];
    uint64_t        dest;
};

static struct hlist_head ipv69_socks;
static DEFINE_SPINLOCK(ipv69_lock);

static struct proto ipv69_proto = {
    .name     = "IPV69",
    .owner    = THIS_MODULE,
    .obj_size = sizeof(struct ipv69_sock),
};

static const struct proto_ops ipv69_ops;

static inline struct ipv69_sock *ipv69_sk(struct sock *sk)
{
    return container_of(sk, struct ipv69_sock, sk);
}

static int ipv69_create(struct net *net, struct socket *sock, int protocol, int kern)
{
    struct ipv69_sock *is;

    if (protocol != 0)
        return -EPROTONOSUPPORT;

    is = (struct ipv69_sock *)sk_alloc(net, AF_IPV69, GFP_KERNEL, &ipv69_proto, kern);
    if (!is)
        return -ENOMEM;

    sock_init_data(sock, &is->sk);
    sock->ops = &ipv69_ops;
    sock->state = SS_UNCONNECTED;
    is->ifindex = 0;
    memset(is->dst_mac, 0xff, 6);
    is->dest = 2;

    spin_lock_bh(&ipv69_lock);
    hlist_add_head(&is->sk.sk_node, &ipv69_socks);
    spin_unlock_bh(&ipv69_lock);
    return 0;
}

static int ipv69_release(struct socket *sock)
{
    struct sock *sk = sock->sk;

    if (!sk)
        return 0;
    spin_lock_bh(&ipv69_lock);
    hlist_del_init(&sk->sk_node);
    spin_unlock_bh(&ipv69_lock);
    sock_orphan(sk);
    sock_put(sk);
    return 0;
}

static int ipv69_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
    struct sockaddr_ipv69 *sa = (struct sockaddr_ipv69 *)addr;
    struct ipv69_sock *is = ipv69_sk(sock->sk);

    if (addr_len < sizeof(*sa) || sa->family != AF_IPV69)
        return -EINVAL;

    lock_sock(sock->sk);
    is->ifindex = sa->ifindex;
    memcpy(is->dst_mac, sa->dst_mac, 6);
    is->dest = sa->dest ? sa->dest : 2;
    release_sock(sock->sk);
    return 0;
}

static int ipv69_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
    struct ipv69_sock *is = ipv69_sk(sock->sk);
    struct net_device *dev;
    struct sk_buff *skb;
    unsigned char *f;
    int ifindex;
    size_t flen;
    int err;

    if (len < 4 || len > IPV69_MAX_PAYLOAD)
        return -EMSGSIZE;

    lock_sock(sock->sk);
    ifindex = is->ifindex;
    release_sock(sock->sk);
    if (!ifindex)
        return -EDESTADDRREQ;

    dev = dev_get_by_index(sock_net(sock->sk), ifindex);
    if (!dev)
        return -ENODEV;

    flen = 14 + IPV69_HEADER_LEN + len;
    skb = alloc_skb(LL_RESERVED_SPACE(dev) + flen, GFP_KERNEL);
    if (!skb) {
        dev_put(dev);
        return -ENOMEM;
    }
    skb_reserve(skb, LL_RESERVED_SPACE(dev));
    f = skb_put(skb, flen);

    /* ethernet II */
    lock_sock(sock->sk);
    memcpy(f, is->dst_mac, 6);
    memcpy(f + 6, dev->dev_addr, 6);
    release_sock(sock->sk);
    f[12] = ETH_P_IPV69 >> 8;
    f[13] = ETH_P_IPV69 & 0xff;

    /* header IPv69 (big-endian) */
    f[14] = 0x69;                       /* versao 6 + traffic class 9 */
    f[15] = 0;                          /* dscp_ecn */
    f[16] = (len >> 8) & 0xff;          /* payload_len */
    f[17] = len & 0xff;
    f[18] = 0; f[19] = 1;               /* flow_id */
    f[20] = IPV69_NEXT_DGRAM;
    f[21] = 64;                         /* hop_limit */
    f[22] = 1;                          /* NOFRAG */
    f[23] = 0;
    f[24] = 0; f[25] = 0;               /* reserved2 */
    f[26] = 0; f[27] = 0; f[28] = 0; f[29] = 1;   /* sequence */
    f[30] = 0; f[31] = 0; f[32] = 0; f[33] = 0;   /* source = 1 */
    f[34] = 0; f[35] = 0; f[36] = 0; f[37] = 1;
    lock_sock(sock->sk);
    f[38] = (is->dest >> 56) & 0xff; f[39] = (is->dest >> 48) & 0xff;
    f[40] = (is->dest >> 40) & 0xff; f[41] = (is->dest >> 32) & 0xff;
    f[42] = (is->dest >> 24) & 0xff; f[43] = (is->dest >> 16) & 0xff;
    f[44] = (is->dest >> 8) & 0xff;  f[45] = is->dest & 0xff;
    release_sock(sock->sk);

    if (memcpy_from_msg(f + 46, msg, len)) {
        kfree_skb(skb);
        dev_put(dev);
        return -EFAULT;
    }

    skb->protocol = htons(ETH_P_IPV69);
    skb->dev = dev;
    err = dev_queue_xmit(skb);
    dev_put(dev);
    return err ? err : (int)len;
}

static int ipv69_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags)
{
    struct sock *sk = sock->sk;
    struct sk_buff *skb;
    int err;

    skb = skb_recv_datagram(sk, flags & MSG_DONTWAIT, &err);
    if (!skb)
        return err;

    if (skb->len > size)
        err = skb_copy_datagram_msg(skb, 0, msg, size);
    else
        err = skb_copy_datagram_msg(skb, 0, msg, skb->len);
    if (!err)
        err = skb->len;
    skb_free_datagram(sk, skb);
    return err;
}

static const struct proto_ops ipv69_ops = {
    .family     = AF_IPV69,
    .owner      = THIS_MODULE,
    .release    = ipv69_release,
    .bind       = ipv69_bind,
    .sendmsg    = ipv69_sendmsg,
    .recvmsg    = ipv69_recvmsg,
    .connect    = sock_no_connect,
    .socketpair = sock_no_socketpair,
    .accept     = sock_no_accept,
    .getname    = sock_no_getname,
    .poll       = datagram_poll,
    .ioctl      = sock_no_ioctl,
    .listen     = sock_no_listen,
    .shutdown   = sock_no_shutdown,
    .mmap       = sock_no_mmap,
};

static const struct net_proto_family ipv69_family = {
    .family = AF_IPV69,
    .create = ipv69_create,
    .owner  = THIS_MODULE,
};

static int ipv69_rcv(struct sk_buff *skb, struct net_device *dev,
                     struct packet_type *pt, struct net_device *orig_dev)
{
    struct ipv69_sock *is;
    struct sk_buff *clone;
    unsigned char *p;
    size_t plen;
    int ifindex = dev->ifindex;

    /* skb->data ja aponta para o header IPv69 (eth_type_trans consumiu
       os 14 bytes do ethernet antes do dispatch por ethertype) */
    if (skb->len < IPV69_HEADER_LEN + 4)
        goto drop;
    p = skb->data;
    if ((p[0] >> 4) != IPV69_VERSION)
        goto drop;
    plen = (p[2] << 8) | p[3];
    if (plen > skb->len - IPV69_HEADER_LEN)
        goto drop;
    if (p[6] != 0 && p[6] != IPV69_NEXT_DGRAM)
        goto drop;

    spin_lock_bh(&ipv69_lock);
    hlist_for_each_entry(is, &ipv69_socks, sk.sk_node) {
        if (is->ifindex != ifindex)
            continue;
        clone = skb_clone(skb, GFP_ATOMIC);
        if (!clone)
            continue;
        skb_pull(clone, IPV69_HEADER_LEN);
        if (sock_queue_rcv_skb(&is->sk, clone))
            kfree_skb(clone);
    }
    spin_unlock_bh(&ipv69_lock);
drop:
    kfree_skb(skb);
    return 0;
}

static struct packet_type ipv69_packet_type __read_mostly = {
    .type = htons(ETH_P_IPV69),
    .func = ipv69_rcv,
};

static int __init ipv69_init(void)
{
    int err;

    INIT_HLIST_HEAD(&ipv69_socks);
    err = sock_register(&ipv69_family);
    if (err)
        return err;
    dev_add_pack(&ipv69_packet_type);
    pr_info("IPv69: AF_IPV69 registrada (family %d), EtherType 0x6969\n", AF_IPV69);
    return 0;
}

static void __exit ipv69_exit(void)
{
    dev_remove_pack(&ipv69_packet_type);
    sock_unregister(AF_IPV69);
    pr_info("IPv69: descarregada\n");
}

module_init(ipv69_init);
module_exit(ipv69_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("IPv69 address family (AF_IPV69)");
