#include "kconfig.h"
#include <linux/net.h>                                  // for socket
#include <linux/netfilter/nf_conntrack_tuple_common.h>  // for IP_CT_DIR_ORIGINAL, IP_CT_DIR_REPLY
#include <linux/skbuff.h>                               // for sk_buff
#include <linux/tcp.h>                                  // for tcp_sock
#include <net/flow.h>                                   // for flowi4, flowi6, fl4_dport, fl4_sport, fl6_dport, fl6_...
#include <net/inet_sock.h>                              // for inet_sock
#include <net/net_namespace.h>                          // for net
#include <net/netfilter/nf_conntrack.h>                 // for nf_conn
#include <net/netfilter/nf_conntrack_tuple.h>           // for nf_conntrack_tuple_hash
#include <net/sock.h>                                   // for sock, sk_daddr, sk_dport, sk_family, sk_net, sk_rcv_s...

#include "bpf_helpers.h"                                // for __sk_buff, offsetof, BPF_ANY, sk_msg_md, bpf_sock_ops
#include "bpf_tracing.h"                                // for pt_regs
#include "ktypes.h"                                     // for __u32, __u64, __s32, __s64, u64, __be16, __be32, __wsum
#include "map-defs.h"                                   // for BPF_HASH_MAP

typedef enum {
    OFFSET_SADDR = 0,
    OFFSET_DADDR,
    OFFSET_SPORT,
    OFFSET_DPORT,
    OFFSET_NETNS,
    OFFSET_INO,
    OFFSET_FAMILY,
    OFFSET_RTT,
    OFFSET_RTTVAR,
    OFFSET_DADDR_IPV6,
    OFFSET_SADDR_FL4,
    OFFSET_DADDR_FL4,
    OFFSET_SPORT_FL4,
    OFFSET_DPORT_FL4,
    OFFSET_SADDR_FL6,
    OFFSET_DADDR_FL6,
    OFFSET_SPORT_FL6,
    OFFSET_DPORT_FL6,
    OFFSET_SOCKET_SK,
    OFFSET_SK_BUFF_SOCK,
    OFFSET_SK_BUFF_TRANSPORT_HEADER,
    OFFSET_SK_BUFF_HEAD,
    OFFSET_CT_ORIGIN,
    OFFSET_CT_REPLY,
    OFFSET_CT_NETNS,
    OFFSET_CT_INO,
} offset_t;

BPF_HASH_MAP(offsets, offset_t, u64, 1024)

static __always_inline u64 get_ino_offset() {
#if defined(_LINUX_NS_COMMON_H)
    return offsetof(struct net, ns) + offsetof(struct ns_common, inum);
#else
    return offsetof(struct net, proc_inum);
#endif
}

SEC("kprobe/tcp_getsockopt")
int kprobe__tcp_getsockopt(struct pt_regs* ctx) {
    u64 offset = 0;
    offset_t o = OFFSET_SADDR;
    offset = offsetof(struct sock, sk_rcv_saddr);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    o = OFFSET_DADDR;
    offset = offsetof(struct sock, sk_daddr);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    o = OFFSET_FAMILY;
    offset = offsetof(struct sock, sk_family);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    o = OFFSET_SPORT;
    offset = offsetof(struct inet_sock, inet_sport);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    o = OFFSET_DPORT;
    offset = offsetof(struct sock, sk_dport);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

#ifdef CONFIG_NET_NS
    o = OFFSET_NETNS;
    offset = offsetof(struct sock, sk_net);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    o = OFFSET_INO;
    offset = get_ino_offset();
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);
#endif

    o = OFFSET_RTT;
    offset = offsetof(struct tcp_sock, srtt_us);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    o = OFFSET_RTTVAR;
    offset = offsetof(struct tcp_sock, mdev_us);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

#if defined(FEATURE_TCPV6_ENABLED) || defined(FEATURE_UDPV6_ENABLED)
    o = OFFSET_DADDR_IPV6;
    offset = offsetof(struct sock, sk_v6_daddr);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);
#endif

    o = OFFSET_SADDR_FL4;
    offset = offsetof(struct flowi4, saddr);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    o = OFFSET_DADDR_FL4;
    offset = offsetof(struct flowi4, daddr);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    o = OFFSET_SPORT_FL4;
    offset = offsetof(struct flowi4, fl4_sport);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    o = OFFSET_DPORT_FL4;
    offset = offsetof(struct flowi4, fl4_dport);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

#ifdef FEATURE_UDPV6_ENABLED
    o = OFFSET_SADDR_FL6;
    offset = offsetof(struct flowi6, saddr);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    o = OFFSET_DADDR_FL6;
    offset = offsetof(struct flowi6, daddr);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    o = OFFSET_SPORT_FL6;
    offset = offsetof(struct flowi6, fl6_sport);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    o = OFFSET_DPORT_FL6;
    offset = offsetof(struct flowi6, fl6_dport);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);
#endif

    o = OFFSET_SOCKET_SK;
    offset = offsetof(struct socket, sk);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    o = OFFSET_SK_BUFF_SOCK;
    offset = offsetof(struct sk_buff, sk);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    o = OFFSET_SK_BUFF_TRANSPORT_HEADER;
    offset = offsetof(struct sk_buff, network_header) - 2;
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    o = OFFSET_SK_BUFF_HEAD;
    offset = offsetof(struct sk_buff, head);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    o = OFFSET_CT_ORIGIN;
    offset = offsetof(struct nf_conn, tuplehash);
    offset += IP_CT_DIR_ORIGINAL * sizeof(struct nf_conntrack_tuple_hash);
    offset += offsetof(struct nf_conntrack_tuple_hash, tuple);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    o = OFFSET_CT_REPLY;
    offset = offsetof(struct nf_conn, tuplehash);
    offset += IP_CT_DIR_REPLY * sizeof(struct nf_conntrack_tuple_hash);
    offset += offsetof(struct nf_conntrack_tuple_hash, tuple);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    o = OFFSET_CT_NETNS;
    offset = offsetof(struct nf_conn, ct_net);
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    o = OFFSET_CT_INO;
    offset = get_ino_offset();
    bpf_map_update_elem(&offsets, &o, &offset, BPF_ANY);

    return 0;
}

char _license[] SEC("license") = "GPL";
