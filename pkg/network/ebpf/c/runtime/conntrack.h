#ifndef __CONNTRACK_H
#define __CONNTRACK_H

#ifdef COMPILE_RUNTIME
#include "kconfig.h"
#include <net/netfilter/nf_conntrack.h>
#include <linux/types.h>
#include <linux/sched.h>
#endif

#include "bpf_builtins.h"        // for bpf_memset
#include "bpf_helpers.h"         // for __always_inline, log_debug, NULL
#include "bpf_tracing.h"         // for BPF_CORE_READ_INTO, bpf_core_field_exists, bpf_core_type_exists
#include "conntrack/helpers.h"   // for nf_conntrack_tuple_to_conntrack_tuple, print_translation
#include "conntrack/maps.h"      // IWYU pragma: keep
#include "conntrack/types.h"     // for conntrack_tuple_t
#include "ktypes.h"              // for nf_conn, nf_conntrack_tuple_hash, u32, possible_net_t, net, nf_conntrack_tuple
#include "netns.h"               // IWYU pragma: keep // for net___old, nf_conn___old

static __always_inline u32 get_netns(const struct nf_conn *ct) {
    u32 net_ns_inum = 0;

#ifdef COMPILE_RUNTIME
    // depending on the kernel version p_net may be a struct net** or possible_net_t*
    void *p_net = (void *)&ct->ct_net;
#ifdef CONFIG_NET_NS
    struct net *ns = NULL;
    bpf_probe_read_kernel_with_telemetry(&ns, sizeof(ns), p_net);
#ifdef _LINUX_NS_COMMON_H
    bpf_probe_read_kernel_with_telemetry(&net_ns_inum, sizeof(net_ns_inum), &ns->ns.inum);
#else
    bpf_probe_read_kernel_with_telemetry(&net_ns_inum, sizeof(net_ns_inum), &ns->proc_inum);
#endif // _LINUX_NS_COMMON_H
#endif // CONFIG_NET_NS
#endif // COMPILE_RUNTIME

#ifdef COMPILE_CORE
    struct net *nt = NULL;
    if (bpf_core_type_exists(possible_net_t)) {
        possible_net_t pnet = BPF_CORE_READ(ct, ct_net);
        // will not exist if CONFIG_NET_NS undefined
        if (!bpf_core_field_exists(pnet.net)) {
            return 0;
        }
        nt = pnet.net;
    } else {
        // will not exist if CONFIG_NET_NS undefined
        if (!bpf_core_field_exists(((struct nf_conn___old*)ct)->ct_net)) {
            return 0;
        }
        BPF_CORE_READ_INTO(&nt, (struct nf_conn___old*)ct, ct_net);
    }

    if (bpf_core_field_exists(((struct net___old*)nt)->proc_inum)) {
        // struct net * -> unsigned int proc_inum
        BPF_CORE_READ_INTO(&net_ns_inum, (struct net___old*)nt, proc_inum);
    } else if (bpf_core_field_exists(nt->ns)) {
        // struct net * -> ns_common ns . unsigned int inum
        BPF_CORE_READ_INTO(&net_ns_inum, nt, ns.inum);
    }
#endif // COMPILE_CORE

    return net_ns_inum;
}

static __always_inline int nf_conn_to_conntrack_tuples(struct nf_conn* ct, conntrack_tuple_t* orig, conntrack_tuple_t* reply) {
    struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];
    bpf_memset(tuplehash, 0, sizeof(tuplehash));

    BPF_CORE_READ_INTO(&tuplehash, ct, tuplehash);
    struct nf_conntrack_tuple orig_tup = tuplehash[IP_CT_DIR_ORIGINAL].tuple;
    struct nf_conntrack_tuple reply_tup = tuplehash[IP_CT_DIR_REPLY].tuple;

    u32 netns = get_netns(ct);

    if (!nf_conntrack_tuple_to_conntrack_tuple(orig, &orig_tup)) {
        return 1;
    }
    orig->netns = netns;

    log_debug("orig");
    print_translation(orig);

    if (!nf_conntrack_tuple_to_conntrack_tuple(reply, &reply_tup)) {
        return 1;
    }
    reply->netns = netns;

    log_debug("reply");
    print_translation(reply);

    return 0;
}

#endif
