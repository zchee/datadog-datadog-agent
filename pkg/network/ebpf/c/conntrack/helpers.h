#ifndef __CONNTRACK_HELPERS_H
#define __CONNTRACK_HELPERS_H

#ifndef COMPILE_CORE
#include <linux/in.h>                                   // for IPPROTO_TCP, IPPROTO_UDP
#include <linux/netfilter.h>                            // for nf_inet_addr
#include <linux/netfilter/nf_conntrack_tuple_common.h>  // for nf_conntrack_man_proto, nf_conntrack_man_proto::(anon...
#include <linux/socket.h>                               // for AF_INET, AF_INET6
#include <net/netfilter/nf_conntrack_tuple.h>           // for nf_conntrack_tuple, nf_conntrack_man, nf_conntrack_tu...
#endif

#include "bpf_endian.h"                                 // for bpf_ntohs
#include "bpf_helpers.h"                                // for log_debug, __always_inline, NULL, bpf_map_lookup_elem
#include "compiler.h"                                   // for LOAD_CONSTANT
#include "conn_tuple.h"                                 // for CONN_TYPE_TCP, CONN_TYPE_UDP, CONN_V4, CONN_V6
#include "conntrack/types.h"                            // for conntrack_tuple_t, conntrack_telemetry_t
#include "ip.h"                                         // for print_ip
#include "ipv6.h"                                       // for read_in6_addr, is_tcpv6_enabled, is_udpv6_enabled
#include "ktypes.h"                                     // for __u16, __u32, __u64, u64
#include "map-defs.h"                                   // for BPF_ARRAY_MAP

/* This map is used for conntrack telemetry in kernelspace
 * only key 0 is used
 * value is a telemetry object
 */
BPF_ARRAY_MAP(conntrack_telemetry, conntrack_telemetry_t, 1)

static __always_inline __u32 systemprobe_pid() {
    __u64 val = 0;
    LOAD_CONSTANT("systemprobe_pid", val);
    return (__u32)val;
}

static __always_inline void print_translation(const conntrack_tuple_t *t) {
    if (t->metadata & CONN_TYPE_TCP) {
        log_debug("TCP");
    } else {
        log_debug("UDP");
    }

    print_ip(t->saddr_h, t->saddr_l, t->sport, t->metadata);
    print_ip(t->daddr_h, t->daddr_l, t->dport, t->metadata);
}

static __always_inline int nf_conntrack_tuple_to_conntrack_tuple(conntrack_tuple_t *t, const struct nf_conntrack_tuple *ct) {
    switch (ct->dst.protonum) {
    case IPPROTO_TCP:
        t->metadata = CONN_TYPE_TCP;
        t->sport = ct->src.u.tcp.port;
        t->dport = ct->dst.u.tcp.port;
        break;
    case IPPROTO_UDP:
        t->metadata = CONN_TYPE_UDP;
        t->sport = ct->src.u.udp.port;
        t->dport = ct->dst.u.udp.port;
        break;
    default:
        log_debug("ERR(to_conn_tuple): unknown protocol number: %u", ct->dst.protonum);
        return 0;
    }

    t->sport = bpf_ntohs(t->sport);
    t->dport = bpf_ntohs(t->dport);
    if (t->sport == 0 || t->dport == 0) {
        log_debug("ERR(to_conn_tuple): src/dst port not set: src: %u, dst: %u", t->sport, t->dport);
        return 0;
    }

    if (ct->src.l3num == AF_INET) {
        t->metadata |= CONN_V4;
        t->saddr_l = ct->src.u3.ip;
        t->daddr_l = ct->dst.u3.ip;

        if (!t->saddr_l || !t->daddr_l) {
            log_debug("ERR(to_conn_tuple.v4): src/dst addr not set src:%llu, dst:%llu", t->saddr_l, t->daddr_l);
            return 0;
        }
    } else if (ct->src.l3num == AF_INET6 && (is_tcpv6_enabled() || is_udpv6_enabled())) {
        t->metadata |= CONN_V6;
        read_in6_addr(&t->saddr_h, &t->saddr_l, &ct->src.u3.in6);
        read_in6_addr(&t->daddr_h, &t->daddr_l, &ct->dst.u3.in6);

        if (!(t->saddr_h || t->saddr_l)) {
            log_debug("ERR(to_conn_tuple.v6): src addr not set: src_l: %llu, src_h: %llu",
                t->saddr_l, t->saddr_h);
            return 0;
        }
        if (!(t->daddr_h || t->daddr_l)) {
            log_debug("ERR(to_conn_tuple.v6): dst addr not set: dst_l: %llu, dst_h: %llu",
                t->daddr_l, t->daddr_h);
            return 0;
        }
    }

    return 1;
}

static __always_inline void increment_telemetry_registers_count() {
    u64 key = 0;
    conntrack_telemetry_t *val = bpf_map_lookup_elem(&conntrack_telemetry, &key);
    if (val == NULL) {
        return;
    }
    __sync_fetch_and_add(&val->registers, 1);
}

#endif /* __CONNTRACK_HELPERS_H */
