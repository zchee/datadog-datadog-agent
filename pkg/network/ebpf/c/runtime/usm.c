#include "bpf_tracing.h"
#include "bpf_builtins.h"
#include "bpf_telemetry.h"
#include "bpf_metadata.h"
#include "bpf_bypass.h"

#include "ktypes.h"
#ifdef COMPILE_RUNTIME
#include "kconfig.h"
#endif

#include "ip.h"
#include "ipv6.h"
#include "sock.h"
#include "port_range.h"

#include "protocols/classification/dispatcher-helpers.h"
#include "protocols/http/buffer.h"
#include "protocols/http/http.h"
#include "protocols/http2/decoding.h"
#include "protocols/http2/decoding-tls.h"
#include "protocols/http2/decoding-kprobe.h"
#include "protocols/http2/decoding-skmsg.h"
#include "protocols/http2/decoding-cgroup-skb.h"
#include "protocols/kafka/kafka-parsing.h"
#include "protocols/postgres/decoding.h"
#include "protocols/sockfd-probes.h"
#include "protocols/tls/java/erpc_dispatcher.h"
#include "protocols/tls/java/erpc_handlers.h"
#include "protocols/tls/go-tls-types.h"
#include "protocols/tls/go-tls-goid.h"
#include "protocols/tls/go-tls-location.h"
#include "protocols/tls/go-tls-conn.h"
#include "protocols/tls/https.h"
#include "protocols/tls/native-tls.h"
#include "protocols/tls/tags-types.h"

// The entrypoint for all packets classification & decoding in universal service monitoring.
SEC("socket/protocol_dispatcher")
int socket__protocol_dispatcher(struct __sk_buff *skb) {
    protocol_dispatcher_entrypoint(skb);
    return 0;
}

SEC("classifier/egress")
int classifier__egress(struct __sk_buff *skb)
{
    log_debug("classifier__egress len %u pkt_type %u", skb->len, skb->pkt_type);
    // log_debug("classifier_egress tup: remote: %08x (%u)", skb->remote_ip4, skb->remote_port);
    // log_debug("classifier_egress tup:  local: %08x (%u)", skb->local_ip4, skb->local_port);
    log_debug("classifier_egress: skb: %lx sk: %lx", (unsigned long)skb, (unsigned long)skb->sk);
    log_debug("classifier_egress: cookie: %llx\n", bpf_get_socket_cookie(skb));

    skb_info_t skb_info = {0};
    conn_tuple_t skb_tup = {0};

    // Exporting the conn tuple from the skb, alongside couple of relevant fields from the skb.
    if (!read_conn_tuple_skb(skb, &skb_info, &skb_tup)) {
        return 0;
    }

    log_debug("classifier_egress tup: saddr: %08llx %08llx (%u)", skb_tup.saddr_h, skb_tup.saddr_l, skb_tup.sport);
    log_debug("classifier_egress tup: daddr: %08llx %08llx (%u)", skb_tup.daddr_h, skb_tup.daddr_l, skb_tup.dport);

    // XXX soft lockup in kernel with this
    // struct bpf_sock *sock = skb->sk;
    // if (sock) {
    //u64 cookie = bpf_get_socket_cookie(skb);
    //     long ret = bpf_map_update_elem(&sockhash, &cookie, sock, BPF_NOEXIST);
    //     if (ret != 1000) {
    //         log_debug("classifier__egress sockhash update ret %ld", ret);
    //     }
    // }
    // log_debug("filter tup: netns: %08x pid: %u", skb_tup.netns, skb_tup.pid);

    return 0;
};

SEC("classifier/ingress")
int classifier__ingress(struct __sk_buff *skb)
{
    log_debug("classifier__ingress len %u pkt_type %u", skb->len, skb->pkt_type);
    // log_debug("classifier_inegress tup: remote: %08x (%u)", skb->remote_ip4, skb->remote_port);
    // log_debug("classifier_inegress tup:  local: %08x (%u)", skb->local_ip4, skb->local_port);
    log_debug("classifier_ingress: skb: %lx sk: %lx", (unsigned long)skb, (unsigned long)skb->sk);
    log_debug("classifier_ingress: cookie: %llx\n", bpf_get_socket_cookie(skb));

    skb_info_t skb_info = {0};
    conn_tuple_t skb_tup = {0};

    // Exporting the conn tuple from the skb, alongside couple of relevant fields from the skb.
    if (!read_conn_tuple_skb(skb, &skb_info, &skb_tup)) {
        return 0;
    }

    log_debug("classifier_ingress tup: saddr: %08llx %08llx (%u)", skb_tup.saddr_h, skb_tup.saddr_l, skb_tup.sport);
    log_debug("classifier_ingress tup: daddr: %08llx %08llx (%u)", skb_tup.daddr_h, skb_tup.daddr_l, skb_tup.dport);


    // XXX soft lockup in kernel with this
    // struct bpf_sock *sock = skb->sk;
    // if (sock) {
    // u64 cookie = bpf_get_socket_cookie(skb);
    //     long ret = bpf_map_update_elem(&sockhash, &cookie, sock, BPF_NOEXIST);
    //     if (ret != 1000) {
    //         log_debug("classifier__egress sockhash update ret %ld", ret);
    //     }
    // }
    // log_debug("filter tup: netns: %08x pid: %u", skb_tup.netns, skb_tup.pid);

    return 0;
};

SEC("cgroup_skb/egress/sockmap_filter")
int cgroup_skb__egress_filter(struct __sk_buff *skb) {
    log_debug("cgroup_skb__egress_filter len %u pkt_type %u", skb->len, skb->pkt_type);
    log_debug("cgroup_skb__egress_filter tup: remote: %08x (%u)", skb->remote_ip4, skb->remote_port);
    log_debug("cgroup_skb__egress_filter tup:  local: %08x (%u)", skb->local_ip4, skb->local_port);
    log_debug("cgroup_skb__egress_filter: skb: %lx sk: %lx", (unsigned long)skb, (unsigned long)skb->sk);
    log_debug("cgroup_skb__egress_filter: cookie: %llx\n", bpf_get_socket_cookie(skb));

    skb_info_t skb_info = {0};
    conn_tuple_t skb_tup = {0};

    // Exporting the conn tuple from the skb, alongside couple of relevant fields from the skb.
    if (!read_conn_tuple_skb_cgroup(skb, &skb_info, &skb_tup)) {
        return 1;
    }

    // log_debug("egress tup: saddr: %08llx %08llx (%u)", skb_tup.saddr_h, skb_tup.saddr_l, skb_tup.sport);
    // log_debug("egress tup: daddr: %08llx %08llx (%u)", skb_tup.daddr_h, skb_tup.daddr_l, skb_tup.dport);

    char tmp[32] = {0};
    bpf_skb_load_bytes(skb, skb_info.data_off, &tmp, sizeof(tmp));
    log_debug("cgroup_skb__egress_filter: data: [%s]", tmp);

    struct sockhash_key key = {
        .remote_ip4 = skb->remote_ip4,
        .local_ip4 = skb->local_ip4,
        .remote_port = skb->remote_port,
        .local_port = skb->local_port,
    };

    log_debug("cgroup key: remote: %x (%u)", key.remote_ip4, key.remote_port);
    log_debug("cgroup key:  local: %x (%u)", key.local_ip4, key.local_port);

    u64 cookie = bpf_get_socket_cookie(skb);
    bpf_map_update_elem(&socket_cookie_hash, &key, &cookie, BPF_NOEXIST);

    // struct sockhash_key key = {
    //     .remote_ip4 = skb->remote_ip4,
    //     .local_ip4 = skb->local_ip4,
    //     .remote_port = skb->remote_port,
    //     .local_port = skb->local_port,
    // };

    // struct bpf_sock *sock = skb->sk;
    // if (sock) {
    //     long ret = bpf_map_update_elem(&sockhash, &key, sock, BPF_NOEXIST);
    //     if (ret != 1000) {
    //         log_debug("cgroup_skb sockhash update ret %ld", ret);
    //     }
    // }

    /* Keep packet, see comments in __cgroup_bpf_run_filter_skb() */
    cgroup_protocol_dispatcher_entrypoint(skb);
    return 1;
}

SEC("cgroup_skb/egress/protocol_dispatcher_kafka")
int cgroup_skb__protocol_dispatcher_kafka(struct __sk_buff *skb) {
    cgroup_skb_dispatch_kafka(skb);
    return 0;
}

// This entry point is needed to bypass a memory limit on socket filters
// See: https://datadoghq.atlassian.net/wiki/spaces/NET/pages/2326855913/HTTP#Known-issues
SEC("socket/protocol_dispatcher_kafka")
int socket__protocol_dispatcher_kafka(struct __sk_buff *skb) {
    dispatch_kafka(skb);
    return 0;
}

// This entry point is needed to bypass stack limit errors if `is_kafka()` is called
// from the regular TLS dispatch entrypoint.
SEC("uprobe/tls_protocol_dispatcher_kafka")
int uprobe__tls_protocol_dispatcher_kafka(struct pt_regs *ctx) {
    tls_dispatch_kafka(ctx);
    return 0;
};

SEC("sk_msg/protocol_dispatcher")
int sk_msg__protocol_dispatcher(struct sk_msg_md *msg) {
    log_debug("sk_msg__protocol_dispatcher: msg %lx msg->sk %lx size %u", (unsigned long)msg, (unsigned long)msg->sk, msg->size);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 *splicing = bpf_map_lookup_elem(&tcp_splicing, &pid_tgid);
    if (splicing) {
        u64 key = (u64)msg->sk;
        u32 *seen_non_splice = bpf_map_lookup_elem(&tcp_seen_non_splice, &key);
        if (seen_non_splice) {
            log_debug("sk_msg__protocol_dispatcher: in splice and seen non-splice");
        } else {
            log_debug("sk_msg__protocol_dispatcher: skipping due to splice and never seen non-splice");
            return SK_PASS;
        }
    } else {
        u64 key = (u64)msg->sk;
        __u32 seen = 1;
        bpf_map_update_elem(&tcp_seen_non_splice, &key, &seen, BPF_ANY);
    }


    protocol_dispatcher_entrypoint_sk_msg(msg);
    return SK_PASS;
}

SEC("sk_msg/protocol_dispatcher_kafka")
int sk_msg__protocol_dispatcher_kafka(struct sk_msg_md *msg) {
    sk_msg_dispatch_kafka(msg);
    return SK_PASS;
}

SEC("kprobe/protocol_dispatcher_kafka")
int kprobe__protocol_dispatcher_kafka(struct pt_regs *ctx) {
    kprobe_dispatch_kafka(ctx);
    return 0;
};

SEC("sockops/sockops")
int sockops__sockops(struct bpf_sock_ops *skops) {
    int op = (int) skops->op;

    return 0;

    if (op == BPF_SOCK_OPS_STATE_CB) {
        u32 new = skops->args[1];
        log_debug("sockops state cb old %d new %d", skops->args[0], skops->args[1]);
        log_debug("sockops ip %x local_port %u", skops->local_ip4, skops->local_port);
        log_debug("sockops ip %x remote_port %u", skops->remote_ip4, bpf_ntohl(skops->remote_port));

        if (new == BPF_TCP_CLOSE || new == BPF_TCP_LAST_ACK) {
            conn_tuple_t tup = {};

            bpf_memset(&tup, 0, sizeof(tup));

            tup.metadata = CONN_V4 | CONN_TYPE_TCP;
            tup.saddr_l = skops->local_ip4;
            tup.daddr_l = skops->remote_ip4;
            tup.sport = skops->local_port;
            tup.dport = bpf_ntohl(skops->remote_port);

            u64 cookie = bpf_get_socket_cookie(skops);
            tup.pid = cookie >> 32;
            tup.netns = cookie;

            log_debug("termination tup: saddr: %08llx %08llx (%u)", tup.saddr_h, tup.saddr_l, tup.sport);
            log_debug("termination tup: daddr: %08llx %08llx (%u)", tup.daddr_h, tup.daddr_l, tup.dport);
            log_debug("termination tup: netns: %08x pid: %u", tup.netns, tup.pid);

            sockops_http_termination(&tup);
            sockops_kafka_termination(&tup);
            sockops_http2_termination(&tup);

                struct sockhash_key key = {
        .remote_ip4 = skops->remote_ip4,
        .local_ip4 = skops->local_ip4,
        .remote_port = skops->remote_port,
        .local_port = skops->local_port,
    };

            bpf_map_delete_elem(&socket_cookie_hash, &key);

            return 0;
        }
    }

    if (op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB && op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        return 0;
    }

    struct sockhash_key key = {
        .remote_ip4 = skops->remote_ip4,
        .local_ip4 = skops->local_ip4,
        .remote_port = skops->remote_port,
        .local_port = skops->local_port,
    };

    log_debug("sockops! op %u", skops->op);
    log_debug("sockops local_port %u", skops->local_port);
    log_debug("sockops remote_port %u", bpf_ntohl(skops->remote_port));
    log_debug("sockops! cookie %llu", bpf_get_socket_cookie(skops));

    long ret = bpf_sock_hash_update(skops, &sockhash, &key, BPF_NOEXIST);
    if (ret != 1000) {
        log_debug("sockops ret %ld", ret);
    }

    u64 cookie = bpf_get_socket_cookie(skops);
    bpf_map_update_elem(&socket_cookie_hash, &key, &cookie, BPF_NOEXIST);

    bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);

    // case (op) {
    // case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:

    // }

     return 0;
 }
 
struct iov_iter___new {
    u8 iter_type;
    void *ubuf;
};

struct iov_iter___old {
    unsigned int type;
};

struct msghdr___old {
    struct iov_iter___old msg_iter;
};

struct msghdr___new {
    int msg_namelen;
    struct iov_iter___new msg_iter;
};

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(kprobe__tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len, int flags) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    log_debug("kprobe/tcp_recvmsg: sk=%lx msghdr=%lx!\n", (unsigned long)sk, (unsigned long)msg);
    log_debug("kprobe/tcp_recvmsg: len=%lu\n", len);

    if (bpf_core_field_exists(((struct msghdr___old *)msg)->msg_iter.type)) {
        // 5.10
        unsigned int type;
        BPF_CORE_READ_INTO(&type, (struct msghdr___old *)msg, msg_iter.type);
        log_debug("kprobe/tcp_recvmsg: type=%u", type);
    } else {
        u8 iter_type;
        BPF_CORE_READ_INTO(&iter_type, msg, msg_iter.iter_type);
        log_debug("kprobe/tcp_recvmsg: iter_type=%u", iter_type);
    }

    void *ubuf;

#ifdef COMPILE_RUNTIME
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
    struct iovec *iov;
    bpf_probe_read_kernel(&iov, sizeof(iov), &msg->msg_iter.iov);
    bpf_probe_read_kernel(&ubuf, sizeof(ubuf), &iov->iov_base);
#else
    bpf_probe_read_kernel(&ubuf, sizeof(ubuf), &msg->msg_iter.ubuf);
#endif
#else
    if (bpf_core_field_exists(((struct msghdr___new *)msg)->msg_iter.ubuf)) {
        BPF_CORE_READ_INTO(&ubuf, (struct msghdr___new *)msg, msg_iter.ubuf);
    } else {
        size_t count = 0;

        BPF_CORE_READ_INTO(&ubuf, msg, msg_iter.iov, iov_base);
        BPF_CORE_READ_INTO(&count, msg, msg_iter.count);
        log_debug("kprobe/tcp_recvmsg: count=%zu", count);
    }
#endif

    log_debug("kprobe/tcp_recvmsg: ubuf=%lx", (unsigned long)ubuf);


    // BPF_CORE_READ_INTO(&iter_type, (struct msghdr_new *)msg, msg_iter.iter_type);

    // int x;
    // BPF_CORE_READ_INTO(&x, (struct msghdr*)msg, msg_namelen);
    // log_debug("kprobe/tcp_sendmsg: msg_namelen1=%d", x);

#ifdef COMPILE_CORE
    int inq;
    if (bpf_core_field_exists(((struct msghdr___new *)msg)->msg_namelen)) {
        BPF_CORE_READ_INTO(&inq, (struct msghdr___new*)msg, msg_namelen);
        log_debug("kprobe/tcp_recvmsg: msg_namelen2=%d", inq);
    } else {
        log_debug("kprobe/tcp_recvmsg: no namelen2");
    }
#endif

    tcp_kprobe_state_t state = {
        .sock = sk,
        .buffer = ubuf,
    };
    bpf_map_update_with_telemetry(tcp_kprobe_state, &pid_tgid, &state, BPF_ANY);

    // map connection tuple during SSL_do_handshake(ctx)
    map_ssl_ctx_to_sock(sk);

    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(kretprobe__tcp_recvmsg, int ret) {
    log_debug("kretprobe/tcp_recvmsg ret=%d", ret);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    tcp_kprobe_state_t *state = bpf_map_lookup_elem(&tcp_kprobe_state, &pid_tgid);
    if (!state) {
        log_debug("kretprobe/tcp_recvmsg no state");
        return 0;
    }

    if (ret > 0) {
        u64 data0 = 0;
        u64 data1 = 0;
        bpf_probe_read_user(&data0, sizeof(data0), state->buffer);
        bpf_probe_read_user(&data1, sizeof(data1), state->buffer + sizeof(data1));
        log_debug("recvmsg data0=%llx", bpf_be64_to_cpu(data0));
        log_debug("recvmsg data1=%llx", bpf_be64_to_cpu(data1));

        kprobe_protocol_dispatcher_entrypoint(ctx, state->sock, state->buffer, ret, true);
    }

    bpf_map_delete_elem(&tcp_kprobe_state, &pid_tgid);

    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_BYPASSABLE_KPROBE(kprobe__tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    log_debug("kprobe/tcp_sendmsg: sk=%lx msghdr=%lx!\n", (unsigned long)sk, (unsigned long)msg);
    log_debug("kprobe/tcp_sendmsg: size=%lu\n", size);

    // map connection tuple during SSL_do_handshake(ctx)
    map_ssl_ctx_to_sock(sk);

    if (bpf_core_field_exists(((struct msghdr___old *)msg)->msg_iter.type)) {
        // 5.10
        unsigned int type;
        BPF_CORE_READ_INTO(&type, (struct msghdr___old *)msg, msg_iter.type);
        log_debug("kprobe/tcp_sendmsg: type=%u", type);
    } else {
        u8 iter_type;
        BPF_CORE_READ_INTO(&iter_type, msg, msg_iter.iter_type);
        log_debug("kprobe/tcp_sendmsg: iter_type=%u", iter_type);
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 *splicing = bpf_map_lookup_elem(&tcp_splicing, &pid_tgid);
    if (splicing) {
        log_debug("kprobe/tcp_sendmsg: ignore due to splice");
        return 0;
    }


    void *ubuf;

#ifdef COMPILE_RUNTIME
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
    struct iovec *iov;
    bpf_probe_read_kernel(&iov, sizeof(iov), &msg->msg_iter.iov);
    bpf_probe_read_kernel(&ubuf, sizeof(ubuf), &iov->iov_base);
#else
    bpf_probe_read_kernel(&ubuf, sizeof(ubuf), &msg->msg_iter.ubuf);
#endif
#else
    if (bpf_core_field_exists(((struct msghdr___new *)msg)->msg_iter.ubuf)) {
        BPF_CORE_READ_INTO(&ubuf, (struct msghdr___new *)msg, msg_iter.ubuf);
    } else {
        size_t count = 0;

        BPF_CORE_READ_INTO(&ubuf, msg, msg_iter.iov, iov_base);
        BPF_CORE_READ_INTO(&count, msg, msg_iter.count);
        log_debug("kprobe/tcp_sendmsg: count=%zu", count);
    }
#endif

    log_debug("kprobe/tcp_sendmsg: ubuf=%lx", (unsigned long)ubuf);

    tcp_kprobe_state_t state = {
        .sock = sk,
        .buffer = ubuf,
    };
    bpf_map_update_with_telemetry(tcp_kprobe_state, &pid_tgid, &state, BPF_ANY);

    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(kretprobe__tcp_sendmsg, int ret) {
    log_debug("kretprobe/tcp_sendmsg ret=%d", ret);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    tcp_kprobe_state_t *state = bpf_map_lookup_elem(&tcp_kprobe_state, &pid_tgid);
    if (!state) {
        log_debug("kretprobe/tcp_sendmsg no state");
        return 0;
    }

    if (ret > 0) {
        u64 data0 = 0;
        u64 data1 = 0;
        bpf_probe_read_user(&data0, sizeof(data0), state->buffer);
        bpf_probe_read_user(&data1, sizeof(data1), state->buffer + sizeof(data1));
        log_debug("sendmsg data0=%llx", bpf_be64_to_cpu(data0));
        log_debug("sendmsg data1=%llx", bpf_be64_to_cpu(data1));

        kprobe_protocol_dispatcher_entrypoint(ctx, state->sock, state->buffer, ret, false);
    }

    bpf_map_delete_elem(&tcp_kprobe_state, &pid_tgid);

    return 0;
}


SEC("kprobe/tcp_splice_read")
int BPF_KPROBE(kprobe__tcp_splice_read, struct socket *sock) {
    log_debug("kprobe/tcp_splice_read sock=%lx\n", (unsigned long)sock);

    return 0;
}

SEC("kprobe/simple_copy_to_iter")
int BPF_KPROBE(kprobe__simple_copy_to_iter, const void *addr, size_t bytes) {
    log_debug("kprobe/simple_copy_to_iter addr=%lx bytes=%lu\n", (unsigned long)addr, bytes);

    // u64 pid_tgid = bpf_get_current_pid_tgid();
    // tcp_kprobe_state_t *state = bpf_map_lookup_elem(&tcp_kprobe_state, &pid_tgid);
    // if (!state) {
    //     log_debug("kprobe/simple_copy_to_iter no state");
    //     return 0;
    // }

    // state->buffer = addr;
    // log_debug("kprobe/simple_copy_to_iter found state");

    return 0;
}

SEC("kretprobe/simple_copy_to_iter")
int BPF_KRETPROBE(kretprobe__simple_copy_to_iter, size_t bytes) {
    log_debug("kretprobe/simple_copy_to_iter");

    // u64 pid_tgid = bpf_get_current_pid_tgid();
    // tcp_kprobe_state_t *state = bpf_map_lookup_elem(&tcp_kprobe_state, &pid_tgid);
    // if (!state) {
    //     log_debug("kretprobe/simple_copy_to_iter no state");
    //     return 0;
    // }

    // log_debug("kretprobe/simple_copy_to_iter found state");
    // kprobe_protocol_dispatcher_entrypoint(ctx, state->sock, state->buffer, bytes);

    return 0;
}

SEC("kprobe/generic_splice_sendpage")
int BPF_KPROBE(kprobe__generic_splice_sendpage) {
    log_debug("kprobe/generic_splice_sendpage\n");

    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 splicing = 1;
    bpf_map_update_elem(&tcp_splicing, &pid_tgid, &splicing, BPF_ANY);

    return 0;
}

SEC("kretprobe/generic_splice_sendpage")
int BPF_KRETPROBE(kretprobe__generic_splice_sendpage) {
    log_debug("kretprobe/generic_splice_sendpage");

    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&tcp_splicing, &pid_tgid);

    return 0;
}

SEC("kprobe/splice_to_socket")
int BPF_KPROBE(kprobe__splice_to_socket) {
    log_debug("kprobe/splice_to_socket\n");

    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 splicing = 1;
    bpf_map_update_elem(&tcp_splicing, &pid_tgid, &splicing, BPF_ANY);

    return 0;
}

SEC("kretprobe/splice_to_socket")
int BPF_KRETPROBE(kretprobe__splice_to_socket) {
    log_debug("kretprobe/splice_to_socket");

    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&tcp_splicing, &pid_tgid);

    return 0;
}

SEC("kprobe/tcp_splice_data_recv")
int BPF_KPROBE(kprobe__tcp_splice_data_recv, read_descriptor_t *rd_desc, struct sk_buff *skb, unsigned int offset, size_t len) {
    log_debug("kprobe/tcp_splice_data_recv skb=%lx offset=%u len=%lu\n", (unsigned long)skb, offset, len);

    __u32 skb_len;
    BPF_CORE_READ_INTO(&skb_len, skb, len);
    __u32 skb_data_len;
    BPF_CORE_READ_INTO(&skb_data_len, skb, data_len);
    void *skb_head;
    BPF_CORE_READ_INTO(&skb_head, skb, head);
    __u32 skb_end;
    BPF_CORE_READ_INTO(&skb_end, skb, end);

    log_debug("kprobe/tcp_splice_data_recv skb->len %u data_len %u skb_headlen %u\n", skb_len, skb_data_len, skb_len - skb_data_len);
    log_debug("kprobe/tcp_splice_data_recv skb->head %lx end %u\n", (unsigned long)skb_head, skb_end);

    void *skb_end_pointer = skb_head + skb_end;
    struct skb_shared_info *shinfo = skb_end_pointer;
    log_debug("kprobe/tcp_splice_data_recv shinfo %lx\n", (unsigned long)shinfo);

    __u8 nr_frags;
    BPF_CORE_READ_INTO(&nr_frags, shinfo, nr_frags);

    log_debug("kprobe/tcp_splice_data_recv nr_frags %u\n", nr_frags);

    struct page *frag_page;
    BPF_CORE_READ_INTO(&frag_page, shinfo, frags[0].bv_page);
    __u32 frag_len;
    BPF_CORE_READ_INTO(&frag_len, shinfo, frags[0].bv_len);
    __u32 frag_offset;
    BPF_CORE_READ_INTO(&frag_offset, shinfo, frags[0].bv_offset);

    log_debug("kprobe/tcp_splice_data_recv frag[0] page %lx len %u offset %u\n", (unsigned long)frag_page, frag_len, frag_offset);

    // u64 pid_tgid = bpf_get_current_pid_tgid();
    // tcp_kprobe_state_t *state = bpf_map_lookup_elem(&tcp_kprobe_state, &pid_tgid);
    // if (!state) {
    //     log_debug("kprobe/simple_copy_to_iter no state");
    //     return 0;
    // }

    // state->buffer = addr;
    // log_debug("kprobe/simple_copy_to_iter found state");

    return 0;
}

SEC("kretprobe/tcp_splice_data_recv")
int BPF_KRETPROBE(kretprobe__tcp_splice_data_recv, size_t bytes) {
    log_debug("kretprobe/tcp_splice_data_recv");

    // u64 pid_tgid = bpf_get_current_pid_tgid();
    // tcp_kprobe_state_t *state = bpf_map_lookup_elem(&tcp_kprobe_state, &pid_tgid);
    // if (!state) {
    //     log_debug("kretprobe/simple_copy_to_iter no state");
    //     return 0;
    // }

    // log_debug("kretprobe/simple_copy_to_iter found state");
    // kprobe_protocol_dispatcher_entrypoint(ctx, state->sock, state->buffer, bytes);

    return 0;
}

SEC("tracepoint/net/netif_receive_skb")
int tracepoint__net__netif_receive_skb(void *ctx) {
    CHECK_BPF_PROGRAM_BYPASSED()
    log_debug("tracepoint/net/netif_receive_skb");
    // flush batch to userspace
    // because perf events can't be sent from socket filter programs
    http_batch_flush(ctx);
    http2_batch_flush(ctx);
    terminated_http2_batch_flush(ctx);
    kafka_batch_flush(ctx);
    postgres_batch_flush(ctx);
    return 0;
}

// GO TLS PROBES

// func (c *Conn) Write(b []byte) (int, error)
SEC("uprobe/crypto/tls.(*Conn).Write")
int BPF_BYPASSABLE_UPROBE(uprobe__crypto_tls_Conn_Write) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = pid_tgid >> 32;
    tls_offsets_data_t* od = get_offsets_data();
    if (od == NULL) {
        log_debug("[go-tls-write] no offsets data in map for pid %llu", pid);
        return 0;
    }

    // Read the PID and goroutine ID to make the partial call key
    go_tls_function_args_key_t call_key = {0};
    call_key.pid = pid;
    if (read_goroutine_id(ctx, &od->goroutine_id, &call_key.goroutine_id)) {
        log_debug("[go-tls-write] failed reading go routine id for pid %llu", pid);
        return 0;
    }

    // Read the parameters to make the partial call data
    // (since the parameters might not be live by the time the return probe is hit).
    go_tls_write_args_data_t call_data = {0};
    if (read_location(ctx, &od->write_conn_pointer, sizeof(call_data.conn_pointer), &call_data.conn_pointer)) {
        log_debug("[go-tls-write] failed reading conn pointer for pid %llu", pid);
        return 0;
    }

    if (read_location(ctx, &od->write_buffer.ptr, sizeof(call_data.b_data), &call_data.b_data)) {
        log_debug("[go-tls-write] failed reading buffer pointer for pid %llu", pid);
        return 0;
    }

    if (read_location(ctx, &od->write_buffer.len, sizeof(call_data.b_len), &call_data.b_len)) {
        log_debug("[go-tls-write] failed reading buffer length for pid %llu", pid);
        return 0;
    }

    bpf_map_update_elem(&go_tls_write_args, &call_key, &call_data, BPF_ANY);
    return 0;
}

// func (c *Conn) Write(b []byte) (int, error)
SEC("uprobe/crypto/tls.(*Conn).Write/return")
int BPF_BYPASSABLE_UPROBE(uprobe__crypto_tls_Conn_Write__return) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = pid_tgid >> 32;
    tls_offsets_data_t* od = get_offsets_data();
    if (od == NULL) {
        log_debug("[go-tls-write-return] no offsets data in map for pid %llu", pid);
        return 0;
    }

    // Read the PID and goroutine ID to make the partial call key
    go_tls_function_args_key_t call_key = {0};
    call_key.pid = pid;

    if (read_goroutine_id(ctx, &od->goroutine_id, &call_key.goroutine_id)) {
        log_debug("[go-tls-write-return] failed reading go routine id for pid %llu", pid);
        return 0;
    }

    uint64_t bytes_written = 0;
    if (read_location(ctx, &od->write_return_bytes, sizeof(bytes_written), &bytes_written)) {
        bpf_map_delete_elem(&go_tls_write_args, &call_key);
        log_debug("[go-tls-write-return] failed reading write return bytes location for pid %llu", pid);
        return 0;
    }

    if (bytes_written <= 0) {
        bpf_map_delete_elem(&go_tls_write_args, &call_key);
        log_debug("[go-tls-write-return] write returned non-positive for amount of bytes written for pid: %llu", pid);
        return 0;
    }

    uint64_t err_ptr = 0;
    if (read_location(ctx, &od->write_return_error, sizeof(err_ptr), &err_ptr)) {
        bpf_map_delete_elem(&go_tls_write_args, &call_key);
        log_debug("[go-tls-write-return] failed reading write return error location for pid %llu", pid);
        return 0;
    }

    // check if err != nil
    if (err_ptr != 0) {
        bpf_map_delete_elem(&go_tls_write_args, &call_key);
        log_debug("[go-tls-write-return] error in write for pid %llu: data will be ignored", pid);
        return 0;
    }

    go_tls_write_args_data_t *call_data_ptr = bpf_map_lookup_elem(&go_tls_write_args, &call_key);
    if (call_data_ptr == NULL) {
        bpf_map_delete_elem(&go_tls_write_args, &call_key);
        log_debug("[go-tls-write-return] no write information in write-return for pid %llu", pid);
        return 0;
    }

    conn_tuple_t *t = conn_tup_from_tls_conn(od, (void*)call_data_ptr->conn_pointer, pid_tgid);
    if (t == NULL) {
        log_debug("[go-tls-write-return] failed getting conn tup from tls conn for pid %llu", pid);
        bpf_map_delete_elem(&go_tls_write_args, &call_key);
        return 0;
    }

    char *buffer_ptr = (char*)call_data_ptr->b_data;
    log_debug("[go-tls-write] processing %s", buffer_ptr);
    bpf_map_delete_elem(&go_tls_write_args, &call_key);
    conn_tuple_t copy = {0};
    bpf_memcpy(&copy, t, sizeof(conn_tuple_t));
    // We want to guarantee write-TLS hooks generates the same connection tuple, while read-TLS hooks generate
    // the inverse direction, thus we're normalizing the tuples into a client <-> server direction, and then flipping it
    // to the server <-> client direction.
    normalize_tuple(&copy);
    flip_tuple(&copy);
    tls_process(ctx, &copy, buffer_ptr, bytes_written, GO);
    return 0;
}

// func (c *Conn) Read(b []byte) (int, error)
SEC("uprobe/crypto/tls.(*Conn).Read")
int BPF_BYPASSABLE_UPROBE(uprobe__crypto_tls_Conn_Read) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = pid_tgid >> 32;
    tls_offsets_data_t* od = get_offsets_data();
    if (od == NULL) {
        log_debug("[go-tls-read] no offsets data in map for pid %llu", pid_tgid >> 32);
        return 0;
    }

    // Read the PID and goroutine ID to make the partial call key
    go_tls_function_args_key_t call_key = {0};
    call_key.pid = pid;
    if (read_goroutine_id(ctx, &od->goroutine_id, &call_key.goroutine_id)) {
        log_debug("[go-tls-read] failed reading go routine id for pid %llu", pid_tgid >> 32);
        return 0;
    }

    // Read the parameters to make the partial call data
    // (since the parameters might not be live by the time the return probe is hit).
    go_tls_read_args_data_t call_data = {0};
    if (read_location(ctx, &od->read_conn_pointer, sizeof(call_data.conn_pointer), &call_data.conn_pointer)) {
        log_debug("[go-tls-read] failed reading conn pointer for pid %llu", pid_tgid >> 32);
        return 0;
    }
    if (read_location(ctx, &od->read_buffer.ptr, sizeof(call_data.b_data), &call_data.b_data)) {
        log_debug("[go-tls-read] failed reading buffer pointer for pid %llu", pid_tgid >> 32);
        return 0;
    }

    bpf_map_update_elem(&go_tls_read_args, &call_key, &call_data, BPF_ANY);
    return 0;
}

// func (c *Conn) Read(b []byte) (int, error)
SEC("uprobe/crypto/tls.(*Conn).Read/return")
int BPF_BYPASSABLE_UPROBE(uprobe__crypto_tls_Conn_Read__return) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = pid_tgid >> 32;
    tls_offsets_data_t* od = get_offsets_data();
    if (od == NULL) {
        log_debug("[go-tls-read-return] no offsets data in map for pid %llu", pid);
        return 0;
    }

    // On 4.14 kernels we suffered from a verifier issue, that lost track on `call_key` and failed later when accessing
    // to it. The workaround was to delay its creation, so we're getting the goroutine separately.
    __s64 goroutine_id = 0;
    // Read the PID and goroutine ID to make the partial call key
    if (read_goroutine_id(ctx, &od->goroutine_id, &goroutine_id)) {
        log_debug("[go-tls-read-return] failed reading go routine id for pid %llu", pid);
        return 0;
    }

    go_tls_function_args_key_t call_key = {0};
    call_key.pid = pid;
    call_key.goroutine_id = goroutine_id;

    go_tls_read_args_data_t* call_data_ptr = bpf_map_lookup_elem(&go_tls_read_args, &call_key);
    if (call_data_ptr == NULL) {
        log_debug("[go-tls-read-return] no read information in read-return for pid %llu", pid);
        return 0;
    }

    uint64_t bytes_read = 0;
    if (read_location(ctx, &od->read_return_bytes, sizeof(bytes_read), &bytes_read)) {
        log_debug("[go-tls-read-return] failed reading return bytes location for pid %llu", pid);
        bpf_map_delete_elem(&go_tls_read_args, &call_key);
        return 0;
    }

    // Errors like "EOF" of "unexpected EOF" can be treated as no error by the hooked program.
    // Therefore, if we choose to ignore data if read had returned these errors we may have accuracy issues.
    // For now for success validation we chose to check only the amount of bytes read
    // and make sure it's greater than zero.
    if (bytes_read <= 0) {
        log_debug("[go-tls-read-return] read returned non-positive for amount of bytes read for pid: %llu", pid);
        bpf_map_delete_elem(&go_tls_read_args, &call_key);
        return 0;
    }

    conn_tuple_t* t = conn_tup_from_tls_conn(od, (void*) call_data_ptr->conn_pointer, pid_tgid);
    if (t == NULL) {
        log_debug("[go-tls-read-return] failed getting conn tup from tls conn for pid %llu", pid);
        bpf_map_delete_elem(&go_tls_read_args, &call_key);
        return 0;
    }

    char *buffer_ptr = (char*)call_data_ptr->b_data;
    bpf_map_delete_elem(&go_tls_read_args, (go_tls_function_args_key_t*)&call_key);

    // The read tuple should be flipped (compared to the write tuple).
    // tls_process and the appropriate parsers will flip it back if needed.
    conn_tuple_t copy = {0};
    bpf_memcpy(&copy, t, sizeof(conn_tuple_t));
    // We want to guarantee write-TLS hooks generates the same connection tuple, while read-TLS hooks generate
    // the inverse direction, thus we're normalizing the tuples into a client <-> server direction.
    normalize_tuple(&copy);
    tls_process(ctx, &copy, buffer_ptr, bytes_read, GO);
    return 0;
}

// func (c *Conn) Close(b []byte) (int, error)
SEC("uprobe/crypto/tls.(*Conn).Close")
int BPF_BYPASSABLE_UPROBE(uprobe__crypto_tls_Conn_Close) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    tls_offsets_data_t* od = get_offsets_data();
    if (od == NULL) {
        log_debug("[go-tls-close] no offsets data in map for pid %llu", pid_tgid >> 32);
        return 0;
    }

    // Read the PID and goroutine ID to make the partial call key
    go_tls_function_args_key_t call_key = {0};
    call_key.pid = pid_tgid >> 32;
    if (read_goroutine_id(ctx, &od->goroutine_id, &call_key.goroutine_id) == 0) {
        bpf_map_delete_elem(&go_tls_read_args, &call_key);
        bpf_map_delete_elem(&go_tls_write_args, &call_key);
    }

    void* conn_pointer = NULL;
    if (read_location(ctx, &od->close_conn_pointer, sizeof(conn_pointer), &conn_pointer)) {
        log_debug("[go-tls-close] failed reading close conn pointer for pid %llu", pid_tgid >> 32);
        return 0;
    }

    conn_tuple_t* t = conn_tup_from_tls_conn(od, conn_pointer, pid_tgid);
    if (t == NULL) {
        log_debug("[go-tls-close] failed getting conn tup from tls conn for pid %llu", pid_tgid >> 32);
        return 0;
    }

    // Clear the element in the map since this connection is closed
    bpf_map_delete_elem(&conn_tup_by_go_tls_conn, &conn_pointer);

    conn_tuple_t copy = *t;
    // tls_finish can launch a tail call, thus cleanup should be done before.
    tls_finish(ctx, &copy, false);
    return 0;
}

static __always_inline void* get_tls_base(struct task_struct* task) {
#if defined(__TARGET_ARCH_x86)
    // X86 (RUNTIME & CO-RE)
    return (void *)BPF_CORE_READ(task, thread.fsbase);
#elif defined(__TARGET_ARCH_arm64)
#if defined(COMPILE_RUNTIME)
    // ARM64 (RUNTIME)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
    return (void *)BPF_CORE_READ(task, thread.uw.tp_value);
#else
    // This branch (kernel < 5.5) won't ever be executed, but is needed for
    // for the runtime compilation/program load to work in older kernels.
    return NULL;
#endif
#else
    // ARM64 (CO-RE)
    // Note that all Kernels currently supported by GoTLS monitoring (>= 5.5) do
    // have the field below, but if we don't check for its existence the program
    // *load* may fail in older Kernels, even if GoTLS monitoring is disabled.
    if (bpf_core_field_exists(task->thread.uw)) {
        return (void *)BPF_CORE_READ(task, thread.uw.tp_value);
    } else {
        return NULL;
    }
#endif
#else
    #error "Unsupported platform"
#endif
}

char _license[] SEC("license") = "GPL";
