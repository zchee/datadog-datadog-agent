#ifndef __SOCKFD_PROBES_H
#define __SOCKFD_PROBES_H

#ifndef COMPILE_CORE
#include <linux/net.h>            // for proto_ops, socket, SOCK_STREAM, sock_type
#include <linux/socket.h>         // for AF_INET, AF_INET6
#include <net/sock.h>             // for sock
#endif

#include "bpf_helpers.h"          // for NULL, BPF_ANY, SEC, bpf_get_current_pid_tgid, bpf_map_delete_elem, bpf_map_...
#include "bpf_telemetry.h"        // for FN_INDX_bpf_probe_read_kernel, bpf_map_update_with_telemetry, bpf_probe_rea...
#include "bpf_tracing.h"          // for pt_regs, user_pt_regs, PT_REGS_PARM1, PT_REGS_RC
#include "conn_tuple.h"           // for conn_tuple_t, CONN_TYPE_TCP
#include "ktypes.h"               // for u64, true
#include "pid_fd.h"               // for pid_fd_t
#include "offsets.h"     // for offset_socket_sk
#include "protocols/tls/https.h"  // for tls_finish
#include "sock.h"                 // for read_conn_tuple, socket_sk
#include "sockfd.h"               // for pid_fd_by_tuple, sockfd_lookup_args, tuple_by_pid_fd

SEC("kprobe/tcp_close")
int BPF_KPROBE(kprobe__tcp_close, struct sock *sk) {
    if (sk == NULL) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    conn_tuple_t t;
    if (!read_conn_tuple(&t, sk, pid_tgid, CONN_TYPE_TCP)) {
        return 0;
    }

    pid_fd_t *pid_fd = bpf_map_lookup_elem(&pid_fd_by_tuple, &t);
    if (pid_fd == NULL) {
        return 0;
    }

    // Copy map value to stack so we can use it as a map key (needed for older kernels)
    pid_fd_t pid_fd_copy = *pid_fd;
    bpf_map_delete_elem(&tuple_by_pid_fd, &pid_fd_copy);
    bpf_map_delete_elem(&pid_fd_by_tuple, &t);

    // The cleanup of the map happens either during TCP termination or during the TLS shutdown event.
    // TCP termination is managed by the socket filter, thus it cannot clean TLS entries,
    // as it does not have access to the PID and NETNS.
    // Therefore, we use tls_finish to clean the connection. While this approach is not ideal, it is the best option available to us for now.
    tls_finish(ctx, &t, true);
    return 0;
}

SEC("kprobe/sockfd_lookup_light")
int kprobe__sockfd_lookup_light(struct pt_regs *ctx) {
    int sockfd = (int)PT_REGS_PARM1(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // Check if have already a map entry for this pid_fd_t
    // TODO: This lookup eliminates *4* map operations for existing entries
    // but can reduce the accuracy of programs relying on socket FDs for
    // processes with a lot of FD churn
    pid_fd_t key = {
        .pid = pid_tgid >> 32,
        .fd = sockfd,
    };
    conn_tuple_t *t = bpf_map_lookup_elem(&tuple_by_pid_fd, &key);
    if (t != NULL) {
        return 0;
    }

    bpf_map_update_with_telemetry(sockfd_lookup_args, &pid_tgid, &sockfd, BPF_ANY);
    return 0;
}

static __always_inline const struct proto_ops * socket_proto_ops(struct socket *sock) {
    const struct proto_ops *proto_ops = NULL;
#ifdef COMPILE_PREBUILT
    // (struct socket).ops is always directly after (struct socket).sk,
    // which is a pointer.
    u64 ops_offset = offset_socket_sk() + sizeof(void *);
    bpf_probe_read_kernel_with_telemetry(&proto_ops, sizeof(proto_ops), (char*)sock + ops_offset);
#elif defined(COMPILE_RUNTIME) || defined(COMPILE_CORE)
    BPF_CORE_READ_INTO(&proto_ops, sock, ops);
#endif

    return proto_ops;
}

// this kretprobe is essentially creating:
// * an index of pid_fd_t to a struct sock*;
// * an index of struct sock* to pid_fd_t;
SEC("kretprobe/sockfd_lookup_light")
int kretprobe__sockfd_lookup_light(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    int *sockfd = bpf_map_lookup_elem(&sockfd_lookup_args, &pid_tgid);
    if (sockfd == NULL) {
        return 0;
    }

    // NOTE: the code below should be executed only once for a given socket
    // For now let's only store information for TCP sockets
    struct socket *socket = (struct socket *)PT_REGS_RC(ctx);
    if (!socket)
        goto cleanup;

    enum sock_type sock_type = 0;
    bpf_probe_read_kernel_with_telemetry(&sock_type, sizeof(short), &socket->type);

    const struct proto_ops *proto_ops = socket_proto_ops(socket);
    if (!proto_ops) {
        goto cleanup;
    }

    int family = 0;
    bpf_probe_read_kernel_with_telemetry(&family, sizeof(family), &proto_ops->family);
    if (sock_type != SOCK_STREAM || !(family == AF_INET || family == AF_INET6)) {
        goto cleanup;
    }

    // Retrieve struct sock* pointer from struct socket*
    struct sock *sock = socket_sk(socket);
    if (!sock) {
        goto cleanup;
    }

    conn_tuple_t t;
    if (!read_conn_tuple(&t, sock, pid_tgid, CONN_TYPE_TCP)) {
        goto cleanup;
    }

    pid_fd_t pid_fd = {
        .pid = pid_tgid >> 32,
        .fd = (*sockfd),
    };

    // These entries are cleaned up by tcp_close
    bpf_map_update_with_telemetry(pid_fd_by_tuple, &t, &pid_fd, BPF_ANY);
    bpf_map_update_with_telemetry(tuple_by_pid_fd, &pid_fd, &t, BPF_ANY);
cleanup:
    bpf_map_delete_elem(&sockfd_lookup_args, &pid_tgid);
    return 0;
}

#endif // __SOCKFD_PROBES_H
