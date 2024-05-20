#ifndef __TRACER_BIND_H
#define __TRACER_BIND_H

#ifndef COMPILE_CORE
#include <linux/in.h>       // for sockaddr_in
#include <linux/in6.h>      // for sockaddr_in6
#include <linux/net.h>      // for SOCK_DGRAM, socket
#include <linux/socket.h>   // for sa_family_t, AF_INET, AF_INET6, sockaddr
#endif

#include "bpf_endian.h"     // for bpf_ntohs
#include "bpf_helpers.h"    // for log_debug, __always_inline, bpf_get_current_pid_tgid, BPF_ANY, bpf_map_delete_elem
#include "bpf_telemetry.h"  // for FN_INDX_bpf_probe_read_kernel, bpf_probe_read_kernel_with_telemetry, bpf_map_upda...
#include "ktypes.h"         // for u16, __u16, NULL, __u64, __s64
#include "netns.h"          // for get_netns_from_sock
#include "sock.h"           // for read_sport, socket_sk
#include "tracer/maps.h"    // for pending_bind, udp_port_bindings
#include "tracer/port.h"    // for add_port_bind
#include "tracer/tracer.h"  // for bind_syscall_args_t, port_binding_t

static __always_inline u16 sockaddr_sin_port(struct sockaddr *addr) {
    u16 sin_port = 0;
    sa_family_t family = 0;
    bpf_probe_read_kernel_with_telemetry(&family, sizeof(sa_family_t), &addr->sa_family);
    if (family == AF_INET) {
        bpf_probe_read_kernel_with_telemetry(&sin_port, sizeof(u16), &(((struct sockaddr_in *)addr)->sin_port));
    } else if (family == AF_INET6) {
        bpf_probe_read_kernel_with_telemetry(&sin_port, sizeof(u16), &(((struct sockaddr_in6 *)addr)->sin6_port));
    }

    return bpf_ntohs(sin_port);
}

static __always_inline int sys_enter_bind(struct socket *sock, struct sockaddr *addr) {
    __u64 tid = bpf_get_current_pid_tgid();

    __u16 type = 0;
    bpf_probe_read_kernel_with_telemetry(&type, sizeof(__u16), &sock->type);
    if ((type & SOCK_DGRAM) == 0) {
        return 0;
    }

    if (addr == NULL) {
        log_debug("sys_enter_bind: could not read sockaddr, sock=%p, tid=%llu", sock, tid);
        return 0;
    }

    // ignore binds to port 0, as these are most
    // likely from clients, not servers
    if (sockaddr_sin_port(addr) == 0) {
        log_debug("sys_enter_bind: ignoring bind to 0 port, sock=%p", sock);
        return 0;
    }

    // write to pending_binds so the retprobe knows we can mark this as binding.
    bind_syscall_args_t args = {};
    args.sk = socket_sk(sock);
    if (!args.sk) {
        log_debug("sys_enter_bind: could not get socket sk");
        return 0;
    }

    args.addr = addr;

    bpf_map_update_with_telemetry(pending_bind, &tid, &args, BPF_ANY);
    log_debug("sys_enter_bind: started a bind on UDP sock=%p tid=%llu", sock, tid);

    return 0;
}

static __always_inline int sys_exit_bind(__s64 ret) {
    __u64 tid = bpf_get_current_pid_tgid();

    // bail if this bind() is not the one we're instrumenting
    bind_syscall_args_t *args = bpf_map_lookup_elem(&pending_bind, &tid);

    log_debug("sys_exit_bind: tid=%llu, ret=%lld", tid, ret);

    if (args == NULL) {
        log_debug("sys_exit_bind: was not a UDP bind, will not process");
        return 0;
    }

    struct sock * sk = args->sk;
    struct sockaddr *addr = args->addr;
    bpf_map_delete_elem(&pending_bind, &tid);

    if (ret != 0) {
        return 0;
    }

    u16 sin_port = sockaddr_sin_port(addr);
    if (sin_port == 0) {
        sin_port = read_sport(sk);
    }

    if (sin_port == 0) {
        log_debug("ERR(sys_exit_bind): sin_port is 0");
        return 0;
    }

    port_binding_t pb = {};
    pb.netns = get_netns_from_sock(sk);
    pb.port = sin_port;
    add_port_bind(&pb, udp_port_bindings);
    log_debug("sys_exit_bind: netns=%u", pb.netns);
    log_debug("sys_exit_bind: bound UDP port %u", sin_port);

    return 0;
}


#endif // __TRACER_BIND_H
