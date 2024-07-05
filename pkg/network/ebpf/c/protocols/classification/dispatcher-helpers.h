#ifndef __PROTOCOL_DISPATCHER_HELPERS_H
#define __PROTOCOL_DISPATCHER_HELPERS_H

#include "ktypes.h"

#include "ip.h"
#include "sock.h"

#include "protocols/classification/defs.h"
#include "protocols/classification/maps.h"
#include "protocols/classification/structs.h"
#include "protocols/classification/dispatcher-maps.h"
#include "protocols/http/classification-helpers.h"
#include "protocols/http/usm-events.h"
#include "protocols/http2/helpers.h"
#include "protocols/http2/usm-events.h"
#include "protocols/kafka/kafka-classification.h"
#include "protocols/kafka/usm-events.h"
#include "protocols/postgres/helpers.h"
#include "protocols/postgres/usm-events.h"

__maybe_unused static __always_inline protocol_prog_t protocol_to_program(protocol_t proto) {
    switch(proto) {
    case PROTOCOL_HTTP:
        return PROG_HTTP;
    case PROTOCOL_HTTP2:
        return PROG_HTTP2_HANDLE_FIRST_FRAME;
    case PROTOCOL_KAFKA:
        return PROG_KAFKA;
    case PROTOCOL_POSTGRES:
        return PROG_POSTGRES;
    default:
        if (proto != PROTOCOL_UNKNOWN) {
            log_debug("protocol doesn't have a matching program: %d", proto);
        }
        return PROG_UNKNOWN;
    }
}

// Returns true if the payload represents a TCP termination by checking if the tcp flags contains TCPHDR_FIN or TCPHDR_RST.
static __always_inline bool is_tcp_termination(skb_info_t *skb_info) {
    return skb_info->tcp_flags & (TCPHDR_FIN | TCPHDR_RST);
}

static __always_inline bool is_tcp_ack(skb_info_t *skb_info) {
    return skb_info->tcp_flags == TCPHDR_ACK;
}

// checks if we have seen that tcp packet before. It can happen if a packet travels multiple interfaces or retransmissions.
static __always_inline bool has_sequence_seen_before(conn_tuple_t *tup, skb_info_t *skb_info) {
    if (!skb_info || !skb_info->tcp_seq) {
        return false;
    }

    u32 *tcp_seq = bpf_map_lookup_elem(&connection_states, tup);

    // check if we've seen this TCP segment before. this can happen in the
    // context of localhost traffic where the same TCP segment can be seen
    // multiple times coming in and out from different interfaces
    if (tcp_seq != NULL && *tcp_seq == skb_info->tcp_seq) {
        return true;
    }

    bpf_map_update_elem(&connection_states, tup, &skb_info->tcp_seq, BPF_ANY);
    return false;
}

// Determines the protocols of the given buffer. If we already classified the payload (a.k.a protocol out param
// has a known protocol), then we do nothing.
static __always_inline void classify_protocol_for_dispatcher(protocol_t *protocol, conn_tuple_t *tup, const char *buf, __u32 size) {
    if (protocol == NULL || *protocol != PROTOCOL_UNKNOWN) {
        return;
    }

    if (is_http_monitoring_enabled() && is_http(buf, size)) {
        *protocol = PROTOCOL_HTTP;
    } else if (is_http2_monitoring_enabled() && is_http2(buf, size)) {
        *protocol = PROTOCOL_HTTP2;
    } else if (is_postgres_monitoring_enabled() && is_postgres(buf, size)) {
        *protocol = PROTOCOL_POSTGRES;
    } else {
        *protocol = PROTOCOL_UNKNOWN;
    }

    log_debug("[protocol_dispatcher_classifier]: Classified protocol as %d %d; %s", *protocol, size, buf);
}

static __always_inline void dispatcher_delete_protocol_stack(conn_tuple_t *tuple, protocol_stack_t *stack) {
    bool flipped = normalize_tuple(tuple);
    delete_protocol_stack(tuple, stack, FLAG_SOCKET_FILTER_DELETION);
    if (flipped) {
        flip_tuple(tuple);
    }
}

static __always_inline void protocol_dispatcher_entrypoint_sk_msg(struct sk_msg_md *msg) {
    skb_info_t skb_info = {0};
    conn_tuple_t skb_tup = {0};
    
    log_debug("protocol_dispatcher_entrypoint_sk_msg");

    // Exporting the conn tuple from the skb, alongside couple of relevant fields from the skb.
    if (!read_conn_tuple_sk_msg(msg, &skb_info, &skb_tup)) {
        log_debug("dispatch no read conn");
        return;
    }

        struct sockhash_key key = {
        .remote_ip4 = msg->remote_ip4,
        .local_ip4 = msg->local_ip4,
        .remote_port = msg->remote_port,
        .local_port = msg->local_port,
    };

    log_debug("skmsg key: remote: %x (%u)", key.remote_ip4, key.remote_port);
    log_debug("skmsg key:  local: %x (%u)", key.local_ip4, key.local_port);

    u64 *cookie = bpf_map_lookup_elem(&socket_cookie_hash, &key);
    if (!cookie) {
        log_debug("protocol_dispatcher_entrypoint_sk_msg: no cookie");
        return;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    skb_tup.pid = pid_tgid >> 32;

    skb_tup.pid = *cookie >> 32;
    skb_tup.netns = *cookie;

    log_debug("sk_msg tup: saddr: %08llx %08llx (%u)", skb_tup.saddr_h, skb_tup.saddr_l, skb_tup.sport);
    log_debug("sk_msg tup: daddr: %08llx %08llx (%u)", skb_tup.daddr_h, skb_tup.daddr_l, skb_tup.dport);
    log_debug("sk_msg tup: netns: %08x pid: %u", skb_tup.netns, skb_tup.pid);

    conn_tuple_t normalized_tuple = skb_tup;
    normalize_tuple(&normalized_tuple);
    normalized_tuple.pid = 0;
    normalized_tuple.netns = 0;
 
    bool tcp_termination = is_tcp_termination(&skb_info);
    // We don't process non tcp packets, nor empty tcp packets which are not tcp termination packets.
    if (!is_tcp(&skb_tup) || (is_payload_empty(&skb_info) && !tcp_termination)) {
        log_debug("dispatch no tcp");
        return;
    }

    // Making sure we've not processed the same tcp segment, which can happen when a single packet travels different
    // interfaces.
    if (has_sequence_seen_before(&skb_tup, &skb_info)) {
        log_debug("dispatch seen before");
        return;
    }

    if (tcp_termination) {
        bpf_map_delete_elem(&connection_states, &skb_tup);
    }

    protocol_stack_t *stack = get_protocol_stack(&normalized_tuple);
    if (!stack) {
        // should never happen, but it is required by the eBPF verifier
        return;
    }

    // This is used to signal the tracer program that this protocol stack
    // is also shared with our USM program for the purposes of deletion.
    // For more context refer to the comments in `delete_protocol_stack`
    stack->flags |= FLAG_USM_ENABLED;

    protocol_t cur_fragment_protocol = get_protocol_from_stack(stack, LAYER_APPLICATION);
    if (tcp_termination) {
        dispatcher_delete_protocol_stack(&normalized_tuple, stack);
    } else if (is_protocol_layer_known(stack, LAYER_ENCRYPTION)) {
        // If we have a TLS connection and we're not in the middle of a TCP termination, we can skip the packet.
        return;
    }

    if (msg && cur_fragment_protocol == PROTOCOL_UNKNOWN) {
        log_debug("[protocol_dispatcher_entrypoint_sk_msg]: %p was not classified", msg);
        char request_fragment[CLASSIFICATION_MAX_BUFFER];
        bpf_memset(request_fragment, 0, sizeof(request_fragment));

        //read_into_buffer_for_classification((char *)request_fragment, skb, skb_info.data_off);
        long err = bpf_msg_pull_data(msg, 0, CLASSIFICATION_MAX_BUFFER, 0);
        if (err < 0) {
            log_debug("protocol_dispatcher_entrypoint_sk_msg: pull fail %ld", err);
            return;
        }

        void *data = msg->data;
        void *data_end = msg->data_end;
        if (data + CLASSIFICATION_MAX_BUFFER > data_end) {
            return;
        }

        bpf_memcpy(request_fragment, data, CLASSIFICATION_MAX_BUFFER);

        const size_t payload_length = skb_info.data_end - skb_info.data_off;
        const size_t final_fragment_size = payload_length < CLASSIFICATION_MAX_BUFFER ? payload_length : CLASSIFICATION_MAX_BUFFER;
        classify_protocol_for_dispatcher(&cur_fragment_protocol, &skb_tup, request_fragment, final_fragment_size);
        if (is_kafka_monitoring_enabled() && cur_fragment_protocol == PROTOCOL_UNKNOWN) {
            bpf_tail_call_compat(msg, &skmsg_dispatcher_classification_progs, DISPATCHER_KAFKA_PROG);
        }
        log_debug("[protocol_dispatcher_entrypoint_sk_msg]: %p Classifying protocol as: %d", msg, cur_fragment_protocol);
        // If there has been a change in the classification, save the new protocol.
        if (cur_fragment_protocol != PROTOCOL_UNKNOWN) {
            set_protocol(stack, cur_fragment_protocol);
        }
    }

    if (cur_fragment_protocol != PROTOCOL_UNKNOWN) {
        // dispatch if possible
        const u32 zero = 0;
        dispatcher_arguments_t *args = bpf_map_lookup_elem(&dispatcher_arguments, &zero);
        if (args == NULL) {
            log_debug("dispatcher failed to save arguments for tail call");
            return;
        }
        bpf_memset(args, 0, sizeof(dispatcher_arguments_t));
        bpf_memcpy(&args->tup, &skb_tup, sizeof(conn_tuple_t));
        bpf_memcpy(&args->skb_info, &skb_info, sizeof(skb_info_t));

        log_debug("dispatching to protocol number: %d", cur_fragment_protocol);
        bpf_tail_call_compat(msg, &skmsg_protocols_progs, protocol_to_program(cur_fragment_protocol));
    }
}

static __always_inline void kprobe_protocol_dispatcher_entrypoint(struct pt_regs *ctx, struct sock *sock, const void *buffer, size_t bytes, bool receive) {
    conn_tuple_t tup = {0};

    u64 pid_tgid = bpf_get_current_pid_tgid();

    if (!read_conn_tuple(&tup, sock, pid_tgid, CONN_TYPE_TCP)) {
        log_debug("kprobe_protoco: could not read conn tuple");
        return;
    }

    // struct sockhash_key key = {
    //     .remote_ip4 = tup.daddr_l,
    //     .local_ip4 = tup.saddr_l,
    //     .remote_port = bpf_ntohl(tup.dport),
    //     .local_port = tup.sport,
    // };

    // log_debug("kprobe key: remote: %x (%u)", key.remote_ip4, key.remote_port);
    // log_debug("kprobe key:  local: %x (%u)", key.local_ip4, key.local_port);


    if (receive) {
        __u64 tmp_h;
        __u64 tmp_l;

        // The tup data is read from the socker so source is always local but here
        // we are receveing data on the socket so flip things around.  Maybe this
        // could/should even come from the skb.
        tmp_h = tup.daddr_h;
        tmp_l = tup.daddr_l;
        tup.daddr_h = tup.saddr_h;
        tup.daddr_l = tup.saddr_l;
        tup.saddr_h = tmp_h;
        tup.saddr_l = tmp_l;

        __u16 tmp_port;
        tmp_port = tup.dport;
        tup.dport = tup.sport;
        tup.sport = tmp_port;
    }

    // u64 *cookie = bpf_map_lookup_elem(&socket_cookie_hash, &key);
    // if (!cookie) {
    //     log_debug("kprobe_protocol_dipatcher_entrypoint: no cookie");
    //     return;
    // }

    // tup.pid = *cookie >> 32;
    // tup.netns = *cookie;
    // tup.netns = 0;
    // tup.pid = pid_tgid >> 32;

    log_debug("kprobe tup: saddr: %08llx %08llx (%u)", tup.saddr_h, tup.saddr_l, tup.sport);
    log_debug("kprobe tup: daddr: %08llx %08llx (%u)", tup.daddr_h, tup.daddr_l, tup.dport);
    log_debug("kprobe tup: netns: %08x pid: %u", tup.netns, tup.pid);

    conn_tuple_t normalized_tuple = tup;
    normalize_tuple(&normalized_tuple);
    normalized_tuple.pid = 0;
    normalized_tuple.netns = 0;

    // Exporting the conn tuple from the skb, alongside couple of relevant fields from the skb.
    // if (!read_conn_tuple_skb(skb, &skb_info, &skb_tup)) {
    //     return;
    // }

    // bool tcp_termination = is_tcp_termination(&skb_info);
    // // We don't process non tcp packets, nor empty tcp packets which are not tcp termination packets.
    // if (!is_tcp(&skb_tup) || (is_payload_empty(&skb_info) && !tcp_termination)) {
    //     return;
    // }

    // Making sure we've not processed the same tcp segment, which can happen when a single packet travels different
    // interfaces.
    // if (has_sequence_seen_before(&skb_tup, &skb_info)) {
    //     return;
    // }

    // if (tcp_termination) {
    //     bpf_map_delete_elem(&connection_states, &skb_tup);
    // }

    protocol_stack_t *stack = get_protocol_stack(&normalized_tuple);
    if (!stack) {
        // should never happen, but it is required by the eBPF verifier
        return;
    }

    // This is used to signal the tracer program that this protocol stack
    // is also shared with our USM program for the purposes of deletion.
    // For more context refer to the comments in `delete_protocol_stack`
    stack->flags |= FLAG_USM_ENABLED;

    protocol_t cur_fragment_protocol = get_protocol_from_stack(stack, LAYER_APPLICATION);
    if (0 /* tcp_termination */) {
        dispatcher_delete_protocol_stack(&normalized_tuple, stack);
    } else if (is_protocol_layer_known(stack, LAYER_ENCRYPTION)) {
        // If we have a TLS connection and we're not in the middle of a TCP termination, we can skip the packet.
        return;
    }

    if (cur_fragment_protocol == PROTOCOL_UNKNOWN) {
        log_debug("[kprobe_protocol_dispatcher_entrypoint]: %p was not classified", sock);
        char request_fragment[CLASSIFICATION_MAX_BUFFER];
        bpf_memset(request_fragment, 0, sizeof(request_fragment));
        // read_into_kernel_buffer_for_classification((char *)request_fragment, buffer);
        read_into_user_buffer_for_classification((char *)request_fragment, buffer);
        const size_t final_fragment_size = bytes < CLASSIFICATION_MAX_BUFFER ? bytes : CLASSIFICATION_MAX_BUFFER;
        classify_protocol_for_dispatcher(&cur_fragment_protocol, &tup, request_fragment, final_fragment_size);
        if (is_kafka_monitoring_enabled() && cur_fragment_protocol == PROTOCOL_UNKNOWN) {
            const __u32 zero = 0;
            kprobe_dispatcher_arguments_t *args = bpf_map_lookup_elem(&kprobe_dispatcher_arguments, &zero);
            if (args == NULL) {
                return;
            }
            *args = (kprobe_dispatcher_arguments_t){
                .tup = tup,
                .buffer_ptr = buffer,
                .data_end = bytes,
                .data_off = 0,
            };
            bpf_tail_call_compat(ctx, &kprobe_dispatcher_classification_progs, DISPATCHER_KAFKA_PROG);
        }
        log_debug("[kprobe_protocol_dispatcher_entrypoint]: %p Classifying protocol as: %d", sock, cur_fragment_protocol);
        // If there has been a change in the classification, save the new protocol.
        if (cur_fragment_protocol != PROTOCOL_UNKNOWN) {
            set_protocol(stack, cur_fragment_protocol);
        }
    }

    if (cur_fragment_protocol != PROTOCOL_UNKNOWN) {
        // dispatch if possible


        conn_tuple_t *final_tuple = &tup;
        if (cur_fragment_protocol == PROTOCOL_HTTP) {
            final_tuple = &normalized_tuple;

        }

        const u32 zero = 0;
        kprobe_dispatcher_arguments_t *args = bpf_map_lookup_elem(&kprobe_dispatcher_arguments, &zero);
        if (args == NULL) {
            log_debug("dispatcher failed to save arguments for tail call");
            return;
        }

        bpf_memset(args, 0, sizeof(*args));
        bpf_memcpy(&args->tup, final_tuple, sizeof(conn_tuple_t));
        args->buffer_ptr = buffer;
        args->data_end = bytes;

        log_debug("kprobe_dispatching to protocol number: %d", cur_fragment_protocol);
        bpf_tail_call_compat(ctx, &kprobe_protocols_progs, protocol_to_program(cur_fragment_protocol));
    }
}

// A shared implementation for the runtime & prebuilt socket filter that classifies & dispatches the protocols of the connections.
static __always_inline void protocol_dispatcher_entrypoint(struct __sk_buff *skb) {
    skb_info_t skb_info = {0};
    conn_tuple_t skb_tup = {0};

    // Exporting the conn tuple from the skb, alongside couple of relevant fields from the skb.
    if (!read_conn_tuple_skb(skb, &skb_info, &skb_tup)) {
        return;
    }

    bool tcp_termination = is_tcp_termination(&skb_info);
    // We don't process non tcp packets, nor empty tcp packets which are not tcp termination packets.
    if (!is_tcp(&skb_tup) || (is_payload_empty(&skb_info) && !tcp_termination)) {
        return;
    }

    // Making sure we've not processed the same tcp segment, which can happen when a single packet travels different
    // interfaces.
    if (has_sequence_seen_before(&skb_tup, &skb_info)) {
        return;
    }

    if (tcp_termination) {
        bpf_map_delete_elem(&connection_states, &skb_tup);
    }

    protocol_stack_t *stack = get_protocol_stack(&skb_tup);
    if (!stack) {
        // should never happen, but it is required by the eBPF verifier
        return;
    }

    // This is used to signal the tracer program that this protocol stack
    // is also shared with our USM program for the purposes of deletion.
    // For more context refer to the comments in `delete_protocol_stack`
    stack->flags |= FLAG_USM_ENABLED;

    protocol_t cur_fragment_protocol = get_protocol_from_stack(stack, LAYER_APPLICATION);
    if (tcp_termination) {
        dispatcher_delete_protocol_stack(&skb_tup, stack);
    } else if (is_protocol_layer_known(stack, LAYER_ENCRYPTION)) {
        // If we have a TLS connection and we're not in the middle of a TCP termination, we can skip the packet.
        return;
    }

    if (cur_fragment_protocol == PROTOCOL_UNKNOWN) {
        log_debug("[protocol_dispatcher_entrypoint]: %p was not classified", skb);
        char request_fragment[CLASSIFICATION_MAX_BUFFER];
        bpf_memset(request_fragment, 0, sizeof(request_fragment));
        read_into_buffer_for_classification((char *)request_fragment, skb, skb_info.data_off);
        const size_t payload_length = skb_info.data_end - skb_info.data_off;
        const size_t final_fragment_size = payload_length < CLASSIFICATION_MAX_BUFFER ? payload_length : CLASSIFICATION_MAX_BUFFER;
        classify_protocol_for_dispatcher(&cur_fragment_protocol, &skb_tup, request_fragment, final_fragment_size);
        if (is_kafka_monitoring_enabled() && cur_fragment_protocol == PROTOCOL_UNKNOWN) {
            bpf_tail_call_compat(skb, &dispatcher_classification_progs, DISPATCHER_KAFKA_PROG);
        }
        log_debug("[protocol_dispatcher_entrypoint]: %p Classifying protocol as: %d", skb, cur_fragment_protocol);
        // If there has been a change in the classification, save the new protocol.
        if (cur_fragment_protocol != PROTOCOL_UNKNOWN) {
            set_protocol(stack, cur_fragment_protocol);
        }
    }

    if (cur_fragment_protocol != PROTOCOL_UNKNOWN) {
        // dispatch if possible
        const u32 zero = 0;
        dispatcher_arguments_t *args = bpf_map_lookup_elem(&dispatcher_arguments, &zero);
        if (args == NULL) {
            log_debug("dispatcher failed to save arguments for tail call");
            return;
        }
        bpf_memset(args, 0, sizeof(dispatcher_arguments_t));
        bpf_memcpy(&args->tup, &skb_tup, sizeof(conn_tuple_t));
        bpf_memcpy(&args->skb_info, &skb_info, sizeof(skb_info_t));

        log_debug("dispatching to protocol number: %d", cur_fragment_protocol);
        bpf_tail_call_compat(skb, &protocols_progs, protocol_to_program(cur_fragment_protocol));
    }
}

static __always_inline void cgroup_protocol_dispatcher_entrypoint(struct __sk_buff *skb) {
    skb_info_t skb_info = {0};
    conn_tuple_t skb_tup = {0};

    // Exporting the conn tuple from the skb, alongside couple of relevant fields from the skb.
    if (!read_conn_tuple_skb_cgroup(skb, &skb_info, &skb_tup)) {
        return;
    }

    u64 cookie = bpf_get_socket_cookie(skb);
    skb_tup.pid = cookie >> 32;
    skb_tup.netns = cookie;

    log_debug("cgroup tup: saddr: %08llx %08llx (%u)", skb_tup.saddr_h, skb_tup.saddr_l, skb_tup.sport);
    log_debug("cgroup tup: daddr: %08llx %08llx (%u)", skb_tup.daddr_h, skb_tup.daddr_l, skb_tup.dport);
    log_debug("cgroup tup: netns: %08x pid: %u", skb_tup.netns, skb_tup.pid);

    conn_tuple_t normalized_tuple = skb_tup;
    normalize_tuple(&normalized_tuple);
    normalized_tuple.pid = 0;
    normalized_tuple.netns = 0;

    bool tcp_termination = is_tcp_termination(&skb_info);
    // We don't process non tcp packets, nor empty tcp packets which are not tcp termination packets.
    if (!is_tcp(&skb_tup) || (is_payload_empty(&skb_info) && !tcp_termination)) {
        return;
    }

    // Making sure we've not processed the same tcp segment, which can happen when a single packet travels different
    // interfaces.
    if (has_sequence_seen_before(&skb_tup, &skb_info)) {
        return;
    }

    if (tcp_termination) {
        bpf_map_delete_elem(&connection_states, &skb_tup);
    }

    protocol_stack_t *stack = get_protocol_stack(&normalized_tuple);
    if (!stack) {
        // should never happen, but it is required by the eBPF verifier
        return;
    }

    // This is used to signal the tracer program that this protocol stack
    // is also shared with our USM program for the purposes of deletion.
    // For more context refer to the comments in `delete_protocol_stack`
    stack->flags |= FLAG_USM_ENABLED;

    protocol_t cur_fragment_protocol = get_protocol_from_stack(stack, LAYER_APPLICATION);
    if (tcp_termination) {
        dispatcher_delete_protocol_stack(&skb_tup, stack);
    } else if (is_protocol_layer_known(stack, LAYER_ENCRYPTION)) {
        // If we have a TLS connection and we're not in the middle of a TCP termination, we can skip the packet.
        return;
    }

    if (cur_fragment_protocol == PROTOCOL_UNKNOWN) {
        log_debug("[protocol_dispatcher_entrypoint]: %p was not classified", skb);
        char request_fragment[CLASSIFICATION_MAX_BUFFER];
        bpf_memset(request_fragment, 0, sizeof(request_fragment));
        read_into_buffer_for_classification((char *)request_fragment, skb, skb_info.data_off);
        const size_t payload_length = skb_info.data_end - skb_info.data_off;
        const size_t final_fragment_size = payload_length < CLASSIFICATION_MAX_BUFFER ? payload_length : CLASSIFICATION_MAX_BUFFER;
        classify_protocol_for_dispatcher(&cur_fragment_protocol, &skb_tup, request_fragment, final_fragment_size);
        if (is_kafka_monitoring_enabled() && cur_fragment_protocol == PROTOCOL_UNKNOWN) {
            bpf_tail_call_compat(skb, &cgroup_skb_dispatcher_classification_progs, DISPATCHER_KAFKA_PROG);
        }
        log_debug("[protocol_dispatcher_entrypoint]: %p Classifying protocol as: %d", skb, cur_fragment_protocol);
        // If there has been a change in the classification, save the new protocol.
        if (cur_fragment_protocol != PROTOCOL_UNKNOWN) {
            set_protocol(stack, cur_fragment_protocol);
        }
    }

    if (cur_fragment_protocol != PROTOCOL_UNKNOWN) {
        // dispatch if possible
        const u32 zero = 0;
        dispatcher_arguments_t *args = bpf_map_lookup_elem(&dispatcher_arguments, &zero);
        if (args == NULL) {
            log_debug("dispatcher failed to save arguments for tail call");
            return;
        }
        bpf_memset(args, 0, sizeof(dispatcher_arguments_t));
        bpf_memcpy(&args->tup, &skb_tup, sizeof(conn_tuple_t));
        bpf_memcpy(&args->skb_info, &skb_info, sizeof(skb_info_t));

        log_debug("dispatching to protocol number: %d", cur_fragment_protocol);
        bpf_tail_call_compat(skb, &cgroup_skb_protocols_progs, protocol_to_program(cur_fragment_protocol));
    }
}

static __always_inline void sk_msg_dispatch_kafka(struct sk_msg_md *msg) {
    skb_info_t skb_info = {0};
    conn_tuple_t skb_tup = {0};
    // Exporting the conn tuple from the skb, alongside couple of relevant fields from the skb.
    if (!read_conn_tuple_sk_msg(msg, &skb_info, &skb_tup)) {
        return;
    }

            struct sockhash_key key = {
        .remote_ip4 = msg->remote_ip4,
        .local_ip4 = msg->local_ip4,
        .remote_port = msg->remote_port,
        .local_port = msg->local_port,
    };

    u64 *cookie = bpf_map_lookup_elem(&socket_cookie_hash, &key);
    if (!cookie) {
        log_debug("sk_msg_dispatch_kafka: no cookie");
        return;
    }

    log_debug("sk_msg_dispatch_kafka: cookie %llu", *cookie);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    skb_tup.netns = 0;
    skb_tup.pid = pid_tgid >> 32;

    skb_tup.pid = *cookie >> 32;
    skb_tup.netns = *cookie;

    log_debug("kafka sk_msg tup: saddr: %08llx %08llx (%u)", skb_tup.saddr_h, skb_tup.saddr_l, skb_tup.sport);
    log_debug("kafka sk_msg tup: daddr: %08llx %08llx (%u)", skb_tup.daddr_h, skb_tup.daddr_l, skb_tup.dport);
    log_debug("kafka sk_msg tup: netns: %08x pid: %u", skb_tup.netns, skb_tup.pid);


    char request_fragment[CLASSIFICATION_MAX_BUFFER];
    bpf_memset(request_fragment, 0, sizeof(request_fragment));

    //read_into_buffer_for_classification((char *)request_fragment, skb, skb_info.data_off);
    long err = bpf_msg_pull_data(msg, 0, CLASSIFICATION_MAX_BUFFER, 0);
    if (err < 0) {
        log_debug("protocol_dispatcher_entrypoint_sk_msg: pull fail %ld", err);
        return;
    }

    void *data = msg->data;
    void *data_end = msg->data_end;
    if (data + CLASSIFICATION_MAX_BUFFER > data_end) {
        return;
    }

    bpf_memcpy(request_fragment, data, CLASSIFICATION_MAX_BUFFER);

    conn_tuple_t normalized_tuple = skb_tup;
    normalize_tuple(&normalized_tuple);
    normalized_tuple.pid = 0;
    normalized_tuple.netns = 0;

    const size_t payload_length = skb_info.data_end - skb_info.data_off;
    const size_t final_fragment_size = payload_length < CLASSIFICATION_MAX_BUFFER ? payload_length : CLASSIFICATION_MAX_BUFFER;
    protocol_t cur_fragment_protocol = PROTOCOL_UNKNOWN;
    if (skskb_is_kafka(msg, &skb_info, request_fragment, final_fragment_size)) {
        cur_fragment_protocol = PROTOCOL_KAFKA;
        update_protocol_stack(&normalized_tuple, cur_fragment_protocol);
    }

    if (cur_fragment_protocol != PROTOCOL_UNKNOWN) {
        // dispatch if possible
        const u32 zero = 0;
        dispatcher_arguments_t *args = bpf_map_lookup_elem(&dispatcher_arguments, &zero);
        if (args == NULL) {
            log_debug("dispatcher failed to save arguments for tail call");
            return;
        }
        bpf_memset(args, 0, sizeof(dispatcher_arguments_t));
        bpf_memcpy(&args->tup, &skb_tup, sizeof(conn_tuple_t));
        bpf_memcpy(&args->skb_info, &skb_info, sizeof(skb_info_t));

        // dispatch if possible
        log_debug("dispatching to protocol number: %d", cur_fragment_protocol);
        bpf_tail_call_compat(msg, &skmsg_protocols_progs, protocol_to_program(cur_fragment_protocol));
    }
    return;
}

static __always_inline void kprobe_dispatch_kafka(struct pt_regs *ctx)
{
    log_debug("kprobe_dispatch_kafka");

    const __u32 zero = 0;
    kprobe_dispatcher_arguments_t *args = bpf_map_lookup_elem(&kprobe_dispatcher_arguments, &zero);
    if (args == NULL) {
        return;
    }

    char request_fragment[CLASSIFICATION_MAX_BUFFER];
    bpf_memset(request_fragment, 0, sizeof(request_fragment));

    // char *request_fragment = bpf_map_lookup_elem(&tls_classification_heap, &zero);
    // if (request_fragment == NULL) {
    //     return;
    // }

    conn_tuple_t normalized_tuple = args->tup;
    normalize_tuple(&normalized_tuple);
    normalized_tuple.pid = 0;
    normalized_tuple.netns = 0;

    // read_into_kernel_buffer_for_classification(request_fragment, args->buffer_ptr);
    read_into_user_buffer_for_classification(request_fragment, args->buffer_ptr);
    bool is_kafka = kprobe_is_kafka(ctx, args, request_fragment, CLASSIFICATION_MAX_BUFFER);
    log_debug("kprobe_dispatch_kafka: is_kafka %d", is_kafka);
    if (!is_kafka) {
        return;
    }

    protocol_stack_t *stack = get_protocol_stack(&normalized_tuple);
    if (!stack) {
        return;
    }

    set_protocol(stack, PROTOCOL_KAFKA);
    bpf_tail_call_compat(ctx, &kprobe_protocols_progs, PROG_KAFKA);
}

static __always_inline void dispatch_kafka(struct __sk_buff *skb) {
    skb_info_t skb_info = {0};
    conn_tuple_t skb_tup = {0};
    // Exporting the conn tuple from the skb, alongside couple of relevant fields from the skb.
    if (!read_conn_tuple_skb(skb, &skb_info, &skb_tup)) {
        return;
    }

    char request_fragment[CLASSIFICATION_MAX_BUFFER];
    bpf_memset(request_fragment, 0, sizeof(request_fragment));
    read_into_buffer_for_classification((char *)request_fragment, skb, skb_info.data_off);
    const size_t payload_length = skb_info.data_end - skb_info.data_off;
    const size_t final_fragment_size = payload_length < CLASSIFICATION_MAX_BUFFER ? payload_length : CLASSIFICATION_MAX_BUFFER;
    protocol_t cur_fragment_protocol = PROTOCOL_UNKNOWN;
    if (is_kafka(skb, &skb_info, request_fragment, final_fragment_size)) {
        cur_fragment_protocol = PROTOCOL_KAFKA;
        update_protocol_stack(&skb_tup, cur_fragment_protocol);
    }

    if (cur_fragment_protocol != PROTOCOL_UNKNOWN) {
        // dispatch if possible
        const u32 zero = 0;
        dispatcher_arguments_t *args = bpf_map_lookup_elem(&dispatcher_arguments, &zero);
        if (args == NULL) {
            log_debug("dispatcher failed to save arguments for tail call");
            return;
        }
        bpf_memset(args, 0, sizeof(dispatcher_arguments_t));
        bpf_memcpy(&args->tup, &skb_tup, sizeof(conn_tuple_t));
        bpf_memcpy(&args->skb_info, &skb_info, sizeof(skb_info_t));

        // dispatch if possible
        log_debug("dispatching to protocol number: %d", cur_fragment_protocol);
        bpf_tail_call_compat(skb, &protocols_progs, protocol_to_program(cur_fragment_protocol));
    }
    return;
}

static __always_inline void cgroup_skb_dispatch_kafka(struct __sk_buff *skb) {
    skb_info_t skb_info = {0};
    conn_tuple_t skb_tup = {0};
    // Exporting the conn tuple from the skb, alongside couple of relevant fields from the skb.
    if (!read_conn_tuple_skb_cgroup(skb, &skb_info, &skb_tup)) {
        return;
    }

    u64 cookie = bpf_get_socket_cookie(skb);
    skb_tup.pid = cookie >> 32;
    skb_tup.netns = cookie;

    conn_tuple_t normalized_tuple = skb_tup;
    normalize_tuple(&normalized_tuple);
    normalized_tuple.pid = 0;
    normalized_tuple.netns = 0;

    char request_fragment[CLASSIFICATION_MAX_BUFFER];
    bpf_memset(request_fragment, 0, sizeof(request_fragment));
    read_into_buffer_for_classification((char *)request_fragment, skb, skb_info.data_off);
    const size_t payload_length = skb_info.data_end - skb_info.data_off;
    const size_t final_fragment_size = payload_length < CLASSIFICATION_MAX_BUFFER ? payload_length : CLASSIFICATION_MAX_BUFFER;
    protocol_t cur_fragment_protocol = PROTOCOL_UNKNOWN;
    if (is_kafka(skb, &skb_info, request_fragment, final_fragment_size)) {
        cur_fragment_protocol = PROTOCOL_KAFKA;
        update_protocol_stack(&normalized_tuple, cur_fragment_protocol);
    }

    if (cur_fragment_protocol != PROTOCOL_UNKNOWN) {
        // dispatch if possible
        const u32 zero = 0;
        dispatcher_arguments_t *args = bpf_map_lookup_elem(&dispatcher_arguments, &zero);
        if (args == NULL) {
            log_debug("dispatcher failed to save arguments for tail call");
            return;
        }
        bpf_memset(args, 0, sizeof(dispatcher_arguments_t));
        bpf_memcpy(&args->tup, &skb_tup, sizeof(conn_tuple_t));
        bpf_memcpy(&args->skb_info, &skb_info, sizeof(skb_info_t));

        // dispatch if possible
        log_debug("dispatching to protocol number: %d", cur_fragment_protocol);
        bpf_tail_call_compat(skb, &cgroup_skb_protocols_progs, protocol_to_program(cur_fragment_protocol));
    }
    return;
}

static __always_inline bool fetch_dispatching_arguments(conn_tuple_t *tup, skb_info_t *skb_info) {
    const __u32 zero = 0;
    dispatcher_arguments_t *args = bpf_map_lookup_elem(&dispatcher_arguments, &zero);
    if (args == NULL) {
        return false;
    }
    bpf_memcpy(tup, &args->tup, sizeof(conn_tuple_t));
    bpf_memcpy(skb_info, &args->skb_info, sizeof(skb_info_t));

    return true;
}

#endif
