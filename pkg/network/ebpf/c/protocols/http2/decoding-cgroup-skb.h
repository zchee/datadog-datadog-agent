#ifndef __HTTP2_DECODING_CGROUP_SKB_H
#define __HTTP2_DECODING_CGROUP_SKB_H

#include "protocols/http2/decoding-common.h"
#include "protocols/http2/usm-events.h"
#include "protocols/http/types.h"

SEC("cgroup/skb/egress/http2_handle_first_frame")
int cgroup_skb__http2_handle_first_frame(struct __sk_buff *skb) {
    const __u32 zero = 0;

    dispatcher_arguments_t dispatcher_args_copy;
    // We're not calling fetch_dispatching_arguments as, we need to modify the `data_off` field of packet, so
    // the next prog will start to read from the next valid frame.
    dispatcher_arguments_t *args = bpf_map_lookup_elem(&dispatcher_arguments, &zero);
    if (args == NULL) {
        return 1;
    }
    dispatcher_args_copy = *args;

    // If we detected a tcp termination we should stop processing the packet, and clear its dynamic table by deleting the counter.
    if (is_tcp_termination(&dispatcher_args_copy.skb_info)) {
        // Deleting the entry for the original tuple.
        bpf_map_delete_elem(&http2_remainder, &dispatcher_args_copy.tup);
        bpf_map_delete_elem(&http2_dynamic_counter_table, &dispatcher_args_copy.tup);
        terminated_http2_batch_enqueue(&dispatcher_args_copy.tup);
        // In case of local host, the protocol will be deleted for both (client->server) and (server->client),
        // so we won't reach for that path again in the code, so we're deleting the opposite side as well.
        flip_tuple(&dispatcher_args_copy.tup);
        bpf_map_delete_elem(&http2_dynamic_counter_table, &dispatcher_args_copy.tup);
        bpf_map_delete_elem(&http2_remainder, &dispatcher_args_copy.tup);
        return 1;
    }

    pktbuf_t pkt = pktbuf_from_cgroup_skb_egress(skb, &dispatcher_args_copy.skb_info);

    handle_first_frame(pkt, &args->skb_info.data_off, &dispatcher_args_copy.tup);
    return 1;
}

SEC("cgroup/skb/egress/http2_frame_filter")
int cgroup_skb__http2_frame_filter(struct __sk_buff *skb) {
    dispatcher_arguments_t dispatcher_args_copy;
    bpf_memset(&dispatcher_args_copy, 0, sizeof(dispatcher_arguments_t));
    if (!fetch_dispatching_arguments(&dispatcher_args_copy.tup, &dispatcher_args_copy.skb_info)) {
        return 1;
    }

    pktbuf_t pkt = pktbuf_from_cgroup_skb_egress(skb, &dispatcher_args_copy.skb_info);

    filter_frame(pkt, &dispatcher_args_copy, &dispatcher_args_copy.tup);
    return 1;
}

SEC("cgroup/skb/egress/http2_headers_parser")
int cgroup_skb__http2_headers_parser(struct __sk_buff *skb) {
    dispatcher_arguments_t dispatcher_args_copy;
    bpf_memset(&dispatcher_args_copy, 0, sizeof(dispatcher_arguments_t));
    if (!fetch_dispatching_arguments(&dispatcher_args_copy.tup, &dispatcher_args_copy.skb_info)) {
        return 1;
    }

    pktbuf_t pkt = pktbuf_from_cgroup_skb_egress(skb, &dispatcher_args_copy.skb_info);

    headers_parser(pkt, &dispatcher_args_copy, &dispatcher_args_copy.tup, NO_TAGS);

    return 1;
}

SEC("cgroup/skb/egress/http2_dynamic_table_cleaner")
int cgroup_skb__http2_dynamic_table_cleaner(struct __sk_buff *skb) {
    dispatcher_arguments_t dispatcher_args_copy;
    bpf_memset(&dispatcher_args_copy, 0, sizeof(dispatcher_arguments_t));
    if (!fetch_dispatching_arguments(&dispatcher_args_copy.tup, &dispatcher_args_copy.skb_info)) {
        return 1;
    }

    pktbuf_t pkt = pktbuf_from_cgroup_skb_egress(skb, &dispatcher_args_copy.skb_info);
    dynamic_table_cleaner(pkt, &dispatcher_args_copy.tup);

    return 1;
}

SEC("cgroup/skb/egress/http2_eos_parser")
int cgroup_skb__http2_eos_parser(struct __sk_buff *skb) {
    dispatcher_arguments_t dispatcher_args_copy;
    bpf_memset(&dispatcher_args_copy, 0, sizeof(dispatcher_arguments_t));
    if (!fetch_dispatching_arguments(&dispatcher_args_copy.tup, &dispatcher_args_copy.skb_info)) {
        return 1;
    }

    pktbuf_t pkt = pktbuf_from_cgroup_skb_egress(skb, &dispatcher_args_copy.skb_info);

    eos_parser(pkt, &dispatcher_args_copy, &dispatcher_args_copy.tup);
    return 1;
}

// http2_tls_termination is responsible for cleaning up the state of the HTTP2
// decoding once the TLS connection is terminated.
// SEC("sk_msg/http2_tls_termination")
// int sk_msg__http2_tls_termination(struct pt_regs *ctx) {
//     const __u32 zero = 0;
// 
//     sk_msg_dispatcher_arguments_t *args = bpf_map_lookup_elem(&kprobe_dispatcher_arguments, &zero);
//     if (args == NULL) {
//         return 0;
//     }
// 
//     bpf_map_delete_elem(&sk_msg_http2_iterations, &args->tup);
// 
//     terminated_http2_batch_enqueue(&args->tup);
//     // Deleting the entry for the original tuple.
//     bpf_map_delete_elem(&http2_remainder, &args->tup);
//     bpf_map_delete_elem(&http2_dynamic_counter_table, &args->tup);
//     // In case of local host, the protocol will be deleted for both (client->server) and (server->client),
//     // so we won't reach for that path again in the code, so we're deleting the opposite side as well.
//     flip_tuple(&args->tup);
//     bpf_map_delete_elem(&http2_dynamic_counter_table, &args->tup);
//     bpf_map_delete_elem(&http2_remainder, &args->tup);
// 
//     return 0;
// }
#endif
