#ifndef __PROTOCOL_DISPATCHER_MAPS_H
#define __PROTOCOL_DISPATCHER_MAPS_H

#include "map-defs.h"

#include "protocols/classification/defs.h"
#include "protocols/classification/shared-tracer-maps.h"

    struct sockhash_key {
        	__u32 remote_ip4;	/* Stored in network byte order */
	__u32 local_ip4;	/* Stored in network byte order */
	__u32 remote_port;	/* Stored in network byte order */
	__u32 local_port;	/* stored in host byte order */
    };

BPF_MAP(sockhash, BPF_MAP_TYPE_SOCKHASH, struct sockhash_key, struct bpf_sock *, 5000, 0, 0);

BPF_HASH_MAP(socket_cookie_hash, struct sockhash_key, u64, 10000); // should be sized based on number of connections


// Maps a connection tuple to latest tcp segment we've processed. Helps to detect same packets that travels multiple
// interfaces or retransmissions.
BPF_HASH_MAP(connection_states, conn_tuple_t, u32, 0)

// Map used to store the sub program actually used by the socket filter.
// This is done to avoid memory limitation when attaching a filter to
// a socket.
// See: https://datadoghq.atlassian.net/wiki/spaces/NET/pages/2326855913/HTTP#Program-size-limit-for-socket-filters
BPF_PROG_ARRAY(protocols_progs, PROG_MAX)

BPF_PROG_ARRAY(skmsg_protocols_progs, PROG_MAX)

// Map used to store the sub programs responsible for decoding of TLS encrypted
// traffic, after getting plain data from our TLS implementations
BPF_PROG_ARRAY(tls_process_progs, TLS_PROG_MAX)

BPF_PROG_ARRAY(kprobe_protocols_progs, KPROBE_PROG_MAX)

// This program array is needed to bypass a memory limit on socket filters.
// There is a limitation on number of instructions can be attached to a socket filter,
// as we dispatching more protocols, we reached that limit, thus we workaround it
// by using tail call.
BPF_PROG_ARRAY(dispatcher_classification_progs, DISPATCHER_PROG_MAX)

BPF_PROG_ARRAY(kprobe_dispatcher_classification_progs, DISPATCHER_PROG_MAX)

BPF_PROG_ARRAY(skmsg_dispatcher_classification_progs, DISPATCHER_PROG_MAX)

// Similar to the above, this array is used to keep some dispatcher functions
// in a separate tail call to avoid hitting limits. Specifically, putting Kafka
// classification in the same program as HTTP and HTTPs leads to hitting a stack
// limit.
BPF_PROG_ARRAY(tls_dispatcher_classification_progs, TLS_DISPATCHER_PROG_MAX)

// A per-cpu array to share conn_tuple and skb_info between the dispatcher and the tail-calls.
BPF_PERCPU_ARRAY_MAP(dispatcher_arguments, dispatcher_arguments_t, 1)

BPF_PERCPU_ARRAY_MAP(kprobe_dispatcher_arguments, kprobe_dispatcher_arguments_t, 1)

BPF_PERCPU_ARRAY_MAP(tls_dispatcher_arguments, tls_dispatcher_arguments_t, 1)

struct sock;

typedef struct {
    struct sock *sock;
    const void *buffer;
} tcp_kprobe_state_t;

BPF_HASH_MAP(tcp_kprobe_state, __u64, tcp_kprobe_state_t, 2048)

#endif
