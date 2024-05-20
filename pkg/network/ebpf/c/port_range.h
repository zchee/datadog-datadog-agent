#ifndef __PORT_RANGE_H
#define __PORT_RANGE_H

#include "bpf_helpers.h"  // for __always_inline
#include "compiler.h"     // for LOAD_CONSTANT
#include "conn_tuple.h"   // for conn_tuple_t
#include "ip.h"           // for flip_tuple
#include "ktypes.h"       // for __u16, __u64, false, bool, true, u16

static __always_inline __u16 ephemeral_range_begin() {
    __u64 val = 0;
    LOAD_CONSTANT("ephemeral_range_begin", val);
    return (__u16) val;
}

static __always_inline __u16 ephemeral_range_end() {
    __u64 val = 0;
    LOAD_CONSTANT("ephemeral_range_end", val);
    return (__u16) val;
}

static __always_inline int is_ephemeral_port(u16 port) {
    return port >= ephemeral_range_begin() && port <= ephemeral_range_end();
}

// ensure that the given tuple is in the (src: client, dst: server) format based
// on the port range heuristic
// The return value is true when the tuple is modified (flipped) or false otherwise.
static __always_inline bool normalize_tuple(conn_tuple_t *t) {
    if (is_ephemeral_port(t->sport) && !is_ephemeral_port(t->dport)) {
        return false;
    }

    if ((!is_ephemeral_port(t->sport) && is_ephemeral_port(t->dport)) || t->dport > t->sport) {
        // flip the tuple if:
        // 1) the tuple is currently in the (server, client) format;
        // 2) unlikely: if both ports are in the same range we ensure that sport > dport to make
        // this function return a deterministic result for a given pair of ports;
        flip_tuple(t);
        return true;
    }

    return false;
}

#endif
