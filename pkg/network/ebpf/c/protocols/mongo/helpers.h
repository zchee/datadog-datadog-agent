#ifndef __MONGO_HELPERS_H
#define __MONGO_HELPERS_H

#include "bpf_helpers.h"                       // for __always_inline, BPF_ANY, bpf_map_delete_elem, bpf_map_lookup_...
#include "conn_tuple.h"                        // for conn_tuple_t
#include "ktypes.h"                            // for false, bool, true, __s32, NULL, __u32
#include "protocols/classification/common.h"   // for CHECK_PRELIMINARY_BUFFER_CONDITIONS
#include "protocols/classification/maps.h"     // for mongo_request_id
#include "protocols/classification/structs.h"  // for mongo_msg_header, mongo_key
#include "protocols/mongo/defs.h"              // for MONGO_HEADER_LENGTH, MONGO_OP_COMPRESSED, MONGO_OP_DELETE, MON...

static __always_inline void mongo_handle_request(conn_tuple_t *tup, __s32 request_id) {
    // mongo_request_id acts as a set, and we only check for existence in that set.
    // Thus, the val = true is just a dummy value, as we ignore the value.
    const bool val = true;
    mongo_key key = {};
    key.tup = *tup;
    key.req_id = request_id;
    bpf_map_update_elem(&mongo_request_id, &key, &val, BPF_ANY);
}

static __always_inline bool mongo_have_seen_request(conn_tuple_t *tup, __s32 response_to) {
    mongo_key key = {};
    key.tup = *tup;
    key.req_id = response_to;
    void *exists = bpf_map_lookup_elem(&mongo_request_id, &key);
    bpf_map_delete_elem(&mongo_request_id, &key);
    return exists != NULL;
}

// Checks if the given buffer represents a mongo request or a response.
static __always_inline bool is_mongo(conn_tuple_t *tup, const char *buf, __u32 size) {
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, size, MONGO_HEADER_LENGTH);

    mongo_msg_header header = *((mongo_msg_header*)buf);

    // The message length should contain the size of headers
    if (header.message_length < MONGO_HEADER_LENGTH) {
        return false;
    }

    if (header.request_id < 0) {
        return false;
    }

    switch (header.op_code) {
    case MONGO_OP_UPDATE:
    case MONGO_OP_INSERT:
    case MONGO_OP_DELETE:
        // If the response_to is not 0, then it is not a valid mongo request by the RFC.
        return header.response_to == 0;
    case MONGO_OP_REPLY:
        // If the message is a reply, make sure we've seen the request of the response.
        // If will eliminate false positives.
        return mongo_have_seen_request(tup, header.response_to);
    case MONGO_OP_QUERY:
    case MONGO_OP_GET_MORE:
        if (header.response_to == 0) {
            mongo_handle_request(tup, header.request_id);
            return true;
        }
        return false;
    case MONGO_OP_COMPRESSED:
    case MONGO_OP_MSG:
        // If the response_to is not 0, then it is not a valid mongo request by the RFC.
        if (header.response_to == 0) {
            mongo_handle_request(tup, header.request_id);
            return true;
        }
        return mongo_have_seen_request(tup, header.response_to);
    }

    return false;
}

#endif
