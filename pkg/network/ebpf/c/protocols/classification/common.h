#ifndef __PROTOCOL_CLASSIFICATION_COMMON_H
#define __PROTOCOL_CLASSIFICATION_COMMON_H

#include "bpf_helpers.h"                 // for __always_inline
#include "bpf_telemetry.h"               // for FN_INDX_bpf_skb_load_bytes
#include "conn_tuple.h"                  // for conn_tuple_t, CONN_TYPE_TCP
#include "defs.h"                        // for CLASSIFICATION_MAX_BUFFER
#include "ip.h"                          // for skb_info_t
#include "ktypes.h"                      // for false, NULL, bool
#include "protocols/read_into_buffer.h"  // for BLK_SIZE, READ_INTO_BUFFER

#define CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, buf_size, min_buff_size) \
    do {                                                                  \
        if (buf_size < min_buff_size) {                                   \
            return false;                                                 \
        }                                                                 \
                                                                          \
        if (buf == NULL) {                                                \
            return false;                                                 \
        }                                                                 \
    } while (0)

// Returns true if the packet is TCP.
static __always_inline bool is_tcp(conn_tuple_t *tup) {
    return tup->metadata & CONN_TYPE_TCP;
}

// Returns true if the payload is empty.
static __always_inline bool is_payload_empty(skb_info_t *skb_info) {
    return skb_info->data_off == skb_info->data_end;
}

READ_INTO_BUFFER(for_classification, CLASSIFICATION_MAX_BUFFER, BLK_SIZE)

#endif
