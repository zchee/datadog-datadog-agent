#ifndef __HTTP2_DECODING_KPROBE_H
#define __HTTP2_DECODING_KPROBE_H

#include "protocols/http2/decoding-common.h"
#include "protocols/http2/usm-events.h"
#include "protocols/http/types.h"

// http2_tls_handle_first_frame is the entry point of our HTTP2+TLS processing.
// It is responsible for getting and filtering the first frame present in the
// buffer we get from the TLS kprobes.
//
// This first frame needs special handling as it may be split between multiple
// two buffers, and we may have the first part of the first frame from the
// processing of the previous buffer, in which case http2_tls_handle_first_frame
// will try to complete the frame.
//
// Once we have the first frame, we can continue to the regular frame filtering
// program.
SEC("kprobe/http2_handle_first_frame")
int kprobe__http2_handle_first_frame(struct pt_regs *ctx) {
    const __u32 zero = 0;

    kprobe_dispatcher_arguments_t dispatcher_args_copy;
    // We're not calling fetch_dispatching_arguments as, we need to modify the
    // `off` field of tls_dispatcher_arguments, so the next prog will start to
    // read from the next valid frame.
    kprobe_dispatcher_arguments_t *args = bpf_map_lookup_elem(&kprobe_dispatcher_arguments, &zero);
    if (args == NULL) {
        return false;
    }
    dispatcher_args_copy = *args;

    pktbuf_t pkt = pktbuf_from_kprobe(ctx, &dispatcher_args_copy);

    handle_first_frame(pkt, (__u32*)&args->data_off, &dispatcher_args_copy.tup);
    return 0;
}

// http2_tls_filter finds and filters the HTTP2 frames from the buffer got from
// the TLS probes. Interesting frames are saved to be parsed in
// http2_tls_headers_parser.
SEC("kprobe/http2_frame_filter")
int kprobe__http2_frame_filter(struct pt_regs *ctx) {
    const __u32 zero = 0;

    kprobe_dispatcher_arguments_t dispatcher_args_copy;
    // We're not calling fetch_dispatching_arguments as, we need to modify the
    // `off` field of the tls_dispatcher_arguments, so the next prog will start
    // to read from the next valid frame.
    kprobe_dispatcher_arguments_t *args = bpf_map_lookup_elem(&kprobe_dispatcher_arguments, &zero);
    if (args == NULL) {
        return false;
    }
    dispatcher_args_copy = *args;

    pktbuf_t pkt = pktbuf_from_kprobe(ctx, &dispatcher_args_copy);

    filter_frame(pkt, &dispatcher_args_copy, &dispatcher_args_copy.tup);
    return 0;
}


// The program is responsible for parsing all headers frames. For each headers frame we parse the headers,
// fill the dynamic table with the new interesting literal headers, and modifying the streams accordingly.
// The program can be called multiple times (via "self call" of tail calls) in case we have more frames to parse
// than the maximum number of frames we can process in a single tail call.
// The program is being called after kprobe__http2_tls_filter, and it is being called only if we have interesting frames.
// The program calls kprobe__http2_dynamic_table_cleaner to clean the dynamic table if needed.
SEC("kprobe/http2_headers_parser")
int kprobe__http2_headers_parser(struct pt_regs *ctx) {
    const __u32 zero = 0;

    kprobe_dispatcher_arguments_t dispatcher_args_copy;
    // We're not calling fetch_dispatching_arguments as, we need to modify the
    // `off` field of tls_dispatcher_arguments, so the next prog will start to
    // read from the next valid frame.
    kprobe_dispatcher_arguments_t *args = bpf_map_lookup_elem(&kprobe_dispatcher_arguments, &zero);
    if (args == NULL) {
        return false;
    }
    dispatcher_args_copy = *args;

    pktbuf_t pkt = pktbuf_from_kprobe(ctx, &dispatcher_args_copy);

    headers_parser(pkt, &dispatcher_args_copy, &dispatcher_args_copy.tup, 0);

    return 0;
}

// The program is responsible for cleaning the dynamic table.
// The program calls kprobe__http2_tls_eos_parser to finalize the streams and enqueue them to be sent to the user mode.
SEC("kprobe/http2_dynamic_table_cleaner")
int kprobe__http2_dynamic_table_cleaner(struct pt_regs *ctx) {
    const __u32 zero = 0;

    kprobe_dispatcher_arguments_t dispatcher_args_copy;
    // We're not calling fetch_dispatching_arguments as, we need to modify the `off` field of skb_info, so
    // the next prog will start to read from the next valid frame.
    kprobe_dispatcher_arguments_t *args = bpf_map_lookup_elem(&kprobe_dispatcher_arguments, &zero);
    if (args == NULL) {
        return false;
    }
    dispatcher_args_copy = *args;

    pktbuf_t pkt = pktbuf_from_kprobe(ctx, &dispatcher_args_copy);
    dynamic_table_cleaner(pkt, &dispatcher_args_copy.tup);

    return 0;
}

// The program is responsible for parsing all frames that mark the end of a stream.
// We consider a frame as marking the end of a stream if it is either:
//  - An headers or data frame with END_STREAM flag set.
//  - An RST_STREAM frame.
// The program is being called after http2_dynamic_table_cleaner, and it finalizes the streams and enqueue them
// to be sent to the user mode.
// The program is ready to be called multiple times (via "self call" of tail calls) in case we have more frames to
// process than the maximum number of frames we can process in a single tail call.
SEC("kprobe/http2_eos_parser")
int kprobe__http2_eos_parser(struct pt_regs *ctx) {
    const __u32 zero = 0;

    kprobe_dispatcher_arguments_t dispatcher_args_copy;
    // We're not calling fetch_dispatching_arguments as, we need to modify the `off` field of skb_info, so
    // the next prog will start to read from the next valid frame.
    kprobe_dispatcher_arguments_t *args = bpf_map_lookup_elem(&kprobe_dispatcher_arguments, &zero);
    if (args == NULL) {
        return false;
    }
    dispatcher_args_copy = *args;

    pktbuf_t pkt = pktbuf_from_kprobe(ctx, &dispatcher_args_copy);

    eos_parser(pkt, &dispatcher_args_copy, &dispatcher_args_copy.tup);

    return 0;
}

#endif
