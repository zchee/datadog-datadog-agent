#ifndef TRACEPOINTS_H
#define TRACEPOINTS_H

#include "ktypes.h"
#include "bpf_tracing.h"

#ifdef COMPILE_CORE
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

// Represents the parameters being passed to several tracepoints in the net group
// BTF struct is named trace_event_raw_net_dev_template, so this must retain that prefix
struct trace_event_raw_net_dev_template___dd {
    struct trace_entry ent;
    void* skbaddr;
    unsigned int len;
};

#ifdef COMPILE_CORE
#pragma clang attribute pop
#endif

#endif
