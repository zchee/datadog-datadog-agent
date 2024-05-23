#include "kconfig.h"
#include <net/netfilter/nf_conntrack.h> // for nf_conn
#include "conntrack.h"                  // for nf_conn_to_conntrack_tuples
#include "bpf_helpers.h"                // for BPF_ANY, SEC, log_debug, bpf_get_current_pid_tgid
#include "bpf_telemetry.h"              // for bpf_map_update_with_telemetry
#include "bpf_tracing.h"                // for pt_regs, user_pt_regs, PT_REGS_PARM1, PT_REGS_PARM5
#include "conntrack/helpers.h"          // for increment_telemetry_registers_count
#include "conntrack/maps.h"             // for conntrack
#include "ktypes.h"                     // for u32

SEC("kprobe/__nf_conntrack_hash_insert")
int BPF_KPROBE(kprobe___nf_conntrack_hash_insert, struct nf_conn *ct) {
    log_debug("kprobe/__nf_conntrack_hash_insert: netns: %u", get_netns(ct));

    conntrack_tuple_t orig = {}, reply = {};
    if (nf_conn_to_conntrack_tuples(ct, &orig, &reply) != 0) {
        return 0;
    }
    RETURN_IF_NOT_NAT(&orig, &reply);

    bpf_map_update_with_telemetry(conntrack, &orig, &reply, BPF_ANY);
    bpf_map_update_with_telemetry(conntrack, &reply, &orig, BPF_ANY);
    increment_telemetry_registers_count();

    return 0;
}

SEC("kprobe/ctnetlink_fill_info")
int kprobe_ctnetlink_fill_info(struct pt_regs* ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != systemprobe_pid()) {
        log_debug("skipping kprobe/ctnetlink_fill_info invocation from non-system-probe process");
        return 0;
    }

    struct nf_conn *ct = (struct nf_conn*)PT_REGS_PARM5(ctx);

    log_debug("kprobe/ctnetlink_fill_info: netns: %u", get_netns(ct));

    conntrack_tuple_t orig = {}, reply = {};
    if (nf_conn_to_conntrack_tuples(ct, &orig, &reply) != 0) {
        return 0;
    }

    RETURN_IF_NOT_NAT(&orig, &reply);

    bpf_map_update_with_telemetry(conntrack, &orig, &reply, BPF_ANY);
    bpf_map_update_with_telemetry(conntrack, &reply, &orig, BPF_ANY);
    increment_telemetry_registers_count();

    return 0;
}

char _license[] SEC("license") = "GPL";
