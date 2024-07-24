#include "ktypes.h"
#include "bpf_metadata.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "bpf_builtins.h"
#include "map-defs.h"
#include "softirq.h"
#include "compiler.h"

#define NET_RX_SOFTIRQ 3

BPF_PERCPU_ARRAY_MAP(packets_per_irq, ppirq_t, 1);

#define log_and_ret_err(err)                                        \
{                                                                   \
    log_debug("[%s] [%d] err: %d", __FUNCTION__, __LINE__, err);    \
    return 0;                                                       \
}

static volatile const u64 softnet_stats_pcpu = 0;
static volatile const u64 __per_cpu_offset = 0;

static __always_inline u64 per_cpu_ptr(u64 ptr, u64 cpu) {
    u64 cpu_per_cpu_region;
    int err;

    err = bpf_core_read(&cpu_per_cpu_region, sizeof(u64), __per_cpu_offset + (cpu * 8));
    if (err < 0)
        return 0;

    return ptr + cpu_per_cpu_region;
}

static __always_inline int get_packets_processed() {
    struct softnet_data* softnet_stats;
    int processed;

    softnet_stats = (struct softnet_data *)per_cpu_ptr(softnet_stats_pcpu, bpf_get_smp_processor_id());
    if (softnet_stats == NULL)
        return -1;

    int err = bpf_core_read(&processed, sizeof(int), &softnet_stats->processed);
    if (err < 0)
        return err;

    return processed;
}

SEC("raw_tracepoint/irq/softirq_entry")
int BPF_PROG(raw_tracepoint__irq__softirq_entry, unsigned int vec) {
    int processed;
    ppirq_t* stats;

    if (vec != NET_RX_SOFTIRQ)
        return 0;

    u64 key = 0;
    stats = bpf_map_lookup_elem(&packets_per_irq, &key);
    if (stats == NULL)
        log_and_ret_err(-1);

    if (stats->entry_packets_count != 0)
        log_and_ret_err(-1);

    processed = get_packets_processed();
    if (processed < 0)
        log_and_ret_err((int)processed);

    stats->entry_packets_count = processed;

    return 0;
}

SEC("raw_tracepoint/irq/softirq_exit")
int BPF_PROG(raw_tracepoint__irq__softirq_exit, unsigned int vec) {
    int processed;
    ppirq_t *stats;

    if (vec != NET_RX_SOFTIRQ)
        return 0;

    u64 key = 0;
    stats = bpf_map_lookup_elem(&packets_per_irq, &key);
    if (stats == NULL)
        log_and_ret_err(-1);

    processed = get_packets_processed();
    if (processed < 0)
        log_and_ret_err(processed);

    if (stats->entry_packets_count == 0)
        return 0;

    if ((processed - stats->entry_packets_count) > stats->max_packets_processed) {
        stats->max_packets_processed += (processed - stats->entry_packets_count);
    }
    stats->entry_packets_count = 0;

    return 0;
}

char _license[] SEC("license") = "GPL";
