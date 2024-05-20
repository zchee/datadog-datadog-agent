#ifndef BPF_CGROUP_H
#define BPF_CGROUP_H

#ifdef COMPILE_RUNTIME
#include "kconfig.h"
#include <linux/cgroup.h>
#endif

#include "bpf_helpers.h"         // for __always_inline, bpf_get_current_task, bpf_probe_read_kernel_str
#include "bpf_tracing.h"         // for ___nolast5, ___last5, ___nolast3, ___nolast4, BPF_CORE_READ, ___arrow1, ___a...
#include "ktypes.h"              // for task_struct, css_set, cgroup_subsys_state, cgroup, kernfs_node, BPF_FUNC_get...

static __always_inline int get_cgroup_name(char *buf, size_t sz) {
    if (!bpf_helper_exists(BPF_FUNC_get_current_task)) {
        return 0;
    }
    __builtin_memset(buf, 0, sz);
    struct task_struct *cur_tsk = (struct task_struct *)bpf_get_current_task();

#ifdef COMPILE_CORE
    enum cgroup_subsys_id___local {
        memory_cgrp_id___local = 123, /* value doesn't matter */
    };
    int cgrp_id = bpf_core_enum_value(enum cgroup_subsys_id___local, memory_cgrp_id___local);
#else
    int cgrp_id = memory_cgrp_id;
#endif
    const char *name = BPF_CORE_READ(cur_tsk, cgroups, subsys[cgrp_id], cgroup, kn, name);
    if (bpf_probe_read_kernel_str(buf, sz, name) < 0) {
        return 0;
    }

    return 1;
}

#endif /* defined(BPF_CGROUP_H) */
