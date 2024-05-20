#ifndef __COOKIE_H__
#define __COOKIE_H__

#ifndef COMPILE_CORE
#include <net/sock.h>       // for sock
#endif

#include "bpf_helpers.h"    // for KERNEL_VERSION, __always_inline, bpf_ktime_get_ns
#include "bpf_telemetry.h"  // for FN_INDX_bpf_probe_read_kernel, bpf_probe_read_kernel_with_telemetry
#include "ktypes.h"         // for __u64, u32, sock

static __always_inline u32 get_sk_cookie(struct sock *sk) {
#if defined(COMPILE_RUNTIME) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
    return bpf_get_prandom_u32();
#else
    __u64 t = bpf_ktime_get_ns();
    __u64 _sk = 0;
    bpf_probe_read_kernel_with_telemetry(&_sk, sizeof(_sk), &sk);
    return (u32)(_sk ^ t);
#endif
}

#endif // __COOKIE_H__
