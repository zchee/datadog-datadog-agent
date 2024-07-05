#ifndef _CONSTANTS_FENTRY_MACRO_H_
#define _CONSTANTS_FENTRY_MACRO_H_

#ifdef USE_FENTRY

typedef unsigned long long ctx_t;

#define HOOK_ENTRY(func_name) SEC("fentry/" func_name)
#define HOOK_EXIT(func_name) SEC("fexit/" func_name)
#define HOOK_SYSCALL_ENTRY0(name, ...) SYSCALL_FENTRY0(name, __VA_ARGS__)
#define HOOK_SYSCALL_ENTRY1(name, ...) SYSCALL_FENTRY1(name, __VA_ARGS__)
#define HOOK_SYSCALL_ENTRY2(name, ...) SYSCALL_FENTRY2(name, __VA_ARGS__)
#define HOOK_SYSCALL_ENTRY3(name, ...) SYSCALL_FENTRY3(name, __VA_ARGS__)
#define HOOK_SYSCALL_ENTRY4(name, ...) SYSCALL_FENTRY4(name, __VA_ARGS__)
#define HOOK_SYSCALL_ENTRY5(name, ...) SYSCALL_FENTRY5(name, __VA_ARGS__)
#define HOOK_SYSCALL_ENTRY6(name, ...) SYSCALL_FENTRY6(name, __VA_ARGS__)
#define HOOK_SYSCALL_COMPAT_ENTRY0(name, ...) SYSCALL_FENTRY0(name, __VA_ARGS__)
#define HOOK_SYSCALL_COMPAT_ENTRY1(name, ...) SYSCALL_FENTRY1(name, __VA_ARGS__)
#define HOOK_SYSCALL_COMPAT_ENTRY2(name, ...) SYSCALL_FENTRY2(name, __VA_ARGS__)
#define HOOK_SYSCALL_COMPAT_ENTRY3(name, ...) SYSCALL_FENTRY3(name, __VA_ARGS__)
#define HOOK_SYSCALL_COMPAT_ENTRY4(name, ...) SYSCALL_FENTRY4(name, __VA_ARGS__)
#define HOOK_SYSCALL_COMPAT_TIME_ENTRY0(name, ...) SYSCALL_TIME_FENTRY0(name, __VA_ARGS__)
#define HOOK_SYSCALL_COMPAT_TIME_ENTRY1(name, ...) SYSCALL_TIME_FENTRY1(name, __VA_ARGS__)
#define HOOK_SYSCALL_COMPAT_TIME_ENTRY2(name, ...) SYSCALL_TIME_FENTRY2(name, __VA_ARGS__)
#define HOOK_SYSCALL_EXIT(name) SYSCALL_FEXIT(name)
#define HOOK_SYSCALL_COMPAT_EXIT(name) SYSCALL_FEXIT(name)
#define HOOK_SYSCALL_COMPAT_TIME_EXIT(name) SYSCALL_TIME_FEXIT(name)
#define TAIL_CALL_TARGET(_name) SEC("fentry/start_kernel") // `start_kernel` is only used at boot time, the hook should never be hit

#define CTX_PARM1(ctx) (u64)(ctx[0])
#define CTX_PARM2(ctx) (u64)(ctx[1])
#define CTX_PARM3(ctx) (u64)(ctx[2])
#define CTX_PARM4(ctx) (u64)(ctx[3])
#define CTX_PARM5(ctx) (u64)(ctx[4])

#define CTX_PARMRET(ctx, argc) (u64)(ctx[argc])
#define SYSCALL_PARMRET(ctx) CTX_PARMRET(ctx, 1)

#if defined(bpf_target_x86)
#define SYSCALL_NR(ctx) SYSCALL_PARMRET(ctx)
#elif defined(bpf_target_arm64)
#define SYSCALL_NR(ctx) (u64)(ctx[8])
#endif /* defined(bpf_target_x86) */

#else

typedef struct pt_regs ctx_t;

#define HOOK_ENTRY(func_name) SEC("kprobe/" func_name)
#define HOOK_EXIT(func_name) SEC("kretprobe/" func_name)
#define HOOK_SYSCALL_ENTRY0(name, ...) SYSCALL_KPROBE0(name, __VA_ARGS__)
#define HOOK_SYSCALL_ENTRY1(name, ...) SYSCALL_KPROBE1(name, __VA_ARGS__)
#define HOOK_SYSCALL_ENTRY2(name, ...) SYSCALL_KPROBE2(name, __VA_ARGS__)
#define HOOK_SYSCALL_ENTRY3(name, ...) SYSCALL_KPROBE3(name, __VA_ARGS__)
#define HOOK_SYSCALL_ENTRY4(name, ...) SYSCALL_KPROBE4(name, __VA_ARGS__)
#define HOOK_SYSCALL_ENTRY5(name, ...) SYSCALL_KPROBE5(name, __VA_ARGS__)
#define HOOK_SYSCALL_ENTRY6(name, ...) SYSCALL_KPROBE6(name, __VA_ARGS__)
#define HOOK_SYSCALL_COMPAT_ENTRY0(name, ...) SYSCALL_COMPAT_KPROBE0(name, __VA_ARGS__)
#define HOOK_SYSCALL_COMPAT_ENTRY1(name, ...) SYSCALL_COMPAT_KPROBE1(name, __VA_ARGS__)
#define HOOK_SYSCALL_COMPAT_ENTRY2(name, ...) SYSCALL_COMPAT_KPROBE2(name, __VA_ARGS__)
#define HOOK_SYSCALL_COMPAT_ENTRY3(name, ...) SYSCALL_COMPAT_KPROBE3(name, __VA_ARGS__)
#define HOOK_SYSCALL_COMPAT_ENTRY4(name, ...) SYSCALL_COMPAT_KPROBE4(name, __VA_ARGS__)
#define HOOK_SYSCALL_COMPAT_TIME_ENTRY0(name, ...) SYSCALL_COMPAT_TIME_KPROBE0(name, __VA_ARGS__)
#define HOOK_SYSCALL_COMPAT_TIME_ENTRY1(name, ...) SYSCALL_COMPAT_TIME_KPROBE1(name, __VA_ARGS__)
#define HOOK_SYSCALL_COMPAT_TIME_ENTRY2(name, ...) SYSCALL_COMPAT_TIME_KPROBE2(name, __VA_ARGS__)
#define HOOK_SYSCALL_EXIT(name) SYSCALL_KRETPROBE(name)
#define HOOK_SYSCALL_COMPAT_EXIT(name) SYSCALL_COMPAT_KRETPROBE(name)
#define HOOK_SYSCALL_COMPAT_TIME_EXIT(name) SYSCALL_COMPAT_TIME_KRETPROBE(name)
#define TAIL_CALL_TARGET(name) SEC("kprobe/" name)

#define CTX_PARM1(ctx) PT_REGS_PARM1(ctx)
#define CTX_PARM2(ctx) PT_REGS_PARM2(ctx)
#define CTX_PARM3(ctx) PT_REGS_PARM3(ctx)
#define CTX_PARM4(ctx) PT_REGS_PARM4(ctx)
#define CTX_PARM5(ctx) PT_REGS_PARM5(ctx)

#define CTX_PARMRET(ctx, _argc) PT_REGS_RC(ctx)
#define SYSCALL_PARMRET(ctx) CTX_PARMRET(ctx, _)
#define SYSCALL_NR(ctx) PT_REGS_SYSCALL_NR(ctx)

#endif

#endif
