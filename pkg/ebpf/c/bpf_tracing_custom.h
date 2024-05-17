#ifndef __BPF_TRACING_CUSTOM_H__
#define __BPF_TRACING_CUSTOM_H__

#if defined(bpf_target_x86)

#define __PT_PARM6_REG r9
#define PT_REGS_STACK_PARM(x,n)                                                     \
({                                                                                  \
    unsigned long p = 0;                                                            \
    bpf_probe_read_kernel(&p, sizeof(p), ((unsigned long *)x->__PT_SP_REG) + n);    \
    p;                                                                              \
})

#define PT_REGS_PARM7(x) PT_REGS_STACK_PARM(x,1)
#define PT_REGS_PARM8(x) PT_REGS_STACK_PARM(x,2)
#define PT_REGS_PARM9(x) PT_REGS_STACK_PARM(x,3)
#define PT_REGS_PARM10(x) PT_REGS_STACK_PARM(x,4)

#elif defined(bpf_target_arm64)

#define __PT_PARM6_REG regs[5]
#define PT_REGS_STACK_PARM(x,n)                                            \
({                                                                         \
    unsigned long p = 0;                                                   \
    bpf_probe_read_kernel(&p, sizeof(p), ((unsigned long *)x->sp) + n);    \
    p;                                                                     \
})

#define PT_REGS_PARM7(x) (__PT_REGS_CAST(x)->regs[6])
#define PT_REGS_PARM8(x) (__PT_REGS_CAST(x)->regs[7])
#define PT_REGS_PARM9(x) PT_REGS_STACK_PARM(__PT_REGS_CAST(x),0)
#define PT_REGS_PARM10(x) PT_REGS_STACK_PARM(__PT_REGS_CAST(x),1)
#define PT_REGS_PARM7_CORE(x) BPF_CORE_READ(__PT_REGS_CAST(x), regs[6])
#define PT_REGS_PARM8_CORE(x) BPF_CORE_READ(__PT_REGS_CAST(x), regs[7])

#endif /* defined(bpf_target_x86) */

#if defined(bpf_target_defined)

#define PT_REGS_PARM6(x) (__PT_REGS_CAST(x)->__PT_PARM6_REG)
#define PT_REGS_PARM6_CORE(x) BPF_CORE_READ(__PT_REGS_CAST(x), __PT_PARM6_REG)

#else /* defined(bpf_target_defined) */

#define PT_REGS_PARM6(x) ({ _Pragma(__BPF_TARGET_MISSING); 0l; })
#define PT_REGS_PARM7(x) ({ _Pragma(__BPF_TARGET_MISSING); 0l; })
#define PT_REGS_PARM8(x) ({ _Pragma(__BPF_TARGET_MISSING); 0l; })
#define PT_REGS_PARM9(x) ({ _Pragma(__BPF_TARGET_MISSING); 0l; })
#define PT_REGS_PARM6_CORE(x) ({ _Pragma(__BPF_TARGET_MISSING); 0l; })
#define PT_REGS_PARM7_CORE(x) ({ _Pragma(__BPF_TARGET_MISSING); 0l; })
#define PT_REGS_PARM8_CORE(x) ({ _Pragma(__BPF_TARGET_MISSING); 0l; })

#endif

#define ___bpf_kprobe_args6(x, args...) ___bpf_kprobe_args5(args), (void *)PT_REGS_PARM6(ctx)
#define ___bpf_kprobe_args7(x, args...) ___bpf_kprobe_args6(args), (void *)PT_REGS_PARM7(ctx)
#define ___bpf_kprobe_args8(x, args...) ___bpf_kprobe_args7(args), (void *)PT_REGS_PARM8(ctx)
#define ___bpf_kprobe_args9(x, args...) ___bpf_kprobe_args8(args), (void *)PT_REGS_PARM9(ctx)

#ifndef COMPILE_CORE
// TODO this will not let runtime compilation adjust to changes in this struct
struct trace_entry {
	unsigned short type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct syscall_trace_enter {
	struct trace_entry ent;
	int nr;
	unsigned long args[];
};

struct syscall_trace_exit {
	struct trace_entry ent;
	int nr;
	long ret;
};
#endif

#define ___bpf_tp_sys_enter_args_cast0()              ctx
#define ___bpf_tp_sys_enter_args_cast1(x)             ___bpf_tp_sys_enter_args_cast0(), (void *)ctx->args[0]
#define ___bpf_tp_sys_enter_args_cast2(x, tpargs...)  ___bpf_tp_sys_enter_args_cast1(tpargs), (void *)ctx->args[1]
#define ___bpf_tp_sys_enter_args_cast3(x, tpargs...)  ___bpf_tp_sys_enter_args_cast2(tpargs), (void *)ctx->args[2]
#define ___bpf_tp_sys_enter_args_cast4(x, tpargs...)  ___bpf_tp_sys_enter_args_cast3(tpargs), (void *)ctx->args[3]
#define ___bpf_tp_sys_enter_args_cast5(x, tpargs...)  ___bpf_tp_sys_enter_args_cast4(tpargs), (void *)ctx->args[4]
#define ___bpf_tp_sys_enter_args_cast6(x, tpargs...)  ___bpf_tp_sys_enter_args_cast5(tpargs), (void *)ctx->args[5]
#define ___bpf_tp_sys_enter_args_cast(tpargs...)      ___bpf_apply(___bpf_tp_sys_enter_args_cast, ___bpf_narg(tpargs))(tpargs)

#define BPF_TP_SYSCALL_ENTER(name, args...)						    \
name(struct syscall_trace_enter *ctx);						    \
static __always_inline typeof(name(0))					    \
____##name(struct syscall_trace_enter *ctx, ##args);				    \
typeof(name(0)) name(struct syscall_trace_enter *ctx)				    \
{									    \
    _Pragma("GCC diagnostic push")					    \
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")		    \
	return ____##name(___bpf_tp_sys_enter_args_cast(args));			    \
	_Pragma("GCC diagnostic pop")					    \
}									    \
static __always_inline typeof(name(0))					    \
____##name(struct syscall_trace_enter *ctx, ##args)



#define ___bpf_tp_sys_exit_args_cast0()            ctx
#define ___bpf_tp_sys_exit_args_cast1(x)           ___bpf_tp_sys_exit_args_cast0(), (void *)ctx->ret
#define ___bpf_tp_sys_exit_args_cast(args...)      ___bpf_apply(___bpf_tp_sys_exit_args_cast, ___bpf_narg(args))(args)

#define BPF_TP_SYSCALL_EXIT(name, args...)						    \
name(struct syscall_trace_exit *ctx);						    \
static __always_inline typeof(name(0))					    \
____##name(struct syscall_trace_exit *ctx, ##args);				    \
typeof(name(0)) name(struct syscall_trace_exit *ctx)				    \
{									    \
    _Pragma("GCC diagnostic push")					    \
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")		    \
	return ____##name(___bpf_tp_sys_exit_args_cast(args));			    \
	_Pragma("GCC diagnostic pop")					    \
}									    \
static __always_inline typeof(name(0))					    \
____##name(struct syscall_trace_exit *ctx, ##args)

#endif
