#ifndef __KTYPES_H__
#define __KTYPES_H__

// IWYU pragma: begin_exports
#ifdef COMPILE_CORE
#include "vmlinux.h"
#include "vmlinux-defines.h"
#else
// Go type generation cannot find kconfig.h
#if defined(COMPILE_PREBUILT) || defined(COMPILE_RUNTIME)
#include "kconfig.h"
#ifndef __bpf__
#include <asm/ptrace.h> // for pt_regs
#endif
#endif
#include <linux/types.h>
#include <linux/version.h>
#endif
// IWYU pragma: end_exports

#ifndef bool
typedef _Bool bool;
#endif
#define true 1
#define false 0

#endif
