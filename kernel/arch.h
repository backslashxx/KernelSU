#ifndef __KSU_H_ARCH
#define __KSU_H_ARCH

#include <linux/version.h>

#if defined(__aarch64__)

#define __PT_PARM1_REG regs[0]
#define __PT_PARM2_REG regs[1]
#define __PT_PARM3_REG regs[2]
#define __PT_SYSCALL_PARM4_REG regs[3]
#define __PT_CCALL_PARM4_REG regs[3]
#define __PT_PARM5_REG regs[4]
#define __PT_PARM6_REG regs[5]
#define __PT_RET_REG regs[30]
#define __PT_FP_REG regs[29] /* Works only with CONFIG_FRAME_POINTER */
#define __PT_RC_REG regs[0]
#define __PT_SP_REG sp
#define __PT_IP_REG pc

#elif defined(__arm__)

// https://elixir.bootlin.com/linux/v6.17-rc6/source/tools/lib/bpf/bpf_tracing.h
#define __PT_PARM1_REG uregs[0]
#define __PT_PARM2_REG uregs[1]
#define __PT_PARM3_REG uregs[2]
#define __PT_PARM4_REG uregs[3]

// seems to work atleast on 3.0 on samsung galaxy s3
// nfi what im doing
#define __PT_SYSCALL_PARM4_REG uregs[3] 
#define __PT_CCALL_PARM4_REG uregs[3]

#define __PT_PARM1_SYSCALL_REG __PT_PARM1_REG
#define __PT_PARM2_SYSCALL_REG __PT_PARM2_REG
#define __PT_PARM3_SYSCALL_REG __PT_PARM3_REG
#define __PT_PARM4_SYSCALL_REG __PT_PARM4_REG
#define __PT_PARM5_SYSCALL_REG uregs[4]
#define __PT_PARM6_SYSCALL_REG uregs[5]
#define __PT_PARM7_SYSCALL_REG uregs[6]

#define __PT_RET_REG uregs[14]
#define __PT_FP_REG uregs[11]	/* Works only with CONFIG_FRAME_POINTER */
#define __PT_RC_REG uregs[0]
#define __PT_SP_REG uregs[13]
#define __PT_IP_REG uregs[12]

#elif defined(__x86_64__)

#define __PT_PARM1_REG di
#define __PT_PARM2_REG si
#define __PT_PARM3_REG dx
/* syscall uses r10 for PARM4 */
#define __PT_SYSCALL_PARM4_REG r10
#define __PT_CCALL_PARM4_REG cx
#define __PT_PARM5_REG r8
#define __PT_PARM6_REG r9
#define __PT_RET_REG sp
#define __PT_FP_REG bp
#define __PT_RC_REG ax
#define __PT_SP_REG sp
#define __PT_IP_REG ip

#else
#error "Unsupported arch"
#endif

/* allow some architecutres to override `struct pt_regs` */
#ifndef __PT_REGS_CAST
#define __PT_REGS_CAST(x) (x)
#endif

#define PT_REGS_PARM1(x) (__PT_REGS_CAST(x)->__PT_PARM1_REG)
#define PT_REGS_PARM2(x) (__PT_REGS_CAST(x)->__PT_PARM2_REG)
#define PT_REGS_PARM3(x) (__PT_REGS_CAST(x)->__PT_PARM3_REG)
#define PT_REGS_SYSCALL_PARM4(x) (__PT_REGS_CAST(x)->__PT_SYSCALL_PARM4_REG)
#define PT_REGS_CCALL_PARM4(x) (__PT_REGS_CAST(x)->__PT_CCALL_PARM4_REG)
#define PT_REGS_PARM5(x) (__PT_REGS_CAST(x)->__PT_PARM5_REG)
#define PT_REGS_PARM6(x) (__PT_REGS_CAST(x)->__PT_PARM6_REG)
#define PT_REGS_RET(x) (__PT_REGS_CAST(x)->__PT_RET_REG)
#define PT_REGS_FP(x) (__PT_REGS_CAST(x)->__PT_FP_REG)
#define PT_REGS_RC(x) (__PT_REGS_CAST(x)->__PT_RC_REG)
#define PT_REGS_SP(x) (__PT_REGS_CAST(x)->__PT_SP_REG)
#define PT_REGS_IP(x) (__PT_REGS_CAST(x)->__PT_IP_REG)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
#define PT_REAL_REGS(regs) ((struct pt_regs *)PT_REGS_PARM1(regs))
#else
#define PT_REAL_REGS(regs) ((regs))
#endif

#endif
