#ifndef __KSU_H_KERNEL_INCLUDES
#define __KSU_H_KERNEL_INCLUDES

// common
#include <asm/current.h>
#include <asm/syscall.h>
#include <crypto/hash.h>
#include <generated/compile.h>
#include <generated/utsrelease.h>
#include <linux/aio.h>
#include <linux/anon_inodes.h>
#include <linux/atomic.h>
#include <linux/binfmts.h>
#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/input.h>
#include <linux/ioctl.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/kthread.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/lsm_audit.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/thread_info.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/uio.h>
#include <linux/utsname.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

// versioned / conditional

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#include <linux/stop_machine.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#include <uapi/linux/mount.h>
#else
#include <uapi/linux/fs.h>
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
#include <linux/input-event-codes.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#include <uapi/linux/input.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#include <uapi/asm-generic/errno.h>
#else
#include <asm-generic/errno.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#include <crypto/sha2.h>
#else
#include <crypto/sha.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <linux/compiler_types.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#include <uapi/linux/sched/types.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/sched/user.h>
#endif

#endif // __KSU_H_KERNEL_INCLUDES
