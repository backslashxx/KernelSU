// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 \xx
 *
 * This file is a downstream extension and NOT affiliated, endorsed by,
 * or maintained by the official KernelSU developers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef __KSU_H_KERNEL_INCLUDES
#define __KSU_H_KERNEL_INCLUDES

// gcc -std=gnu23 -dM -E -x c /dev/null
// NOTE: gcc14 uses 202000L on -std=gnu23
#if (defined(__clang__) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L) || \
	(!defined(__clang__) && (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202000L))
#define KSU_HAS_C23
#endif

#ifdef KSU_HAS_C23
#define bool  __ksu_bool
#define false __ksu_false
#define true  __ksu_true
#include <linux/types.h>
#include <linux/stddef.h>
#undef false
#undef true
#undef bool
#endif // KSU_HAS_C23

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
#include <linux/cache.h>
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
#include <linux/jump_label.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/kref.h>
#include <linux/kthread.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/lockdep.h>
#include <linux/lsm_audit.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/poll.h>
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
#include <linux/hex.h>
#endif

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
#include <linux/overflow.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <linux/compiler_types.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
#include <uapi/linux/eventpoll.h>
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
#include <linux/hashtable.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
#include <linux/task_work.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
#include <linux/lsm_hooks.h>
#endif

#ifdef CONFIG_KPROBES
#include <linux/kprobes.h>
#endif

#ifndef __ro_after_init
#define __ro_after_init
#endif

#ifndef __nocfi
#define __nocfi
#endif

/**
 * Linux kernel forbids c99 restrict
 * however we can use builtin's restrict
 */
#define restrict __restrict

/**
 * emulate-able C23 features, should be fine on GNU11 compilers
 *
 */
#if !defined(KSU_HAS_C23)
#define nullptr ((void *)0)
typedef typeof(nullptr) nullptr_t;
#define constexpr const
#define auto __auto_type
#define alignas _Alignas
#define alignof _Alignof
#endif // KSU_HAS_C23

// NOTE: clang < 19 has issues on constexpr even with -std=gnu23
#if defined (KSU_HAS_C23) && defined(__clang__) && (__clang_major__ < 19)
#define constexpr const
#endif

/**
 * old compilers does NOT know fallthrough, this is GNU/C23
 * however we can use a comment and it silences it
 * ref: https://elixir.bootlin.com/linux/v4.4.302/source/tools/include/linux/compiler.h#L121
 */
#ifndef fallthrough
# if defined(__GNUC__) && __GNUC__ >= 7
#  define fallthrough __attribute__ ((fallthrough))
# else
#  define fallthrough do {} while (0) /* fallthrough */
# endif
#endif

/**
 * static_assert is C23
 * this has an alternative available on C11 capable compilers.
 * ref: https://elixir.bootlin.com/linux/v5.1/source/include/linux/build_bug.h
 *
 * static_assert(condition); - condition becomes the comment
 * static_assert(condition, "comment");
 */
#ifndef static_assert
#define __static_assert(expr, msg, ...) _Static_assert(expr, msg)
#define static_assert(expr, ...) __static_assert(expr, ##__VA_ARGS__, #expr)
#endif

/**
 * we do NOT have memset_explicit on the linux kernel
 *
 * from: OPENSSL_cleanse, volatile function pointer prevents memset optimization
 * https://github.com/openssl/openssl/blob/master/crypto/mem_clr.c
 * 
 */
static __nocfi __always_inline void *memset_explicit(void *s, int c, size_t count)
{
	static typeof(memset) *volatile memset_fnptr = memset;
	return memset_fnptr(s, c, count);
}

/**
 * __attribute__((__cleanup__()))
 * - pseudo-raii / defer / scoped cleanup on C 
 *
 * NOTE: passes address of variable attributed to fn()
 */
#ifndef __cleanup
#define __cleanup(fn) __attribute__((__cleanup__(fn)))
#endif

// dummy variable generator
#define __ksu_concat(a, b) a##b
#define __ksu_generate_dummy(a, b) __ksu_concat(a, b)
#define __ksu_dummy_var __ksu_generate_dummy(_ksu_dummy_, __COUNTER__)

// scoped lock, mutex
static inline void mutex_unlock_byref(struct mutex **m) { mutex_unlock(*m); }
#define deferred_mutex_unlock(lock) struct mutex *__ksu_dummy_var __cleanup(mutex_unlock_byref) = (lock)
#define guarded_mutex_lock(lock) ({ mutex_lock(lock); deferred_mutex_unlock(lock); 1; })

// scoped lock, spinlock
static inline void spin_unlock_byref(spinlock_t **lock) { spin_unlock(*lock); }
#define deferred_spin_unlock(lock) spinlock_t *__ksu_dummy_var __cleanup(spin_unlock_byref) = (lock)
#define guarded_spin_lock(lock) ({ spin_lock(lock); deferred_spin_unlock(lock); 1; })

// basic stack offload.
static inline void kfree_byref(void *buf) { kfree(*(void **)buf); }
#define __offstack(size) __cleanup(kfree_byref) = kmalloc(size, GFP_KERNEL)
#define __zoffstack(size) __cleanup(kfree_byref) = kzalloc(size, GFP_KERNEL)

/**
 * uint128_t / int128_t
 *
 * - nonstandard, we can use _BitInt(x) but it needs C23
 * - this exists as an extension on gcc and clang
 * - can be used with atomics on arm64 via ldxp+stxp or LSE / LSE2, no neon entry required.
 *
 */
#if defined(CONFIG_64BIT) && defined(__SIZEOF_INT128__) && (__SIZEOF_INT128__ == 16)
#define KSU_HAS_INT128
typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;
#define make128const(hi,lo) ((((int128_t)hi << 64) | lo))
#endif

// check for guaranteed inline routines
// if unavailable, use plain builtin
#ifndef __has_builtin
#define __has_builtin(x) (0)
#endif

// memcpy_inline IR generation tends to fail on older clang
#if __has_builtin(__builtin_memcpy_inline) && defined(__clang__) && (__clang_major__ >= 17)
#define memcpy_inline	__builtin_memcpy_inline
#else
#define memcpy_inline(to, from, sz) ({			\
	static_assert(__builtin_constant_p(sz));	\
	__builtin_memcpy((to), (from), (sz));		\
})
#endif

// memset_inline IR generation tends to fail on older clang
#if __has_builtin(__builtin_memset_inline) && defined(__clang__) && (__clang_major__ >= 17)
#define memset_inline	__builtin_memset_inline
#else
#define memset_inline(dst, val, sz) ({			\
	static_assert(__builtin_constant_p(sz));	\
	__builtin_memset((dst), (val), (sz));		\
})
#endif

/**
 * replace common mem/str functions with builtins
 * so legacy kernels get better inlining and optimized routines (with newer compielrs)
 * a lot of people rice their flags (mcpu/march), this'll be a good reward for them.
 * minimum that people use is gcc 4.9 for 3.x kernels, so these are fineee
 * https://github.com/gcc-mirror/gcc/blob/releases/gcc-4.9/gcc/builtins.def#L562
 *
 */
#if !defined(CONFIG_KSU_DEBUG)
#define memchr		__builtin_memchr
#define memcmp		__builtin_memcmp
#define memcpy		__builtin_memcpy
#define memmove		__builtin_memmove
#define memset		__builtin_memset
#define strcasecmp	__builtin_strcasecmp
#define strcat		__builtin_strcat
#define strchr		__builtin_strchr
#define strcmp		__builtin_strcmp
#define strcpy		__builtin_strcpy
#define strcspn		__builtin_strcspn
#define strlen		__builtin_strlen
#define strncasecmp	__builtin_strncasecmp
#define strncat		__builtin_strncat
#define strncmp		__builtin_strncmp
#define strncpy		__builtin_strncpy
#define strpbrk		__builtin_strpbrk
#define strrchr		__builtin_strrchr
#define strspn		__builtin_strspn
#define strstr		__builtin_strstr
#endif // !CONFIG_KSU_DEBUG

/**
 * redirect all dmesg/printk logging messages to kernel's no_printk macro.
 * this is an option offerred to shut up KernelSU's routine logging.
 *
 */
#if defined(CONFIG_KSU_NOPRINTK) && !defined(CONFIG_KSU_DEBUG)
#define pr_emerg(fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#define pr_alert(fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#define pr_crit(fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#define pr_notice(fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#define pr_devel(fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#define printk(fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#endif // CONFIG_KSU_NOPRINTK && !CONFIG_KSU_DEBUG

#endif // __KSU_H_KERNEL_INCLUDES
