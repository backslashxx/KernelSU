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

#ifndef CONFIG_ARM64
#error "only meant for ARM64!"
#endif

/**
 *  NOTE: theres no way to hijack sys_reboot and sys_newfstat cleanly.
 *
 *  tested to work on:
 *	- 3.10 ~ 4.14 (partially, no do_faccessat)
 *	- 4.19 ~ 6.12 GKI
 *
 *  Changelog:
 *	- init, 260524
 *	- partial/probably-broken 4.19/5.4 compat, 260525
 *	- fixups for 4.19 ~ 6.6 CFI, resolve symbols via kprobe. (260630)
 *	- optimize ksu_vfs_statx (260630)
 *	- wire up basic pre-4.17 support, however do_faccessat is still needed (260722)
 *	- also patch our hooksite, removes blr overhead compared to function pointers (260725)
 *	- smaller stub code (260728)
 *	- smaller stub code p.2, gcc fix, thx to lh_mouse @ #gcc (260728)
 *
 */

// we can get smaller stub code, 1 insn (trap)
// https://godbolt.org/z/hzTW3WznM
#define KEEP_SYMBOL asmlinkage noinline
#define DEFINE_ASM_STUB(name) 			\
__asm__ (					\
	"\n .text"				\
	"\n .p2align 2"				\
	"\n .global "#name" "			\
	"\n "#name":"				\
	"\n brk #1"				\
);					

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0) || defined(KSU_HAS_FACCESSAT2)
DEFINE_ASM_STUB(ksu_do_faccessat_fn);
KEEP_SYMBOL long ksu_do_faccessat_fn(int dfd, const char __user *filename, int mode, int flags);
KEEP_SYMBOL long ksu_do_faccessat(int dfd, const char __user *filename, int mode, int flags)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return ksu_do_faccessat_fn(dfd, filename, mode, flags);
}
#else
DEFINE_ASM_STUB(ksu_do_faccessat_fn);
KEEP_SYMBOL long ksu_do_faccessat_fn(int dfd, const char __user *filename, int mode);
KEEP_SYMBOL long ksu_do_faccessat(int dfd, const char __user *filename, int mode)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return ksu_do_faccessat_fn(dfd, filename, mode);
}
#endif // 5.7+ || faccessat2

// vfs_statx, vfs_fstatat
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0) // on most kernels vfs_fstatat calls gets inlined, so look for vfs_statx instead
DEFINE_ASM_STUB(ksu_vfs_statx_fn);
KEEP_SYMBOL int ksu_vfs_statx_fn(int dfd, struct filename *filename, int flags, struct kstat *stat, u32 request_mask);
KEEP_SYMBOL int ksu_vfs_statx(int dfd, struct filename *filename, int flags, struct kstat *stat, u32 request_mask)
{
	if (IS_ERR(filename))
		goto orig_fn;

	char *filename_ptr = (char *)filename->name;
	if (!is_su_allowed((const void **)&filename_ptr))
		goto orig_fn;

	// see sucompat.c
	const char su[16] = SU_PATH;
	uint64_t *su_p = (uint64_t *)su;
	uint64_t *fn_p = (uint64_t *)filename_ptr;

	if (likely((fn_p[1] & 0x00FFFFFFFFFFFFFFULL) != (su_p[1] & 0x00FFFFFFFFFFFFFFULL)))
		goto orig_fn;

	if (unlikely(fn_p[0] != su_p[0]))
		goto orig_fn;
	
	pr_info("vfs_statx su->sh\n");
	__builtin_memcpy(filename_ptr, SH_PATH, sizeof(SH_PATH));

orig_fn:
	return ksu_vfs_statx_fn(dfd, filename, flags, stat, request_mask);
}
#else
DEFINE_ASM_STUB(ksu_vfs_statx_fn);
KEEP_SYMBOL int ksu_vfs_statx_fn(int dfd, const char __user *filename, int flags, struct kstat *stat, u32 request_mask);
KEEP_SYMBOL int ksu_vfs_statx(int dfd, const char __user *filename, int flags, struct kstat *stat, u32 request_mask)
{
	ksu_handle_stat(&dfd, &filename, &flags);
	return ksu_vfs_statx_fn(dfd, filename, flags, stat, request_mask);
}
#endif // >= 5.18

DEFINE_ASM_STUB(ksu_vfs_fstatat_fn);
KEEP_SYMBOL int ksu_vfs_fstatat_fn(int dfd, const char __user *filename, struct kstat *stat, int flags);
KEEP_SYMBOL int ksu_vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat, int flags)
{
	ksu_handle_stat(&dfd, &filename, &flags);
	return ksu_vfs_fstatat_fn(dfd, filename, stat, flags);
}

// execve
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
DEFINE_ASM_STUB(ksu_do_execveat_common_fn);
KEEP_SYMBOL int ksu_do_execveat_common_fn(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags);
KEEP_SYMBOL int ksu_do_execveat_common(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags)
{
	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
	return ksu_do_execveat_common_fn(fd, filename, argv, envp, flags);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
DEFINE_ASM_STUB(ksu_do_execve_file_fn);
KEEP_SYMBOL int ksu_do_execve_file_fn(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags, struct file *file);
KEEP_SYMBOL int ksu_do_execve_file(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags, struct file *file)
{
	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
	return ksu_do_execve_file_fn(fd, filename, argv, envp, flags, file);
}
#endif // < 5.9

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
DEFINE_ASM_STUB(ksu_do_execve_common_fn);
KEEP_SYMBOL int ksu_do_execve_common_fn(struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp);
KEEP_SYMBOL int ksu_do_execve_common(struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp)
{
	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
	return ksu_do_execve_common_fn(filename, argv, envp);
}
#endif // < 3.19

DEFINE_ASM_STUB(ksu_do_execve_fn);
KEEP_SYMBOL int ksu_do_execve_fn(struct filename *filename, const char __user *const __user *__argv, const char __user *const __user *__envp);
KEEP_SYMBOL int ksu_do_execve(struct filename *filename, const char __user *const __user *__argv, const char __user *const __user *__envp)
{
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct user_arg_ptr envp = { .ptr.native = __envp };

	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
	return ksu_do_execve_fn(filename, __argv, __envp);
}

#ifdef CONFIG_COMPAT
DEFINE_ASM_STUB(ksu_compat_do_execve_fn);
KEEP_SYMBOL int ksu_compat_do_execve_fn(struct filename *filename, const compat_uptr_t __user *__argv, const compat_uptr_t __user *__envp);
KEEP_SYMBOL int ksu_compat_do_execve(struct filename *filename, const compat_uptr_t __user *__argv, const compat_uptr_t __user *__envp)
{
	struct user_arg_ptr argv = { .is_compat = true, .ptr.compat = __argv, };
	struct user_arg_ptr envp = { .is_compat = true, .ptr.compat = __envp, };

	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
	return ksu_compat_do_execve_fn(filename, __argv, __envp);
}
#endif

#else /* < 3.14 */

DEFINE_ASM_STUB(ksu_do_execve_common_fn);
KEEP_SYMBOL int ksu_do_execve_common_fn(const char *filename, struct user_arg_ptr argv, struct user_arg_ptr envp);
KEEP_SYMBOL int ksu_do_execve_common(const char *filename, struct user_arg_ptr argv, struct user_arg_ptr envp)
{
	ksu_legacy_execve_sucompat(&filename, &argv, &envp);
	return ksu_do_execve_common_fn(filename, argv, envp);
}
#endif

#undef KEEP_SYMBOL
#undef DEFINE_ASM_STUB

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
#define syscall_lookup(name) kallsyms_lookup_retry("__arm64_" name)
#else
#define syscall_lookup(name) kallsyms_lookup_retry(name)
#endif

#ifdef CONFIG_MODULES
#define kernel_function_lookup(name) kallsyms_lookup_retry(#name)
#else
#define kernel_function_lookup(name) (uintptr_t)&name
#endif

static int bl_hook_faccessat(void *data)
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t symbol_addr;

	target_callsite = syscall_lookup("sys_faccessat");
	symbol_addr = kallsyms_lookup_retry("do_faccessat");
	if (!symbol_addr)
		return -ENOENT;

	// patch our hook handler first
	ret = arm64_b_or_bl_patch(kernel_function_lookup(ksu_do_faccessat), 256 * sizeof(void *), kernel_function_lookup(ksu_do_faccessat_fn), symbol_addr);
	pr_info("patch_hook: ksu_do_faccessat->ksu_do_faccessat_fn ret: %d \n", ret);
	if (ret)
		return ret;

	ret = arm64_b_or_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_faccessat);
	pr_info("hook_site: sys_faccessat->do_faccessat ret: %d \n", ret);
	if (!ret)
		goto unhook_sct;

	return ret;

unhook_sct:
	restore_syscall((void *)&aarch64_faccessat, __AARCH64_faccessat, (void *)hook_aarch64_faccessat, (void *)sys_call_table);
#if defined(CONFIG_COMPAT)
	restore_syscall((void *)&armeabi_faccessat, __ARMEABI_faccessat, (void *)hook_armeabi_faccessat, (void *)compat_sys_call_table);
#endif
	return ret;
}

static int bl_hook_newfstatat(void *data)
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t symbol_addr;

	target_callsite = syscall_lookup("sys_newfstatat");
	symbol_addr = kallsyms_lookup_retry("vfs_statx");
	if (!symbol_addr)
		goto hook2;

	// patch our hook handler first
	ret = arm64_b_or_bl_patch(kernel_function_lookup(ksu_vfs_statx), 256 * sizeof(void *), kernel_function_lookup(ksu_vfs_statx_fn), symbol_addr);
	pr_info("patch_hook: ksu_vfs_statx->ksu_vfs_statx_fn ret: %d \n", ret);
	if (ret)
		return ret;

	ret = arm64_b_or_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_statx);
	pr_info("hook_site: sys_newfstatat->vfs_statx ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_native;

hook2:
	symbol_addr = kallsyms_lookup_retry("vfs_fstatat");
	if (!symbol_addr)
		return -ENOENT;

	// patch our hook handler first
	ret = arm64_b_or_bl_patch(kernel_function_lookup(ksu_vfs_fstatat), 256 * sizeof(void *), kernel_function_lookup(ksu_vfs_fstatat_fn), symbol_addr);
	pr_info("patch_hook: ksu_vfs_fstatat->ksu_vfs_fstatat_fn ret: %d \n", ret);
	if (ret)
		return ret;

	ret = arm64_b_or_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_fstatat);
	pr_info("hook_site: sys_newfstatat->vfs_fstatat ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_native;

	return ret;

unhook_sct_native:
	restore_syscall((void *)&aarch64_newfstatat, __AARCH64_newfstatat, (void *)hook_aarch64_newfstatat, (void *)sys_call_table);

#ifdef CONFIG_COMPAT
	target_callsite = syscall_lookup("sys_fstatat64");
	symbol_addr = kallsyms_lookup_retry("vfs_statx");
	if (!symbol_addr)
		goto hook2c;

	ret = arm64_b_or_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_statx);
	pr_info("hook_site: sys_fstatat64->vfs_statx ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_compat;

hook2c:
	symbol_addr = kallsyms_lookup_retry("vfs_fstatat");
	if (!symbol_addr)
		return -ENOENT;

	ret = arm64_b_or_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_fstatat);
	pr_info("hook_site: sys_fstatat64->vfs_fstatat ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_compat;

	return ret;

unhook_sct_compat:
	restore_syscall((void *)&armeabi_fstatat64, __ARMEABI_fstatat64, (void *)hook_armeabi_fstatat64, (void *)compat_sys_call_table);
#endif // CONFIG_COMPAT

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
static int bl_hook_execve(void *data)
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t symbol_addr;

	target_callsite = syscall_lookup("sys_execve");

	symbol_addr = kallsyms_lookup_retry("do_execveat_common");
	if (!symbol_addr)
		goto hook2;

	// patch our hook handler first
	ret = arm64_b_or_bl_patch(kernel_function_lookup(ksu_do_execveat_common), 256 * sizeof(void *), kernel_function_lookup(ksu_do_execveat_common_fn), symbol_addr);
	pr_info("patch_hook: ksu_do_execveat_common->ksu_do_execveat_common_fn ret: %d \n", ret);
	if (ret)
		return ret;

	ret = arm64_b_or_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_execveat_common);
	pr_info("hook_site: sys_execve->do_execveat_common ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_native;

hook2:
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
	symbol_addr = kallsyms_lookup_retry("__do_execve_file");
	if (!symbol_addr)
		goto hook3;

	// patch our hook handler first
	ret = arm64_b_or_bl_patch(kernel_function_lookup(ksu_do_execve_file), 256 * sizeof(void *), kernel_function_lookup(ksu_do_execve_file_fn), symbol_addr);
	pr_info("patch_hook: ksu_do_execve_file->ksu_do_execve_file_fn ret: %d \n", ret);
	if (ret)
		return ret;

	ret = arm64_b_or_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_execve_file);
	pr_info("hook_site: sys_execve->__do_execve_file ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_native;
#endif // < 5.9
hook3:
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	symbol_addr = kallsyms_lookup_retry("do_execve_common");
	if (!symbol_addr)
		goto hook4;

	// patch our hook handler first
	ret = arm64_b_or_bl_patch(kernel_function_lookup(ksu_do_execve_common), 256 * sizeof(void *), kernel_function_lookup(ksu_do_execve_common_fn), symbol_addr);
	pr_info("patch_hook: ksu_do_execve_common->ksu_do_execve_common_fn ret: %d \n", ret);
	if (ret)
		return ret;

	ret = arm64_b_or_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_execve_common_fn);
	pr_info("hook_site: sys_execve->do_execve_common ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_native;
#endif // < 3.19
hook4:
	symbol_addr = kallsyms_lookup_retry("do_execve");
	if (!symbol_addr)
		return -ENOENT;

	// patch our hook handler first
	ret = arm64_b_or_bl_patch(kernel_function_lookup(ksu_do_execve), 256 * sizeof(void *), kernel_function_lookup(ksu_do_execve_fn), symbol_addr);
	pr_info("patch_hook: ksu_do_execve->ksu_do_execve_fn ret: %d \n", ret);
	if (ret)
		return ret;

	ret = arm64_b_or_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_execve);
	pr_info("hook_site: sys_execve->do_execve ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_native;

	return ret;

unhook_sct_native:
	restore_syscall((void *)&aarch64_execve, __AARCH64_execve, (void *)hook_aarch64_execve, (void *)sys_call_table);

#ifdef CONFIG_COMPAT
	target_callsite = syscall_lookup("compat_sys_execve");

	symbol_addr = kallsyms_lookup_retry("do_execveat_common");
	if (!symbol_addr)
		goto hook2c;

	ret = arm64_b_or_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_execveat_common);
	pr_info("hook_site: compat_sys_execve->do_execveat_common ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_compat;

hook2c:
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
	symbol_addr = kallsyms_lookup_retry("__do_execve_file");
	if (!symbol_addr)
		goto hook3c;

	ret = arm64_b_or_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_execve_file);
	pr_info("hook_site: compat_sys_execve->__do_execve_file ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_compat;
#endif // < 5.9
hook3c:
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	symbol_addr = kallsyms_lookup_retry("do_execve_common");
	if (!symbol_addr)
		goto hook4c;

	ret = arm64_b_or_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_execve_common_fn);
	pr_info("hook_site: compat_sys_execve->do_execve_common ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_compat;
#endif // < 3.19
hook4c:
	symbol_addr = kallsyms_lookup_retry("compat_do_execve");
	if (!symbol_addr)
		return -ENOENT;

	// patch our hook handler first
	ret = arm64_b_or_bl_patch(kernel_function_lookup(ksu_compat_do_execve), 256 * sizeof(void *), kernel_function_lookup(ksu_compat_do_execve_fn), symbol_addr);
	pr_info("patch_hook: ksu_compat_do_execve->ksu_compat_do_execve_fn ret: %d \n", ret);
	if (ret)
		return ret;

	ret = arm64_b_or_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_compat_do_execve);
	pr_info("hook_site: compat_sys_execve->compat_do_execve ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_compat;

	return ret;

unhook_sct_compat:
	restore_syscall((void *)&armeabi_execve, __ARMEABI_execve, (void *)hook_armeabi_execve, (void *)compat_sys_call_table);
#endif

	return ret;
}
#else /* < 3.14 */
static int bl_hook_execve(void *data)
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t symbol_addr;

	target_callsite = syscall_lookup("sys_execve");
	symbol_addr = kallsyms_lookup_retry("do_execve_common");
	if (!symbol_addr)
		return -ENOENT;

	// patch our hook handler first
	ret = arm64_b_or_bl_patch(kernel_function_lookup(ksu_do_execve_common), 256 * sizeof(void *), kernel_function_lookup(ksu_do_execve_common_fn), symbol_addr);
	pr_info("patch_hook: ksu_do_execve_common->ksu_do_execve_common_fn ret: %d \n", ret);
	if (ret)
		return ret;

	ret = arm64_b_or_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_execve_common);
	pr_info("hook_site: sys_execve->do_execve_common ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_native;

	return ret;

unhook_sct_native:
	restore_syscall((void *)&aarch64_execve, __AARCH64_execve, (void *)hook_aarch64_execve, (void *)sys_call_table);

#ifdef CONFIG_COMPAT
	target_callsite = syscall_lookup("compat_sys_execve");

	ret = arm64_b_or_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_execve_common);
	pr_info("hook_site: compat_sys_execve->do_execve_common ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_compat;

	return ret;

unhook_sct_compat:
	restore_syscall((void *)&armeabi_execve, __ARMEABI_execve, (void *)hook_armeabi_execve, (void *)compat_sys_call_table);
#endif

	return ret;
}
#endif

#undef kernel_function_lookup
#undef syscall_lookup

static int bl_hack_init_thread(void *data)
{
	set_user_nice(current, 19); // low prio

	bool faccessat = !!!bl_hook_faccessat(data);
	bool newfstatat = !!!bl_hook_newfstatat(data);
	bool execve = !!!bl_hook_execve(data);

	pr_info("branch_link: done! faccessat: %s newfstatat: %s execve: %s\n", (faccessat) ? "ok" : "fail", (newfstatat) ? "ok" : "fail", (execve) ? "ok" : "fail");

	dotted_kallsyms_destroy_hash_array();

	return 0;
}

static int ksu_branch_link_patch_init()
{
	// enable sct first, if branch link succeeds, it will be restored
	syscall_table_ksud_hook_init();
	syscall_table_sucompat_enable();

	/**
	 *  we move sucompat hook initialization to a kthread
	 *  due to it falling back to a bruteforce ksym lookup if !kprobes
	 *  it somewhat takes 0.5 ~ 1s to scan whole kernel _stext to _etext
	 *  so this better be offloaded
	 */
	kthread_run(bl_hack_init_thread, NULL, "kthread");

	return 0;
}
