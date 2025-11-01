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

#if !defined(CONFIG_ARM64)
#error "automated LSM hooking on 6.8+ is only for ARM64!"
#endif

#if !defined(CONFIG_KALLSYMS)
#error "automated LSM hooking on 6.8+ requires kallsyms!"
#endif

// security.c hijack for 6.8+

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
extern int vfs_rename(struct renamedata *rd);
static int ksu_vfs_rename(struct renamedata *rd)
{
	int ret = vfs_rename(rd);
	if (!ret)
		ksu_rename_observer(rd->old_dentry, rd->new_dentry);
	return ret;
}
#endif

extern int security_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int flags);
static int ksu_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return security_inode_rename(old_dir, old_dentry, new_dir, new_dentry, flags);
}

// setuid
extern int security_task_fix_setuid(struct cred *new, const struct cred *old, int flags);
static int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	// see sys_setresuid
	if (flags == LSM_SETID_RES)
		ksu_handle_setresuid_cred(new, old);

	return security_task_fix_setuid(new, old, flags);
}

#define __AARCH64_setresuid 147
static void *aarch64_setresuid __read_mostly = nullptr;
asmlinkage long hook_aarch64_setresuid(const struct pt_regs *regs)
{
	extern long __arm64_sys_setresuid(const struct pt_regs *regs);
	const struct cred old = *current_cred();

	long ret = __arm64_sys_setresuid(regs);
	if (!ret)
		ksu_handle_setresuid_cred(current_cred(), &old);
	return ret;
}

#ifdef CONFIG_COMPAT
#define __ARMEABI_setresuid 208
static void *armeabi_setresuid __read_mostly = nullptr;
asmlinkage long hook_armeabi_setresuid(const struct pt_regs *regs)
{
	extern long __arm64_sys_setresuid(const struct pt_regs *regs);
	const struct cred old = *current_cred();

	long ret = __arm64_sys_setresuid(regs);
	if (!ret)
		ksu_handle_setresuid_cred(current_cred(), &old);
	return ret;
}
#endif

#define estimated_sz (256 * sizeof(uint32_t))
static int arm64_branch_patch_trampolined(uintptr_t callsite, uintptr_t symbol_addr, void *hook_addr)
{
	int ret = arm64_b_or_bl_patch(callsite, ksu_get_ksym_size(callsite, estimated_sz), symbol_addr, (uintptr_t)hook_addr);
	if (ret != -ERANGE)
		return ret;
	
	uintptr_t trampoline = create_landing_pad((uintptr_t)hook_addr);
	if (trampoline)
		ret = arm64_b_or_bl_patch(callsite, ksu_get_ksym_size(callsite, estimated_sz), symbol_addr, trampoline);
	return ret;	
}

static void print_branch_targets(uintptr_t callsite, uintptr_t symbol_addr, char *hook_name)
{
	char buf1[KSYM_SYMBOL_LEN];
	sprint_symbol_no_offset(buf1, symbol_addr);
	pr_info("LSM: Initializing hook for %s -> %s \n", buf1, hook_name);
}
#define do_arm64_branch_patch_trampolined arm64_branch_patch_trampolined
#define arm64_branch_patch_trampolined(callsite, symbol_addr, hook_fn) ({		\
	print_branch_targets(callsite, symbol_addr, #hook_fn);				\
	do_arm64_branch_patch_trampolined(callsite, symbol_addr, (void *)hook_fn);	\
})

static void __init ksu_lsm_hook_init(void)
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t symbol_addr;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0) 
	target_callsite = kallsyms_lookup_retry("filename_renameat2"); // k7.0
	if (!target_callsite)
		target_callsite = kallsyms_lookup_retry("do_renameat2");
	symbol_addr = kallsyms_lookup_retry("vfs_rename");
	ret = arm64_branch_patch_trampolined(target_callsite, symbol_addr, ksu_vfs_rename);
	pr_info("LSM: vfs_rename: ret %d \n", ret);
	if (!ret)
		goto rename_hook_done;
#endif // > 5.12
	target_callsite = kallsyms_lookup_retry("vfs_rename2"); // vfs2
	if (!target_callsite)
		target_callsite = kallsyms_lookup_retry("vfs_rename");
	symbol_addr = kallsyms_lookup_retry("security_inode_rename");
	ret = arm64_branch_patch_trampolined(target_callsite, symbol_addr, ksu_inode_rename);
	pr_info("LSM: security_inode_rename: ret %d \n", ret);
rename_hook_done:

	target_callsite = kallsyms_lookup_retry("__sys_setresuid");
	if (!target_callsite)
		target_callsite = kallsyms_lookup_retry("__arm64_sys_setresuid");
	symbol_addr = kallsyms_lookup_retry("security_task_fix_setuid");
	ret = arm64_branch_patch_trampolined(target_callsite, symbol_addr, ksu_task_fix_setuid);
	if (ret) {
		pr_info("LSM: security_task_fix_setuid: err: %d ! fallback to sys_setresuid!\n", ret);
		replace_syscall((void *)&aarch64_setresuid, __AARCH64_setresuid, (void *)hook_aarch64_setresuid, native_sct);
	#ifdef CONFIG_COMPAT
		replace_syscall((void *)&armeabi_setresuid, __ARMEABI_setresuid, (void *)hook_armeabi_setresuid, compat_sct);
	#endif
	} else
		pr_info("LSM: security_task_fix_setuid: ret %d \n", ret);

}

#undef arm64_branch_patch_trampolined
#undef estimated_sz
