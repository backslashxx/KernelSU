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

#define KEEP_SYMBOL asmlinkage noinline
#define DEFINE_ASM_STUB(name) 			\
__asm__ (					\
	"\n .text"				\
	"\n .p2align 2"				\
	"\n .global "#name" "			\
	"\n "#name":"				\
	"\n brk #1"				\
);	

extern int vfs_rename(struct renamedata *rd);
KEEP_SYMBOL int ksu_vfs_rename(struct renamedata *rd)
{
	int ret = vfs_rename(rd);
	if (!ret)
		ksu_rename_observer(rd->old_dentry, rd->new_dentry);

	return ret;
}

extern int security_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int flags);
KEEP_SYMBOL int ksu_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return security_inode_rename(old_dir, old_dentry, new_dir, new_dentry, flags);
}


DEFINE_ASM_STUB(security_task_fix_setuid_fn);
KEEP_SYMBOL int security_task_fix_setuid_fn(struct cred *new, const struct cred *old, int flags);
KEEP_SYMBOL int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	// see sys_setresuid
	if (flags == LSM_SETID_RES)
		ksu_handle_setresuid_cred(new, old);

	return security_task_fix_setuid_fn(new, old, flags);
}

DEFINE_ASM_STUB(security_bprm_check_fn);
KEEP_SYMBOL int security_bprm_check_fn(struct linux_binprm *bprm);
KEEP_SYMBOL int ksu_bprm_check(struct linux_binprm *bprm)
{
#ifdef CONFIG_KSU_FEATURE_SULOG
	ksu_sulog_emit_bprm((const char *)bprm->filename);
#endif
	return security_bprm_check_fn(bprm);
}

DEFINE_ASM_STUB(security_file_permission_fn);
KEEP_SYMBOL int security_file_permission_fn(struct file *file, int mask);
KEEP_SYMBOL int ksu_file_permission(struct file *file, int mask)
{
#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE)
#ifdef KSU_CAN_USE_JUMP_LABEL
	if (static_branch_likely(&ksud_vfs_read_key))
		ksu_install_rc_hook(file);
#else
	if (unlikely(ksu_vfs_read_hook))
		ksu_install_rc_hook(file);
#endif
#endif
	return security_file_permission_fn(file, mask);
}

// NOTE: weird LSM. only one is allowed. gets folded on 7.1
extern int security_setprocattr(int lsmid, const char *name, void *value, size_t size);
KEEP_SYMBOL int ksu_setprocattr(int lsmid, const char *name, void *value, size_t size)
{
	ksu_hide_setprocattr_inline(name, value, size);
	return security_setprocattr(lsmid, name, value, size);
}

#undef KEEP_SYMBOL
#undef DEFINE_ASM_STUB

#ifdef CONFIG_MODULES
#define kernel_function_lookup(name) kallsyms_lookup_retry(#name)
#else
#define kernel_function_lookup(name) (uintptr_t)&name
#endif

static void __init ksu_core_init(void)
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t symbol_addr;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0) 
	target_callsite = kallsyms_lookup_retry("filename_renameat2");
#else
	target_callsite = kallsyms_lookup_retry("do_renameat2");
#endif
	symbol_addr = kallsyms_lookup_retry("vfs_rename");
	ret = arm64_bl_patch(target_callsite, 256 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_rename);
	pr_info("hook_site: vfs_rename: ret %d \n", ret);
	if (!ret)
		goto skip_rename;

	target_callsite = kallsyms_lookup_retry("vfs_rename");
	symbol_addr = kallsyms_lookup_retry("security_inode_rename");
	ret = arm64_bl_patch(target_callsite, 256 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_inode_rename);
	pr_info("hook_site: security_inode_rename: ret %d \n", ret);
skip_rename:

	symbol_addr = kallsyms_lookup_retry("__SCT__lsm_static_call_task_fix_setuid_0");
	if (!symbol_addr)
		goto skip_setuid;

	// patch our hook handler first
	ret = arm64_b_or_bl_patch(kernel_function_lookup(ksu_task_fix_setuid), 128 * sizeof(void *), kernel_function_lookup(security_task_fix_setuid_fn), symbol_addr);
	pr_info("patch_hook: ksu_task_fix_setuid->security_task_fix_setuid_fn ret: %d \n", ret);

	target_callsite = kallsyms_lookup_retry("security_task_fix_setuid");
	ret = arm64_bl_patch(target_callsite, 64 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_task_fix_setuid);
	pr_info("hook_site: security_task_fix_setuid: ret %d \n", ret);
skip_setuid:

#ifdef CONFIG_KSU_FEATURE_SULOG
	symbol_addr = kallsyms_lookup_retry("__SCT__lsm_static_call_bprm_check_security_0");
	if (!symbol_addr)
		goto skip_bprm;

	// patch our hook handler first
	ret = arm64_b_or_bl_patch(kernel_function_lookup(ksu_bprm_check), 128 * sizeof(void *), kernel_function_lookup(security_bprm_check_fn), symbol_addr);
	pr_info("patch_hook: ksu_bprm_check->security_bprm_check_fn ret: %d \n", ret);

	target_callsite = kallsyms_lookup_retry("security_bprm_check");
	ret = arm64_bl_patch(target_callsite, 64 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_bprm_check);
	pr_info("hook_site: security_bprm_check: ret %d \n", ret);
skip_bprm:
#endif

#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) && !defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
	symbol_addr = kallsyms_lookup_retry("__SCT__lsm_static_call_file_permission_0");
	if (!symbol_addr)
		goto skip_file_permission;

	// patch our hook handler first
	ret = arm64_b_or_bl_patch(kernel_function_lookup(ksu_file_permission), 128 * sizeof(void *), kernel_function_lookup(security_file_permission_fn), symbol_addr);
	pr_info("patch_hook: ksu_task_fix_setuid->security_file_permission_fn ret: %d \n", ret);

	target_callsite = kallsyms_lookup_retry("security_file_permission");
	ret = arm64_b_or_bl_patch(target_callsite, 64 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_file_permission);
	pr_info("hook_site: selinux_file_permission: ret %d \n", ret);
skip_file_permission:
#endif

	// NOTE: weird hook
	target_callsite = kallsyms_lookup_retry("proc_pid_attr_write");
	symbol_addr = kallsyms_lookup_retry("security_setprocattr");
	ret = arm64_bl_patch(target_callsite, 64 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_setprocattr);
	pr_info("lsm_hijack: security_setprocattr: ret %d \n", ret);
}

#undef kernel_function_lookup
