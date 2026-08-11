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
#pragma once
#ifndef __KSU_H_TEMP_PATCH_SETGROUPS
#define __KSU_H_TEMP_PATCH_SETGROUPS

#define __AARCH64_setgroups	159
#define __ARMEABI_setgroups	206

static void ksu_modify_setgroups(int *gidsetsize, void **grouplist_pptr)
{
	int i = 0;
	gid_t user_gid;
	gid_t __user *grouplist = (gid_t __user *)untagged_addr(*(void **)grouplist_pptr);
	int size = *gidsetsize;

	if (!size)
		return;

	// allow 3009 for adbd
	if (!strcmp(current->comm, "adbd"))
		return;
start:
	if (!!get_user(user_gid, &grouplist[i]))
		goto step_up;

	if (user_gid != 3009)
		goto step_up;

	// last entry, just reset size
	if (size - i == 1)
		goto decrement;

	// prepare and copy remaining
	size_t remaining = (size - i) * sizeof(gid_t);
	if (!!memmove_user((void __user *)&grouplist[i], (void __user *)&grouplist[i+1], remaining - sizeof(gid_t)))
		return;

decrement:
	*gidsetsize = *gidsetsize - 1;
	pr_info("ksu_setgroups: %s: %d: prevent gid 3009 assignment\n", current->comm, current->pid);
	return;

step_up:
	i++;
	if (size > i)
		goto start;

}

#if 0
static void print_setgroups(int gidsetsize, void **grouplist_pptr)
{
	int i = 0;
	gid_t user_gid;
	gid_t __user *grouplist = (gid_t __user *)untagged_addr(*(void **)grouplist_pptr);

	if (!gidsetsize)
		return;
start:
	if (!!get_user(user_gid, &grouplist[i]))
		goto increment;

	pr_info("ksu_setgroups: %s: %d: gid: %d \n", current->comm, current->pid, user_gid);

increment:
	i++;
	if (gidsetsize > i)
		goto start;

}
#endif

#ifdef CONFIG_ARM64
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
static syscall_fn_t aarch64_setgroups __read_mostly = NULL;
asmlinkage long hook_aarch64_setgroups(const struct pt_regs *regs)
{
	int *gidsetsize_ptr = (int *)&regs->regs[0];
	void **grouplist_pptr = (void **)&regs->regs[1];

	ksu_modify_setgroups(gidsetsize_ptr, grouplist_pptr);
	return __arm64_sys_setgroups(regs);
}

#ifdef CONFIG_COMPAT
static syscall_fn_t armeabi_setgroups __read_mostly = NULL;
asmlinkage long hook_armeabi_setgroups(const struct pt_regs *regs)
{
	int *gidsetsize_ptr = (int *)&regs->regs[0];
	void **grouplist_pptr = (void **)&regs->regs[1];

	ksu_modify_setgroups(gidsetsize_ptr, grouplist_pptr);
	return __arm64_sys_setgroups(regs);
}
#endif // COMPAT

#else /* < 4.19 */

static void *aarch64_setgroups __read_mostly = NULL;
asmlinkage long hook_aarch64_setgroups(int gidsetsize, gid_t __user *grouplist)
{
	ksu_modify_setgroups(&gidsetsize, (void **)&grouplist);
	return sys_setgroups(gidsetsize, grouplist);
}

#ifdef CONFIG_COMPAT
extern const void *compat_sys_call_table[];

static void *armeabi_setgroups __read_mostly = NULL;
asmlinkage long hook_armeabi_setgroups(int gidsetsize, gid_t __user *grouplist)
{
	ksu_modify_setgroups(&gidsetsize, (void **)&grouplist);
	return sys_setgroups(gidsetsize, grouplist);
}
#endif // COMPAT

#endif /* < 4.19 */

#elif defined(CONFIG_ARM)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
static syscall_fn_t armeabi_setgroups __read_mostly = NULL;
asmlinkage long hook_armeabi_setgroups(const struct pt_regs *regs)
{
	int *gidsetsize_ptr = (int *)&regs->regs[0];
	void **grouplist_pptr = (void **)&regs->regs[1];

	ksu_modify_setgroups(gidsetsize_ptr, grouplist_pptr);
	return sys_setgroups(regs);
}

#else /* < 4.19 */

extern void *sys_call_table[];

static void *armeabi_setgroups __read_mostly = NULL;
asmlinkage long hook_armeabi_setgroups(int gidsetsize, gid_t __user *grouplist)
{
	ksu_modify_setgroups(&gidsetsize, (void **)&grouplist);
	return sys_setgroups(gidsetsize, grouplist);
}

#endif  /* < 4.19 */
#endif // ARM

static int ksu_unhook_setgroups()
{
#ifdef CONFIG_ARM64
	restore_syscall((void *)&aarch64_setgroups, __AARCH64_setgroups, (void *)hook_aarch64_setgroups, (void *)sys_call_table);
#ifdef CONFIG_COMPAT
	restore_syscall((void *)&armeabi_setgroups, __ARMEABI_setgroups, (void *)hook_armeabi_setgroups, (void *)compat_sys_call_table);
#endif // compat

#elif defined(CONFIG_ARM)
	restore_syscall((void *)&armeabi_setgroups, __ARMEABI_setgroups, (void *)hook_armeabi_setgroups, (void *)sys_call_table);
#endif
	
	return 0;
}

static void ksu_init_setgroups_patch()
{
	pr_info("%s: patching setgroups()\n", __func__);

#ifdef CONFIG_ARM64
	read_and_replace_syscall((void *)&aarch64_setgroups, __AARCH64_setgroups, (void *)hook_aarch64_setgroups, (void *)sys_call_table);
#ifdef CONFIG_COMPAT
	read_and_replace_syscall((void *)&armeabi_setgroups, __ARMEABI_setgroups, (void *)hook_armeabi_setgroups, (void *)compat_sys_call_table);
#endif // compat

#elif defined(CONFIG_ARM)
	read_and_replace_syscall((void *)&armeabi_setgroups, __ARMEABI_setgroups, (void *)hook_armeabi_setgroups, (void *)sys_call_table);
#endif
}

#endif // __KSU_H_TEMP_PATCH_SETGROUPS
