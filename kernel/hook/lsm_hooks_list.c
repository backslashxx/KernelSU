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
// k4.2 ~ 6.7, LSM Hijacking, pure function pointer edition.
extern struct security_hook_heads security_hook_heads;

static int (*task_fix_setuid_fn)(struct cred *new, const struct cred *old, int flags) __read_mostly = nullptr;
static __nocfi int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	// see sys_setresuid
	if (flags == LSM_SETID_RES)
		ksu_handle_setresuid_cred(new, old);

	return task_fix_setuid_fn(new, old, flags);
}

static int (*inode_rename_fn)(struct inode *old_inode, struct dentry *old_dentry, struct inode *new_inode, struct dentry *new_dentry) __read_mostly = nullptr;
static __nocfi int ksu_inode_rename(struct inode *old_inode, struct dentry *old_dentry, struct inode *new_inode, struct dentry *new_dentry)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return inode_rename_fn(old_inode, old_dentry, new_inode, new_dentry);
}

static void (*bprm_committing_creds_fn)(struct linux_binprm *bprm) __read_mostly = nullptr;
static __nocfi void ksu_bprm_committing_creds(struct linux_binprm *bprm)
{
	bprm_committing_creds_fn(bprm); // NOTE: void LSM hook
}

static int (*file_permission_fn)(struct file *file, int mask) __read_mostly = nullptr;
static __nocfi int ksu_file_permission(struct file *file, int mask)
{
	if (unlikely(ksu_vfs_read_hook))
		ksu_install_rc_hook(file);

	return file_permission_fn(file, mask);
}

/**
 *
 * Instead of using list/hlist abstractions and shit, since we know these things exist
 * we can just pointerwalk and walk away like its nothing.
 *
 * this should work as the first member of both list_head and hlist_head are just *
 *
 * struct list_head { struct list_head *next, *prev; };
 * struct hlist_head { struct hlist_node *first; }; / struct hlist_node { struct hlist_node *next, **pprev; };
 *
 * variant 1: 4.3 ~ 4.10
 * struct security_hook_list {
 *	struct list_head		list;	// 2 uintptr
 *	struct list_head		*head;
 *	union security_list_options	hook;	// 1 uintptr
 * };
 *
 * variant 2: 4.11 - 4.17
 * struct security_hook_list {
 *	struct list_head		list;
 * 	struct list_head		*head;
 * 	union security_list_options	hook;
 * 	char				*lsm;
 * };
 *
 * variant 3: 4.17+, normally backported to 4.14
 * struct security_hook_list {
 * 	struct hlist_node		list;
 * 	struct hlist_head		*head;
 * 	union security_list_options	hook;
 * 	char				*lsm;
 * };
 *
 */
static void ksu_hack_lsm_slot(void *hook_head, uintptr_t *old_ptr, uintptr_t new_ptr)
{
	if (!hook_head || !*(void **)hook_head)
		return;

	static_assert(sizeof(struct security_hook_list) >= 4 * sizeof(uintptr_t));
	static_assert(offsetof(struct security_hook_list, hook) == 3 * sizeof(uintptr_t));

	// technincally next/first
	uintptr_t node = *(uintptr_t *)hook_head;
	uintptr_t hook_slot_addr = node + 3 * sizeof(uintptr_t);

	uintptr_t current_hook = *(uintptr_t *)hook_slot_addr;
	if (!current_hook) {
		pr_info("LSM: No LSM hook on slot\n");
		return;
	}

	WRITE_ONCE(*old_ptr, current_hook);
	smp_mb();

	if (sizeof(struct security_hook_list) == 5 * sizeof(uintptr_t))
		pr_info("LSM: 0x%lx found at 0x%lx slot, name: %s \n", current_hook, hook_slot_addr, *(char **)(node + 4 * sizeof(uintptr_t)));
	else
		pr_info("LSM: 0x%lx found at slot 0x%lx\n", current_hook, hook_slot_addr);

	int err = ksu_write_to_readonly_slot(hook_slot_addr, new_ptr);
	if (err) {
		pr_err("LSM: ksu_write_to_readonly_slot err: %d\n", err);
		return;
	}

	pr_info("LSM: 0x%lx written to slot\n", new_ptr);
	return;
}

#define LSM_HACK_INIT(hook_name, hook_fn)									\
do {														\
	pr_info("LSM: Initializing hook for %s\n", #hook_name);							\
	ksu_hack_lsm_slot(&security_hook_heads.hook_name, (uintptr_t *)&hook_name##_fn, (uintptr_t)(hook_fn));	\
} while (0)

#define LSM_HACK_RESTORE(hook_name)										\
do {														\
	if (!hook_name##_fn)											\
		break;												\
	uintptr_t dummy_int;											\
	pr_info("LSM: Restoring original hook for %s\n", #hook_name);						\
	ksu_hack_lsm_slot(&security_hook_heads.hook_name, &dummy_int, (uintptr_t)hook_name##_fn);		\
} while (0)

static int ksu_restore_file_permission(void *data)
{
	set_user_nice(current, 19); // low prio

loop_start:
	msleep(1000);
	if (*(volatile bool *)&ksu_vfs_read_hook)
		goto loop_start;

	msleep(1000);

	LSM_HACK_RESTORE(file_permission);
	return 0;
}

static __init void ksu_lsm_hook_init(void)
{
	LSM_HACK_INIT(task_fix_setuid, ksu_task_fix_setuid);
	LSM_HACK_INIT(inode_rename, ksu_inode_rename);
	LSM_HACK_INIT(bprm_committing_creds, ksu_bprm_committing_creds);

#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) && !defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
	LSM_HACK_INIT(file_permission, ksu_file_permission);
	kthread_run(ksu_restore_file_permission, NULL, "kthread");
#endif

}

static void __init ksu_core_init(void)
{
	ksu_lsm_hook_init();
}
