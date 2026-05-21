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

static int (*task_fix_setuid_fn)(struct cred *new, const struct cred *old, int flags) __read_mostly = NULL;
static __nocfi int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	// see sys_setresuid
	if (flags == LSM_SETID_RES)
		ksu_handle_setresuid_cred(new, old);

	return task_fix_setuid_fn(new, old, flags);
}

static int (*inode_rename_fn)(struct inode *old_inode, struct dentry *old_dentry, struct inode *new_inode, struct dentry *new_dentry) __read_mostly = NULL;
static __nocfi int ksu_inode_rename(struct inode *old_inode, struct dentry *old_dentry, struct inode *new_inode, struct dentry *new_dentry)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return inode_rename_fn(old_inode, old_dentry, new_inode, new_dentry);
}

static void (*bprm_committing_creds_fn)(struct linux_binprm *bprm) __read_mostly = NULL;
static __nocfi void ksu_bprm_committing_creds(struct linux_binprm *bprm)
{
	bprm_committing_creds_fn(bprm); // NOTE: void LSM hook
}

static int (*file_permission_fn)(struct file *file, int mask) __read_mostly = NULL;
static __nocfi int ksu_file_permission(struct file *file, int mask)
{
	if (unlikely(ksu_vfs_read_hook))
		ksu_install_rc_hook(file);

	return file_permission_fn(file, mask);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static int (*bprm_set_creds_fn)(struct linux_binprm *bprm) __read_mostly = NULL;
static __nocfi int ksu_bprm_set_creds(struct linux_binprm *bprm)
{
	if (likely(ksu_boot_completed))
		goto capability_fn;

	if (likely(!is_init(current_cred())))
		goto capability_fn;

	if (!bprm->filename)
		goto capability_fn;

	if (!!strcmp(bprm->filename, "/data/adb/ksud"))
		goto capability_fn;

	pr_info("bprm_set_creds: escape init executing %s with pid: %d\n", bprm->filename, current->pid);
	escape_to_root_forced(); // give this context all permissions

capability_fn:
	return bprm_set_creds_fn(bprm);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0) || defined(KSU_COMPAT_SECURITY_ADD_HOOKS_V2)
// reserved for setprocattr
#endif

struct lsm_patch_param {
	void **target_slot;	// pptr to writable vmapped lsm slot
	void *fn_ptr;		// fn_ptr to write on that slot
};

static int patch_lsm_slot_stop_machine(void *data)
{
	struct lsm_patch_param *param = (struct lsm_patch_param *)data;

	// write on the actual lsm slot
	*(param->target_slot) = param->fn_ptr;

	return 0;
}

static inline int ksu_write_to_readonly_slot(uintptr_t slot_ptr, uintptr_t new_ptr)
{
	uintptr_t addr = (uintptr_t)slot_ptr;
	uintptr_t base = addr & PAGE_MASK;
	uintptr_t offset = addr & ~PAGE_MASK;

	struct page *page = phys_to_page(__pa(base));
	if (!page)
		return -EFAULT;

	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		return -ENOMEM;

	void **target_slot = (void **)((unsigned long)writable_addr + offset);

	struct lsm_patch_param param;
	param.target_slot = target_slot;
	param.fn_ptr = new_ptr;

	stop_machine(patch_lsm_slot_stop_machine, (void *)&param, NULL);

	vunmap(writable_addr);
	smp_mb();

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) || defined(KSU_COMPAT_SECURITY_DELETE_HOOKS_HLIST)
static void ksu_hack_lsm_slot(struct hlist_head *hook_head, uintptr_t *old_ptr, uintptr_t new_ptr)
{
	struct security_hook_list *pos;
	struct hlist_head *head = hook_head;
	bool found = false;

	// just grab first entry
	hlist_for_each_entry(pos, head, list) {
		found = true;
		break;
	}

	if (!found) {
		pr_info("LSM: No LSM hook on slot\n");
		return;
	}

	// make sure this happens first, this way we dont have to pre-check on the handler
	WRITE_ONCE(*old_ptr, *(uintptr_t *)&pos->hook);
	smp_mb();

	pr_info("LSM: 0x%lx found at 0x%lx slot, name: %s \n", *(uintptr_t *)&pos->hook, (uintptr_t)&pos->hook, pos->lsm);
	int err = ksu_write_to_readonly_slot((uintptr_t)&pos->hook, new_ptr);
	if (err) {
		pr_err("LSM: ksu_write_to_readonly_slot err: %d\n", err);
		return;
	}

	pr_info("LSM: 0x%lx written to slot\n", new_ptr);
}
#else
static void ksu_hack_lsm_slot(struct list_head *hook_head, uintptr_t *old_ptr, uintptr_t new_ptr)
{
	struct security_hook_list *pos;
	struct list_head *head = hook_head;
	bool found = false;

	// just grab first entry
	list_for_each_entry(pos, head, list) {
		found = true;
		break;
	}

	if (!found) {
		pr_info("LSM: No hook on slot!\n");
		return;
	}

	WRITE_ONCE(*old_ptr, *(uintptr_t *)&pos->hook);
	smp_mb();

	pr_info("LSM: 0x%lx found at first slot 0x%lx\n", *(uintptr_t *)&pos->hook, (uintptr_t)&pos->hook);

	int err = ksu_write_to_readonly_slot((uintptr_t)&pos->hook, new_ptr);
	if (err) {
		pr_err("LSM: ksu_write_to_readonly_slot err: %d\n", err);
		return;
	}

	pr_info("LSM: 0x%lx written to slot\n", new_ptr);
}
#endif

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static int ksu_restore_bprm_set_creds(void *data)
{
	set_user_nice(current, 19); // low prio

loop_start:
	msleep(5000);
	if (!*(volatile bool *)&ksu_boot_completed)
		goto loop_start;

	msleep(1000);

	LSM_HACK_RESTORE(bprm_set_creds);
	return 0;
}
#endif

static __init void ksu_lsm_hook_init(void)
{
	LSM_HACK_INIT(task_fix_setuid, ksu_task_fix_setuid);
	LSM_HACK_INIT(inode_rename, ksu_inode_rename);
	LSM_HACK_INIT(bprm_committing_creds, ksu_bprm_committing_creds);

#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE)
	LSM_HACK_INIT(file_permission, ksu_file_permission);
	kthread_run(ksu_restore_file_permission, NULL, "kthread");
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	LSM_HACK_INIT(bprm_set_creds, ksu_bprm_set_creds);
	kthread_run(ksu_restore_bprm_set_creds, NULL, "kthread");
#endif

}

static void __init ksu_core_init(void)
{
	ksu_lsm_hook_init();
}
