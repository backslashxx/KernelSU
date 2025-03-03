#ifdef CONFIG_KSU_LSM_SECURITY_HOOKS
#define LSM_HANDLER_TYPE static int
#else
#define LSM_HANDLER_TYPE int
#endif

LSM_HANDLER_TYPE ksu_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			    struct inode *new_inode, struct dentry *new_dentry)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return 0;
}

LSM_HANDLER_TYPE ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	// see sys_setresuid
	if (flags == LSM_SETID_RES)
		ksu_handle_setresuid_cred(new, old);

	return 0;
}

LSM_HANDLER_TYPE ksu_bprm_check(struct linux_binprm *bprm)
{
	return 0;
}

LSM_HANDLER_TYPE ksu_file_permission(struct file *file, int mask)
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

	return 0;
}

#ifdef CONFIG_KSU_LSM_SECURITY_HOOKS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
static struct security_hook_list ksu_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(inode_rename, ksu_inode_rename),
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
	LSM_HOOK_INIT(bprm_check_security, ksu_bprm_check),
#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE)
	LSM_HOOK_INIT(file_permission, ksu_file_permission),
#endif
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0) || defined(KSU_COMPAT_SECURITY_ADD_HOOKS_V2)
#define ksu_security_add_hooks security_add_hooks
#else
#define ksu_security_add_hooks(a, b, c) security_add_hooks(a, b)
#endif

static inline void ksu_lsm_hook_init(void)
{
	ksu_security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");

	pr_info("core_hook: initialized %d LSMs \n", ARRAY_SIZE(ksu_hooks));
}
#endif // 4.2 

#else /* ! CONFIG_KSU_LSM_SECURITY_HOOKS */
// TEMP hooks, remove this in a month.
int ksu_handle_setuid(struct cred *new, const struct cred *old)
{
	ksu_handle_setresuid_cred(new, old);
	return 0;
}
int ksu_handle_rename(struct dentry *old_dentry, struct dentry *new_dentry)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return 0;
}
static inline void ksu_lsm_hook_init(void) { } // nothing, no-op
#endif // CONFIG_KSU_LSM_SECURITY_HOOKS

void __init ksu_core_init(void)
{
	ksu_lsm_hook_init();
}
