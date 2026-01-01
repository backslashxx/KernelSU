int ksu_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			    struct inode *new_inode, struct dentry *new_dentry)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return 0;
}

int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	// see sys_setresuid
	if (flags == LSM_SETID_RES)
		ksu_handle_setresuid_cred(new, old);

	return 0;
}

int ksu_bprm_check(struct linux_binprm *bprm)
{
	return 0;
}

int ksu_file_permission(struct file *file, int mask)
{
#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE)
	if (unlikely(ksu_vfs_read_hook))
		ksu_install_rc_hook(file);
#endif

	return 0;
}

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
static void ksu_lsm_hook_init(void)
{
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
}
#else
static void ksu_lsm_hook_init(void)
{
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
}
#endif
#endif // 4.2 || KSU_COMPAT_SECURITY_ADD_HOOKS_V2

void __init ksu_core_init(void)
{
	ksu_lsm_hook_init();
}
