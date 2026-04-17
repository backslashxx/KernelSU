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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
static struct security_hook_list ksu_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(inode_rename, ksu_inode_rename),
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
	LSM_HOOK_INIT(bprm_check_security, ksu_bprm_check),
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

void __init ksu_core_init(void)
{
	ksu_lsm_hook_init();
}
