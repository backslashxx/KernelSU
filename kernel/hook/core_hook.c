int ksu_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			    struct inode *new_inode, struct dentry *new_dentry)
{
	return 0;
}

int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
static struct security_hook_list ksu_hooks[] = {
	LSM_HOOK_INIT(inode_rename, ksu_inode_rename),
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
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
