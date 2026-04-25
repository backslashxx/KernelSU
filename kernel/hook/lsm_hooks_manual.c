int ksu_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			    struct inode *new_inode, struct dentry *new_dentry)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return 0;
}

int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	return 0;
}

int ksu_bprm_check(struct linux_binprm *bprm)
{
	return 0;
}

static void __init ksu_core_init(void)
{
	pr_info("%s: Automated LSM hooking disabled. Make sure manual security hooks are implemented!\n", __func__);
}
