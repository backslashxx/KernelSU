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
	if (unlikely(ksu_vfs_read_hook))
		ksu_install_rc_hook(file);

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)

static struct security_hook_list ksu_hooks_temp[] = {
	LSM_HOOK_INIT(file_permission, ksu_file_permission),
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) || defined(KSU_COMPAT_SECURITY_DELETE_HOOKS_HLIST)
#define delete_lsm_entry hlist_del_rcu
#else
#define delete_lsm_entry list_del_rcu
#endif

// see security_delete_hooks
static inline void ksu_security_delete_hooks(struct security_hook_list *hooks, int count)
{
	int i;
	for (i = 0; i < count; i++)
		delete_lsm_entry(&hooks[i].list);
}

static int ksu_lsm_hook_restore(void *data)
{

loop_start:

	msleep(1000);

	if (*(volatile bool *)&ksu_vfs_read_hook)
		goto loop_start;

	pr_info("%s: unreg file_permission LSM!\n", __func__);

	ksu_security_delete_hooks(ksu_hooks_temp, ARRAY_SIZE(ksu_hooks_temp));
	return 0;
}

static struct security_hook_list ksu_hooks[] = {
	LSM_HOOK_INIT(inode_rename, ksu_inode_rename),
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
	LSM_HOOK_INIT(bprm_check_security, ksu_bprm_check),
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0) || defined(KSU_COMPAT_SECURITY_ADD_HOOKS_V2)
static void ksu_lsm_hook_init(void)
{
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
	security_add_hooks(ksu_hooks_temp, ARRAY_SIZE(ksu_hooks_temp), "ksu");

	kthread_run(ksu_lsm_hook_restore, NULL, "unhook");
}
#else
static void ksu_lsm_hook_init(void)
{
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
	security_add_hooks(ksu_hooks_temp, ARRAY_SIZE(ksu_hooks_temp));

	kthread_run(ksu_lsm_hook_restore, NULL, "unhook");
}
#endif
#endif // 4.2 || KSU_COMPAT_SECURITY_ADD_HOOKS_V2

void __init ksu_core_init(void)
{
	ksu_lsm_hook_init();
}
