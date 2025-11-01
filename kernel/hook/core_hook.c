int ksu_handle_rename(struct dentry *old_dentry, struct dentry *new_dentry)
{
	// skip kernel threads
	if (!current->mm)
		return 0;

	// skip non system uid
	if (current_uid().val != 1000)
		return 0;

	if (!old_dentry || !new_dentry)
		return 0;

	// /data/system/packages.list.tmp -> /data/system/packages.list
	if (strcmp(new_dentry->d_iname, "packages.list"))
		return 0;

	char path[128] = { 0 };
	char *buf = dentry_path_raw(new_dentry, path, sizeof(path) - 1);
	if (IS_ERR(buf)) {
		pr_err("dentry_path_raw failed.\n");
		return 0;
	}

	if (!strstr(buf, "/system/packages.list"))
		return 0;

	pr_info("renameat: %s -> %s, new path: %s\n", old_dentry->d_iname, new_dentry->d_iname, buf);

	track_throne(false);

	return 0;
}

int ksu_handle_setuid(struct cred *new, const struct cred *old)
{
	if (!new || !old) {
		return 0;
	}

	uid_t new_uid = new->uid.val;
	uid_t old_uid = old->uid.val;

	// old process is not root, ignore it.
	if (0 != old_uid)
		return 0;

	// we dont have those new fancy things upstream has
	// lets just do the original thing where we disable seccomp
	if (unlikely(is_uid_manager(new_uid)))
		goto install_ksu_fd;

	if (unlikely(ksu_is_allow_uid_for_current(new_uid)))
		goto kill_seccomp;

	ksu_handle_umount(new, old);
	return 0;

install_ksu_fd:
	pr_info("install fd for manager: %d\n", new_uid);
	ksu_install_fd();

kill_seccomp:
	disable_seccomp();
	return 0;
}

static int ksu_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			    struct inode *new_inode, struct dentry *new_dentry)
{
	return ksu_handle_rename(old_dentry, new_dentry);
}

static int ksu_task_fix_setuid(struct cred *new, const struct cred *old,
			       int flags)
{
	return ksu_handle_setuid(new, old);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
static struct security_hook_list ksu_hooks[] = {
	LSM_HOOK_INIT(inode_rename, ksu_inode_rename),
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
static void ksu_lsm_hook_init(void)
{
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
}

#else
static void ksu_lsm_hook_init(void)
{
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
}
#endif // 4.11
#endif // 4.2

void __init ksu_core_init(void)
{
	ksu_lsm_hook_init();
}
