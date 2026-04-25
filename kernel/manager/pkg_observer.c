static struct inode *system_dir_inode = NULL;

__attribute__((cold))
static noinline void ksu_grab_data_system_inode(void)
{
	struct path path;
	int ret = kern_path("/data/system", LOOKUP_FOLLOW, &path);
	if (ret) {
		pr_info("renameat: /data/system not ready? ret: (%d)\n", ret);
		return;
	}

	system_dir_inode = d_inode(path.dentry);
	pr_info("renameat: cached /data/system d_inode: 0x%lx\n", (uintptr_t)system_dir_inode);
	path_put(&path);
}

// NOTE: we can actually use new_inode from the LSM, basically
// new_inode == new_dentry->d_parent->d_inode
// but the two arg hook is already used by some, so we just traverse it, nbd
static inline void ksu_rename_observer(struct dentry *old_dentry, struct dentry *new_dentry)
{
	// skip kernel threads
	if (!current->mm)
		return;

	// skip non system uid
	if (likely(current_uid().val != 1000))
		return;

	if (!old_dentry || !new_dentry)
		return;

	// HASH_LEN_DECLARE see dcache.h
	if (likely(new_dentry->d_name.len != sizeof("packages.list") - 1  ))
		return;

	// /data/system/packages.list.tmp -> /data/system/packages.list
	if (likely(!!__builtin_memcmp(new_dentry->d_iname, "packages.list", sizeof("packages.list") - 1 )))
		return;

	// cache dir inode, we try to go for fast path, lockless
	if (unlikely(!system_dir_inode))
		ksu_grab_data_system_inode();

	if (unlikely(!system_dir_inode))
		goto slow_path;

	// fallback to slow path, but this should NOT change unless someone overlays /data/system
	// but then again maybe https://github.com/tiann/KernelSU/pull/2633#discussion_r2141740346
	// but /data is casefolded, overlaying is really really unlikely
	// we self heal this thing, so on enxt run, it will try to grab d inode again
	if (unlikely(new_dentry->d_parent->d_inode != system_dir_inode)) {
		system_dir_inode = NULL;
		goto slow_path;
	}

	pr_info("renameat: %s -> %s, /data/system d_inode: 0x%lx \n", old_dentry->d_iname, new_dentry->d_iname, (uintptr_t)system_dir_inode);
	track_throne(false);
	return;

slow_path:
	;
	char path[128] = { 0 };
	char *buf = dentry_path_raw(new_dentry, path, sizeof(path) - 1);
	if (IS_ERR(buf)) {
		pr_err("dentry_path_raw failed.\n");
		return;
	}

	if (!strstr(buf, "/system/packages.list"))
		return;

	pr_info("renameat: %s -> %s, new path: %s\n", old_dentry->d_iname, new_dentry->d_iname, buf);
	track_throne(false);
	return;
}
