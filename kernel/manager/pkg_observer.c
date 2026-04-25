/**
 * ! this is on inode_rename, NOT fsnotify
 * we have access to LSM and overhead is way lower.
 * we watch one file, check ifs on the same parent inode.
 * a few int compare and a ptr compare. thats it.
 * as for throne tracker, we just async it by hand
 * by offloading it to a kthread.
 */

static uintptr_t system_dir_inode_ptr = NULL;

__attribute__((cold))
static noinline void ksu_grab_data_system_inode()
{
	struct path path;
	int ret = kern_path("/data/system", LOOKUP_FOLLOW, &path);
	if (ret) {
		pr_info("renameat: /data/system not ready? ret: (%d)\n", ret);
		return;
	}

	system_dir_inode_ptr = (uintptr_t)d_inode(path.dentry);
	pr_info("renameat: cached /data/system d_inode: 0x%lx\n", system_dir_inode_ptr);
	path_put(&path);
}

static inline void ksu_rename_observer(struct dentry *old_dentry, struct dentry *new_dentry)
{
	// skip kernel threads
	if (!current->mm)
		return;

	if (!old_dentry || !new_dentry)
		return;

	// skip non system uid
	if (likely(current_uid().val != 1000))
		return;

	// HASH_LEN_DECLARE see dcache.h
	if (likely(new_dentry->d_name.len != sizeof("packages.list") - 1  ))
		return;

	// /data/system/packages.list.tmp -> /data/system/packages.list
	if (likely(!!__builtin_memcmp(new_dentry->d_iname, "packages.list", sizeof("packages.list") - 1 )))
		return;

	// cache dir inode, we try to go for fast path, lockless
	if (unlikely(!system_dir_inode_ptr))
		ksu_grab_data_system_inode();

	if (unlikely(!system_dir_inode_ptr))
		goto slow_path;

	if (unlikely(!new_dentry->d_parent || !new_dentry->d_parent->d_inode))
		goto slow_path;

	/*
	 * fallback to slow path, but this should NOT change unless someone overlays /data/system
	 * but then again maybe https://github.com/tiann/KernelSU/pull/2633#discussion_r2141740346
	 * but /data is casefolded, overlaying is really really unlikely
	 * we self heal this thing, so on enxt run, it will try to grab d inode again
	 * alternatively we can use packages.list inode change as trigger too, however,
	 * we need to save last state. more writes.
	 */
	if (unlikely((uintptr_t)new_dentry->d_parent->d_inode != system_dir_inode_ptr))
		goto slow_path;

	pr_info("renameat: %s -> %s, /data/system d_inode: 0x%lx \n", old_dentry->d_iname, new_dentry->d_iname, system_dir_inode_ptr);
	track_throne(false);
	return;

slow_path:
	system_dir_inode_ptr = NULL; // reset cached inode

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
