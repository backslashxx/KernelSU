#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/stddef.h>
#include <linux/lsm_hooks.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/namei.h>

static bool ksu_kernel_umount_enabled = true;

static int kernel_umount_feature_get(u64 *value)
{
	*value = ksu_kernel_umount_enabled ? 1 : 0;
	return 0;
}

static int kernel_umount_feature_set(u64 value)
{
	bool enable = value != 0;
	ksu_kernel_umount_enabled = enable;
	pr_info("kernel_umount: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler kernel_umount_handler = {
	.feature_id = KSU_FEATURE_KERNEL_UMOUNT,
	.name = "kernel_umount",
	.get_handler = kernel_umount_feature_get,
	.set_handler = kernel_umount_feature_set,
};

int ksu_handle_rename(struct dentry *old_dentry, struct dentry *new_dentry)
{
	if (!current->mm) {
		// skip kernel threads
		return 0;
	}

	if (current_uid().val != 1000) {
		// skip non system uid
		return 0;
	}

	if (!old_dentry || !new_dentry) {
		return 0;
	}

	// /data/system/packages.list.tmp -> /data/system/packages.list
	if (strcmp(new_dentry->d_iname, "packages.list")) {
		return 0;
	}

	char path[128];
	char *buf = dentry_path_raw(new_dentry, path, sizeof(path));
	if (IS_ERR(buf)) {
		pr_err("dentry_path_raw failed.\n");
		return 0;
	}

	if (!strstr(buf, "/system/packages.list")) {
		return 0;
	}
	pr_info("renameat: %s -> %s, new path: %s\n", old_dentry->d_iname,
		new_dentry->d_iname, buf);

	track_throne(false);

	return 0;
}

static void ksu_umount_mnt(struct path *path, int flags)
{
	int err = path_umount(path, flags);
	if (err) {
		pr_info("umount %s failed: %d\n", path->dentry->d_iname, err);
	}
}

static void try_umount(const char *mnt, int flags)
{
	struct path path;
	int err = kern_path(mnt, 0, &path);
	if (err) {
		return;
	}

	if (path.dentry != path.mnt->mnt_root) {
		// it is not root mountpoint, maybe umounted by others already.
		path_put(&path);
		return;
	}

	ksu_umount_mnt(&path, flags);
}

int ksu_handle_setuid(struct cred *new, const struct cred *old)
{
	if (!new || !old) {
		return 0;
	}

	uid_t new_uid = new->uid.val;
	uid_t old_uid = old->uid.val;

	// TODO: disable seccomp here!

	// if there isn't any module mounted, just ignore it!
	if (!ksu_module_mounted) {
		return 0;
	}

	if (!ksu_kernel_umount_enabled) {
		return 0;
	}

	if (!ksu_cred) {
		return 0;
	}

	// There are 5 scenarios:
	// 1. Normal app: zygote -> appuid
	// 2. Isolated process forked from zygote: zygote -> isolated_process
	// 3. App zygote forked from zygote: zygote -> appuid
	// 4. Isolated process froked from app zygote: appuid -> isolated_process (already handled by 3)
	// 5. Isolated process froked from webview zygote (no need to handle, app cannot run custom code)
	if (!is_appuid(new_uid) && !is_isolated_process(new_uid)) {
		return 0;
	}

	if (!ksu_uid_should_umount(new_uid) && !is_isolated_process(new_uid)) {
		return 0;
	}

	// check old process's selinux context, if it is not zygote, ignore it!
	// because some su apps may setuid to untrusted_app but they are in global mount namespace
	// when we umount for such process, that is a disaster!
	// also handle case 4 and 5
	bool is_zygote_child = is_zygote(old);
	if (!is_zygote_child) {
		pr_info("handle umount ignore non zygote child: %d\n", current->pid);
		return 0;
	}

	// umount the target mnt
	pr_info("handle umount for uid: %d, pid: %d\n", new_uid, current->pid);

	const struct cred *saved = override_creds(ksu_cred);

	struct mount_entry *entry;
	down_read(&mount_list_lock);
	list_for_each_entry(entry, &mount_list, list) {
		pr_info("%s: unmounting: %s flags 0x%x\n", __func__, entry->umountable, entry->flags);
		try_umount(entry->umountable, entry->flags);
	}
	up_read(&mount_list_lock);

	revert_creds(saved);

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
	if (ksu_register_feature_handler(&kernel_umount_handler)) {
		pr_err("Failed to register kernel_umount feature handler\n");
	}
}
