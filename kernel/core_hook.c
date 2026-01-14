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
#include <linux/binfmts.h>
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
#include <linux/syscalls.h> // sys_umount

#ifdef CONFIG_KSU_LSM_SECURITY_HOOKS
#define LSM_HANDLER_TYPE static int
#else
#define LSM_HANDLER_TYPE int
#endif

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

LSM_HANDLER_TYPE ksu_handle_rename(struct dentry *old_dentry, struct dentry *new_dentry)
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
__weak int path_umount(struct path *path, int flags)
{
	char buf[256] = {0};
	int ret;

	// -1 on the size as implicit null termination
	// as we zero init the thing
	char *usermnt = d_path(path, buf, sizeof(buf) - 1);
	if (!(usermnt && usermnt != buf)) {
		ret = -ENOENT;
		goto out;
	}

	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	ret = ksys_umount((char __user *)usermnt, flags);
#else
	ret = (int)sys_umount((char __user *)usermnt, flags);
#endif

	set_fs(old_fs);

	// release ref here! user_path_at increases it
	// then only cleans for itself
out:
	path_put(path); 
	return ret;
}
#endif

static void ksu_umount_mnt(const char *mnt, struct path *path, int flags)
{
	int err = path_umount(path, flags);

	// upstream actually has a UAF here: path->dentry after dput
	// but its fine as umount always succeeds
	// that code path is very cold
	if (err)
		pr_info("umount %s failed: %d\n", mnt, err);
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

	ksu_umount_mnt(mnt, &path, flags);
}

LSM_HANDLER_TYPE ksu_handle_setuid(struct cred *new, const struct cred *old)
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
	// lets just do original thing where we disable seccomp
	if (likely(ksu_is_manager_appid_valid()) && unlikely(ksu_get_manager_appid() == new_uid % PER_USER_RANGE)) {
		disable_seccomp();
		pr_info("install fd for: %d\n", new_uid);
		ksu_install_fd(); // install fd for ksu manager
	}

	if (unlikely(ksu_is_allow_uid_for_current(new_uid))) {
		disable_seccomp();
		return 0;
	}

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
static void ksu_grab_init_session_keyring(const char *filename);
#endif

LSM_HANDLER_TYPE ksu_bprm_check(struct linux_binprm *bprm)
{
	if (likely(!ksu_execveat_hook))
		return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
	ksu_grab_init_session_keyring((const char *)bprm->filename);
#endif

	ksu_handle_pre_ksud((char *)bprm->filename);

	return 0;
}

bool ksu_vfs_read_hook __read_mostly;
static void ksu_handle_initrc(struct file *file);

LSM_HANDLER_TYPE ksu_file_permission(struct file *file, int mask)
{
	if (!ksu_vfs_read_hook)
		return 0;

	ksu_handle_initrc(file);

	return 0;
}

#ifdef CONFIG_KSU_LSM_SECURITY_HOOKS
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
#include <linux/lsm_hooks.h>
static struct security_hook_list ksu_hooks[] = {
	LSM_HOOK_INIT(inode_rename, ksu_inode_rename),
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
	LSM_HOOK_INIT(bprm_check_security, ksu_bprm_check),
	LSM_HOOK_INIT(file_permission, ksu_file_permission),
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
#endif //  < 4.11

#else // 4.2

// selinux_ops (LSM), security_operations struct tampering for ultra legacy

extern struct security_operations selinux_ops;

static int (*orig_inode_rename) (struct inode *old_dir, struct dentry *old_dentry,
			     struct inode *new_dir, struct dentry *new_dentry);
static int hook_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			    struct inode *new_inode, struct dentry *new_dentry)
{
	ksu_inode_rename(old_inode, old_dentry, new_inode, new_dentry);
	return orig_inode_rename(old_inode, old_dentry, new_inode, new_dentry);
}

static int (*orig_task_fix_setuid) (struct cred *new, const struct cred *old, int flags);
static int hook_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	ksu_task_fix_setuid(new, old, flags);
	return orig_task_fix_setuid(new, old, flags);
}

static int (*orig_bprm_check_security)(struct linux_binprm *bprm);
static int hook_bprm_check_security(struct linux_binprm *bprm)
{
	ksu_bprm_check(bprm);
	return orig_bprm_check_security(bprm);
}

static int (*orig_file_permission) (struct file *file, int mask);
static int hook_file_permission(struct file *file, int mask)
{

	ksu_file_permission(file, mask);
	return orig_file_permission(file, mask);
}

static void ksu_lsm_hook_restore(void)
{
	struct security_operations *ops = (struct security_operations *)&selinux_ops;

	if (!ops)
		return;

	if (!!strcmp((char *)ops, "selinux"))
		return;

	// TODO: maybe hunt for this in memory instead of exporting
	// this is the first member of the struct so it points to the struct
	pr_info("%s: selinux_ops: 0x%lx .name = %s\n", __func__, (long)ops, (const char *)ops );

	preempt_disable();

	if (orig_bprm_check_security) {
		pr_info("%s: restoring: 0x%lx to 0x%lx\n", __func__, (long)ops->bprm_check_security, (long)orig_bprm_check_security);
		ops->bprm_check_security = orig_bprm_check_security;
	}

	if (orig_file_permission) {
		pr_info("%s: restoring: 0x%lx to 0x%lx\n", __func__, (long)ops->file_permission, (long)orig_file_permission);
		ops->file_permission = orig_file_permission;
	}

	preempt_enable();
	
	smp_mb();
	return;
}

static struct task_struct *unhook_thread;

static int execveat_hook_wait_fn(void *data)
{
loop_start:

	msleep(1000);

	if ((volatile bool)ksu_execveat_hook)
		goto loop_start;

	ksu_lsm_hook_restore();

	return 0;
}

static void execveat_hook_wait_thread()
{
	unhook_thread = kthread_run(execveat_hook_wait_fn, NULL, "unhook");
	if (IS_ERR(unhook_thread)) {
		unhook_thread = NULL;
		return;
	}
}

static void ksu_lsm_hook_init(void)
{
	struct security_operations *ops = (struct security_operations *)&selinux_ops;

	if (!ops)
		return;

	if (!!strcmp((char *)ops, "selinux"))
		return;

	// TODO: maybe hunt for this in memory instead of exporting
	// this is the first member of the struct so it points to the struct
	pr_info("%s: selinux_ops: 0x%lx .name = %s\n", __func__, (long)ops, (const char *)ops );

	preempt_disable();

	orig_inode_rename = ops->inode_rename;
	ops->inode_rename = hook_inode_rename;

	orig_task_fix_setuid = ops->task_fix_setuid;
	ops->task_fix_setuid = hook_task_fix_setuid;

	orig_bprm_check_security = ops->bprm_check_security;
	ops->bprm_check_security = hook_bprm_check_security;

	orig_file_permission = ops->file_permission;
	ops->file_permission = hook_file_permission;

	preempt_enable();
	
	smp_mb();

	execveat_hook_wait_thread();
	return;
}

#endif // < 4.2

#else
void __init ksu_lsm_hook_init(void)
{
	// nothing, no-op
}
#endif // CONFIG_KSU_LSM_SECURITY_HOOKS

void __init ksu_core_init(void)
{
	ksu_lsm_hook_init();
	if (ksu_register_feature_handler(&kernel_umount_handler)) {
		pr_err("Failed to register kernel_umount feature handler\n");
	}
}
