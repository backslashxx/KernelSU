#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/kernel.h>
#include <linux/binfmts.h>

#ifdef CONFIG_KSU_LSM_SECURITY_HOOKS
#include <linux/lsm_hooks.h>
#endif

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
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)) && !defined(KSU_HAS_PATH_UMOUNT) 
#include <linux/syscalls.h> // sys_umount
#endif

#include "allowlist.h"
#include "core_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "ksud.h"
#include "manager.h"
#include "selinux/selinux.h"
#include "throne_tracker.h"
#include "throne_tracker.h"
#include "kernel_compat.h"

#ifdef CONFIG_KSU_LSM_SECURITY_HOOKS
#define LSM_HANDLER_TYPE static int
#else
#define LSM_HANDLER_TYPE int
#endif

static bool ksu_module_mounted = false;
static unsigned int ksu_unmountable_count = 0;

extern int handle_sepolicy(unsigned long arg3, void __user *arg4);

static bool ksu_su_compat_enabled = true;
extern void ksu_sucompat_init();
extern void ksu_sucompat_exit();

#ifdef CONFIG_KSU_KPROBES_KSUD
extern void unregister_kprobe_thread();
#else
void unregister_kprobe_thread() {}
#endif

// extras.c
static bool ksu_avc_spoof_enabled = true;
#ifdef CONFIG_KSU_EXTRAS
extern void avc_spoof_init();
extern void avc_spoof_exit();
#else
void avc_spoof_init() { pr_info("%s: feature not implemented!\n", __func__); }
void avc_spoof_exit() { pr_info("%s: feature not implemented!\n", __func__); }
#endif

static inline bool is_allow_su()
{
	if (is_manager()) {
		// we are manager, allow!
		return true;
	}
	return ksu_is_allow_uid(current_uid().val);
}

static inline bool is_unsupported_app_uid(uid_t uid)
{
#define LAST_APPLICATION_UID 19999
	uid_t appid = uid % 100000;
	return appid > LAST_APPLICATION_UID;
}

static struct group_info root_groups = { .usage = ATOMIC_INIT(2) };

static void setup_groups(struct root_profile *profile, struct cred *cred)
{
	if (profile->groups_count > KSU_MAX_GROUPS) {
		pr_warn("Failed to setgroups, too large group: %d!\n",
			profile->uid);
		return;
	}

	if (profile->groups_count == 1 && profile->groups[0] == 0) {
		// setgroup to root and return early.
		if (cred->group_info)
			put_group_info(cred->group_info);
		cred->group_info = get_group_info(&root_groups);
		return;
	}

	u32 ngroups = profile->groups_count;
	struct group_info *group_info = groups_alloc(ngroups);
	if (!group_info) {
		pr_warn("Failed to setgroups, ENOMEM for: %d\n", profile->uid);
		return;
	}

	int i;
	for (i = 0; i < ngroups; i++) {
		gid_t gid = profile->groups[i];
		kgid_t kgid = make_kgid(current_user_ns(), gid);
		if (!gid_valid(kgid)) {
			pr_warn("Failed to setgroups, invalid gid: %d\n", gid);
			put_group_info(group_info);
			return;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
		group_info->gid[i] = kgid;
#else
		GROUP_AT(group_info, i) = kgid;
#endif
	}

	groups_sort(group_info);
	set_groups(cred, group_info);
	put_group_info(group_info);
}

static void disable_seccomp()
{
	assert_spin_locked(&current->sighand->siglock);
	// disable seccomp
#if defined(CONFIG_GENERIC_ENTRY) &&                                           \
	LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	clear_syscall_work(SECCOMP);
#else
	clear_thread_flag(TIF_SECCOMP);
#endif

#ifdef CONFIG_SECCOMP
	current->seccomp.mode = 0;
	current->seccomp.filter = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	atomic_set(&current->seccomp.filter_count, 0);
#endif
#endif
}

void escape_to_root(void)
{
	struct cred *cred;

	if (current_euid().val == 0) {
		pr_warn("Already root, don't escape!\n");
		return;
	}

	cred = prepare_creds();
	if (!cred) {
		pr_warn("prepare_creds failed!\n");
		return;
	}

	struct root_profile *profile = ksu_get_root_profile(cred->uid.val);

	cred->uid.val = profile->uid;
	cred->suid.val = profile->uid;
	cred->euid.val = profile->uid;
	cred->fsuid.val = profile->uid;

	cred->gid.val = profile->gid;
	cred->fsgid.val = profile->gid;
	cred->sgid.val = profile->gid;
	cred->egid.val = profile->gid;
	cred->securebits = 0;

	BUILD_BUG_ON(sizeof(profile->capabilities.effective) !=
		     sizeof(kernel_cap_t));

	// setup capabilities
	// we need CAP_DAC_READ_SEARCH becuase `/data/adb/ksud` is not accessible for non root process
	// we add it here but don't add it to cap_inhertiable, it would be dropped automaticly after exec!
	u64 cap_for_ksud =
		profile->capabilities.effective | CAP_DAC_READ_SEARCH;
	memcpy(&cred->cap_effective, &cap_for_ksud,
	       sizeof(cred->cap_effective));
	memcpy(&cred->cap_permitted, &profile->capabilities.effective,
	       sizeof(cred->cap_permitted));
	memcpy(&cred->cap_bset, &profile->capabilities.effective,
	       sizeof(cred->cap_bset));

	setup_groups(profile, cred);

	commit_creds(cred);

	// Refer to kernel/seccomp.c: seccomp_set_mode_strict
	// When disabling Seccomp, ensure that current->sighand->siglock is held during the operation.
	spin_lock_irq(&current->sighand->siglock);
	disable_seccomp();
	spin_unlock_irq(&current->sighand->siglock);

	setup_selinux(profile->selinux_domain);
}

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

	track_throne();

	return 0;
}

#if defined(CONFIG_EXT4_FS) && ( LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) || defined(KSU_HAS_MODERN_EXT4) )
static void nuke_ext4_sysfs(const char *custompath) {
	struct path path;
	int err = kern_path(custompath, 0, &path);
	if (err) {
		pr_err("nuke path err: %d\n", err);
		return;
	}

	struct super_block* sb = path.dentry->d_inode->i_sb;
	const char* name = sb->s_type->name;
	if (strcmp(name, "ext4") != 0) {
		pr_info("%s: nuke but nothing mounted\n", __func__);
		path_put(&path);
		return;
	}
	
	// char	s_id[32]; /* Informational name */
	pr_info("%s: node: %s - path %s\n", __func__, sb->s_id, custompath);
	ext4_unregister_sysfs(sb);
	path_put(&path);
}
#else
static void nuke_ext4_sysfs(const char *custompath) {
	pr_info("%s: feature not implemented!\n", __func__);
}
#endif

struct mount_entry {
    char *umountable;
    struct list_head list;
};
LIST_HEAD(mount_list);

LSM_HANDLER_TYPE ksu_handle_prctl(int option, unsigned long arg2, unsigned long arg3,
		     unsigned long arg4, unsigned long arg5)
{
	// if success, we modify the arg5 as result!
	u32 *result = (u32 *)arg5;
	u32 reply_ok = KERNEL_SU_OPTION;
	uid_t current_uid_val = current_uid().val;

	// skip this private space support if uid below 100k
	if (current_uid_val < 100000)
		goto skip_check;

	uid_t manager_uid = ksu_get_manager_uid();
	if (current_uid_val != manager_uid && 
		current_uid_val % 100000 == manager_uid) {
			ksu_set_manager_uid(current_uid_val);
	}

skip_check:
	// yes this causes delay, but this keeps the delay consistent, which is what we want
	// with a barrier for safety as the compiler might try to do something smart.
	DONT_GET_SMART();
	if (!is_allow_su())
		return 0;

	// we move it after uid check here so they cannot
	// compare 0xdeadbeef call to a non-0xdeadbeef call
	if (KERNEL_SU_OPTION != option)
		return 0;

#ifdef CONFIG_KSU_DEBUG
	pr_info("option: 0x%x, cmd: %ld\n", option, arg2);
#endif

	if (arg2 == CMD_GRANT_ROOT) {
		pr_info("allow root for: %d\n", current_uid().val);
		escape_to_root();
		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("grant_root: prctl reply error\n");
		}
		return 0;
	}

	if (arg2 == CMD_ENABLE_SU) {
		bool enabled = (arg3 != 0);
		if (enabled == ksu_su_compat_enabled) {
			pr_info("cmd enable su but no need to change.\n");
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {// return the reply_ok directly
				pr_err("prctl reply error, cmd: %lu\n", arg2);
			}
			return 0;
		}

		if (enabled) {
			ksu_sucompat_init();
		} else {
			ksu_sucompat_exit();
		}
		ksu_su_compat_enabled = enabled;

		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		return 0;
	}

	// just continue old logic
	bool from_root = !current_uid().val;
	bool from_manager = is_manager();

	if (!from_root && !from_manager) {
		// only root or manager can access this interface
		return 0;
	}

	if (arg2 == CMD_WIPE_UMOUNT_LIST) {
		struct mount_entry *entry, *tmp;
		list_for_each_entry_safe(entry, tmp, &mount_list, list) {
			pr_info("wipe_umount_list: removing entry: %s\n", entry->umountable);
			list_del(&entry->list);
			kfree(entry->umountable);
			kfree(entry);
        	}
		ksu_unmountable_count = 0;

		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		return 0;
	}

	if (arg2 == CMD_ADD_TRY_UMOUNT) {
		struct mount_entry *new_entry, *entry;
		char buf[384];

		if (copy_from_user(buf, (const char __user *)arg3, sizeof(buf) - 1)) {
			pr_err("cmd_add_try_umount: failed to copy user string\n");
			return 0;
		}
		buf[384 - 1] = '\0';

		new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
		if (!new_entry)
			return 0;

		new_entry->umountable = kstrdup(buf, GFP_KERNEL);
		if (!new_entry->umountable) {
			kfree(new_entry);
			return 0;
		}

		// disallow dupes
		// if this gets too many, we can consider moving this whole task to a kthread
		list_for_each_entry(entry, &mount_list, list) {
			if (!strcmp(entry->umountable, buf)) {
				pr_info("cmd_add_try_umount: %s is already here!\n", buf);
				kfree(new_entry->umountable);
				kfree(new_entry);
				return 0;
			}	
		}	

		// debug
		// pr_info("cmd_add_try_umount: %s added!\n", buf);
		list_add(&new_entry->list, &mount_list);
		ksu_unmountable_count++;

		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		return 0;
	}

	if (arg2 == CMD_NUKE_EXT4_SYSFS) {
		char buf[384];

		if (copy_from_user(buf, (const char __user *)arg3, sizeof(buf) - 1)) {
			pr_err("cmd_nuke_ext4_sysfs: failed to copy user string\n");
			return 0;
		}
		buf[384 - 1] = '\0';

		nuke_ext4_sysfs(buf);

		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		return 0;
	}

	if (arg2 == CMD_TOGGLE_AVC_SPOOF) {

		pr_info("toggle_avc_spoof, cmd: %lu subcmd: %lu\n", arg2, arg3);

		if (arg3 == 0) {
			avc_spoof_exit();
			ksu_avc_spoof_enabled = false;
		}

		if (arg3 == 1) {
			avc_spoof_init();
			ksu_avc_spoof_enabled = true;
		}


		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		return 0;
	}

	if (arg2 == CMD_BECOME_MANAGER) {
		if (from_manager) {
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("become_manager: prctl reply error\n");
			}
			return 0;
		}
		return 0;
	}

	// Both root manager and root processes should be allowed to get version
	if (arg2 == CMD_GET_VERSION) {
		u32 version = KERNEL_SU_VERSION;
		if (copy_to_user(arg3, &version, sizeof(version))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		u32 version_flags = 0;
		if (arg4 &&
		    copy_to_user(arg4, &version_flags, sizeof(version_flags))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		return 0;
	}

	if (arg2 == CMD_REPORT_EVENT) {
		if (!from_root) {
			return 0;
		}
		switch (arg3) {
		case EVENT_POST_FS_DATA: {
			static bool post_fs_data_lock = false;
			if (!post_fs_data_lock) {
				post_fs_data_lock = true;
				pr_info("post-fs-data triggered\n");
				on_post_fs_data();
			}
			break;
		}
		case EVENT_BOOT_COMPLETED: {
			static bool boot_complete_lock = false;
			if (!boot_complete_lock) {
				boot_complete_lock = true;
				pr_info("boot_complete triggered\n");
				unregister_kprobe_thread();
				avc_spoof_init(); 
			}
			break;
		}
		case EVENT_MODULE_MOUNTED: {
			ksu_module_mounted = true;
			pr_info("module mounted!\n");
			nuke_ext4_sysfs("/data/adb/modules");
			break;
		}
		default:
			break;
		}
		return 0;
	}

	if (arg2 == CMD_SET_SEPOLICY) {
		if (!from_root) {
			return 0;
		}
		if (!handle_sepolicy(arg3, arg4)) {
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("sepolicy: prctl reply error\n");
			}
		}

		return 0;
	}

	if (arg2 == CMD_CHECK_SAFEMODE) {
		if (ksu_is_safe_mode()) {
			pr_warn("safemode enabled!\n");
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("safemode: prctl reply error\n");
			}
		}
		return 0;
	}

	if (arg2 == CMD_GET_ALLOW_LIST || arg2 == CMD_GET_DENY_LIST) {
		u32 array[128];
		u32 array_length;
		bool success = ksu_get_allow_list(array, &array_length,
						  arg2 == CMD_GET_ALLOW_LIST);
		if (success) {
			if (!copy_to_user(arg4, &array_length,
					  sizeof(array_length)) &&
			    !copy_to_user(arg3, array,
					  sizeof(u32) * array_length)) {
				if (copy_to_user(result, &reply_ok,
						 sizeof(reply_ok))) {
					pr_err("prctl reply error, cmd: %lu\n",
					       arg2);
				}
			} else {
				pr_err("prctl copy allowlist error\n");
			}
		}
		return 0;
	}

	if (arg2 == CMD_UID_GRANTED_ROOT || arg2 == CMD_UID_SHOULD_UMOUNT) {
		uid_t target_uid = (uid_t)arg3;
		bool allow = false;
		if (arg2 == CMD_UID_GRANTED_ROOT) {
			allow = ksu_is_allow_uid(target_uid);
		} else if (arg2 == CMD_UID_SHOULD_UMOUNT) {
			allow = ksu_uid_should_umount(target_uid);
		} else {
			pr_err("unknown cmd: %lu\n", arg2);
		}
		if (!copy_to_user(arg4, &allow, sizeof(allow))) {
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("prctl reply error, cmd: %lu\n", arg2);
			}
		} else {
			pr_err("prctl copy err, cmd: %lu\n", arg2);
		}
		return 0;
	}

	if (arg2 == CMD_GET_MANAGER_UID) {
		uid_t manager_uid = ksu_get_manager_uid();
		if (copy_to_user(arg3, &manager_uid, sizeof(manager_uid))) {
			pr_err("get manager uid failed\n");
		}
		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		return 0;
	}

	// all other cmds are for 'root manager'
	if (!from_manager) {
		return 0;
	}

	// we are already manager
	if (arg2 == CMD_GET_APP_PROFILE) {
		struct app_profile profile;
		if (copy_from_user(&profile, arg3, sizeof(profile))) {
			pr_err("copy profile failed\n");
			return 0;
		}

		bool success = ksu_get_app_profile(&profile);
		if (success) {
			if (copy_to_user(arg3, &profile, sizeof(profile))) {
				pr_err("copy profile failed\n");
				return 0;
			}
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("prctl reply error, cmd: %lu\n", arg2);
			}
		}
		return 0;
	}

	if (arg2 == CMD_SET_APP_PROFILE) {
		struct app_profile profile;
		if (copy_from_user(&profile, arg3, sizeof(profile))) {
			pr_err("copy profile failed\n");
			return 0;
		}

		// todo: validate the params
		if (ksu_set_app_profile(&profile, true)) {
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("prctl reply error, cmd: %lu\n", arg2);
			}
		}
		return 0;
	}

	if (arg2 == CMD_IS_SU_ENABLED) {
		if (copy_to_user(arg3, &ksu_su_compat_enabled,
				 sizeof(ksu_su_compat_enabled))) {
			pr_err("copy su compat failed\n");
			return 0;
		}
		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		return 0;
	}

	if (arg2 == CMD_IS_AVC_SPOOF_ENABLED) {
		if (copy_to_user(arg3, &ksu_avc_spoof_enabled, sizeof(ksu_avc_spoof_enabled))) {
			pr_err("copy avc spoof failed\n");
			return 0;
		}

		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		return 0;
	}

	return 0;
}

static bool is_non_appuid(kuid_t uid)
{
#define PER_USER_RANGE 100000
#define FIRST_APPLICATION_UID 10000

	uid_t appid = uid.val % PER_USER_RANGE;
	return appid < FIRST_APPLICATION_UID;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0) || defined(KSU_HAS_PATH_UMOUNT)
static void ksu_path_umount(const char *mnt, struct path *path, int flags)
{
	int err = path_umount(path, flags);
	pr_info("%s: path: %s code: %d\n", __func__, mnt, err);
}
#else
static void ksu_sys_umount(const char *mnt, int flags)
{
	char __user *usermnt = (char __user *)mnt;

	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	int ret = ksys_umount(usermnt, flags);
#else
	long ret = sys_umount(usermnt, flags); // cuz asmlinkage long sys##name
#endif
	set_fs(old_fs);
	pr_info("%s: path: %s code: %d \n", __func__, mnt, ret);
}
#endif // KSU_HAS_PATH_UMOUNT

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0) || defined(KSU_HAS_PATH_UMOUNT)
	ksu_path_umount(mnt, &path, flags);
	// dont call path_put here!!
	// path_umount releases ref for us
#else
	ksu_sys_umount(mnt, flags);
	// release ref here! user_path_at increases it
	// then only cleans for itself
	path_put(&path);
#endif
}

LSM_HANDLER_TYPE ksu_handle_setuid(struct cred *new, const struct cred *old)
{
	struct mount_entry *entry;

	// this hook is used for umounting overlayfs for some uid, if there isn't any module mounted, just ignore it!
	if (!ksu_module_mounted) {
		return 0;
	}

	// we dont need to unmount if theres no unmountable
	if (!ksu_unmountable_count)
		return 0;

	if (!new || !old) {
		return 0;
	}

	kuid_t new_uid = new->uid;
	kuid_t old_uid = old->uid;

	if (0 != old_uid.val) {
		// old process is not root, ignore it.
		return 0;
	}

	if (is_non_appuid(new_uid)) {
#ifdef CONFIG_KSU_DEBUG
		pr_info("handle setuid ignore non application uid: %d\n", new_uid.val);
#endif
		return 0;
	}

	// isolated process may be directly forked from zygote, always unmount
	if (is_unsupported_app_uid(new_uid.val)) {
#ifdef CONFIG_KSU_DEBUG
		pr_info("handle umount for unsupported application uid: %d\n", new_uid.val);
#endif
		goto do_umount;
	}

	if (ksu_is_allow_uid(new_uid.val)) {
#ifdef CONFIG_KSU_DEBUG
		pr_info("handle setuid ignore allowed application: %d\n", new_uid.val);
#endif
		return 0;
	}

	if (!ksu_uid_should_umount(new_uid.val)) {
		return 0;
	} else {
#ifdef CONFIG_KSU_DEBUG
		pr_info("uid: %d should not umount!\n", current_uid().val);
#endif
	}

do_umount:
	// check old process's selinux context, if it is not zygote, ignore it!
	// because some su apps may setuid to untrusted_app but they are in global mount namespace
	// when we umount for such process, that is a disaster!
	if (!is_zygote(old->security)) {
		pr_info("handle umount ignore non zygote child: %d\n",
			current->pid);
		return 0;
	}

	// umount the target mnt
	pr_info("handle umount for uid: %d, pid: %d\n", new_uid.val,
		current->pid);

	// don't free! keep on heap! this is used on subsequent setuid calls
	// if this is freed, we dont have anything to umount next
	list_for_each_entry(entry, &mount_list, list)
		try_umount(entry->umountable, MNT_DETACH);

	return 0;
}

LSM_HANDLER_TYPE ksu_sb_mount(const char *dev_name, const struct path *path,
                        const char *type, unsigned long flags, void *data)
{
	return 0;
}

LSM_HANDLER_TYPE ksu_inode_permission(struct inode *inode, int mask)
{
	return 0;
}

#ifdef CONFIG_COMPAT
extern bool ksu_is_compat __read_mostly;
#endif

LSM_HANDLER_TYPE ksu_bprm_check(struct linux_binprm *bprm)
{
	char *filename = (char *)bprm->filename;
	
	if (likely(!ksu_execveat_hook))
		return 0;

#ifdef CONFIG_COMPAT
	static bool compat_check_done __read_mostly = false;
	if ( unlikely(!compat_check_done) && unlikely(!strcmp(filename, "/data/adb/ksud"))
		&& !memcmp(bprm->buf, "\x7f\x45\x4c\x46", 4) ) {
		if (bprm->buf[4] == 0x01 )
			ksu_is_compat = true;

		pr_info("%s: %s ELF magic found! ksu_is_compat: %d \n", __func__, filename, ksu_is_compat);
		compat_check_done = true;
	}
#endif

	ksu_handle_pre_ksud(filename);

	return 0;

}

// kernel 4.9 and older
#ifndef CONFIG_KSU_KPROBES_KSUD
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
LSM_HANDLER_TYPE ksu_key_permission(key_ref_t key_ref, const struct cred *cred,
			      unsigned perm)
{
	if (init_session_keyring != NULL) {
		return 0;
	}
	if (strcmp(current->comm, "init")) {
		// we are only interested in `init` process
		return 0;
	}
	init_session_keyring = cred->session_keyring;
	pr_info("kernel_compat: got init_session_keyring\n");
	return 0;
}
#endif
#endif // CONFIG_KSU_KPROBES_KSUD

#ifdef CONFIG_KSU_LSM_SECURITY_HOOKS
static int ksu_task_prctl(int option, unsigned long arg2, unsigned long arg3,
			  unsigned long arg4, unsigned long arg5)
{
	ksu_handle_prctl(option, arg2, arg3, arg4, arg5);
	return -ENOSYS;
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

static struct security_hook_list ksu_hooks[] = {
	LSM_HOOK_INIT(task_prctl, ksu_task_prctl),
	LSM_HOOK_INIT(inode_rename, ksu_inode_rename),
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
	LSM_HOOK_INIT(bprm_check_security, ksu_bprm_check),
#ifndef CONFIG_KSU_KPROBES_KSUD
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
	LSM_HOOK_INIT(key_permission, ksu_key_permission)
#endif
#endif // CONFIG_KSU_KPROBES_KSUD
};

void __init ksu_lsm_hook_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
#else
	// https://elixir.bootlin.com/linux/v4.10.17/source/include/linux/lsm_hooks.h#L1892
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
#endif
}

void __init ksu_core_init(void)
{
	ksu_lsm_hook_init();
}
#else
void __init ksu_core_init(void)
{
	pr_info("ksu_core_init: LSM hooks not in use.\n");
}
#endif //CONFIG_KSU_LSM_SECURITY_HOOKS
