#include <asm/current.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/kthread.h>
#include <linux/input.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
#include <linux/input-event-codes.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#include <uapi/linux/input.h>
#else
#include <linux/input.h>
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
#include <linux/aio.h>
#endif
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/namei.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h> /* fatal_signal_pending */
#else
#include <linux/sched.h> /* fatal_signal_pending */
#endif
#include <linux/uio.h>

bool ksu_module_mounted __read_mostly = false;
bool ksu_boot_completed __read_mostly = false;

#ifdef CONFIG_KSU_EXTRAS
extern void ksu_avc_spoof_late_init();
#else
void ksu_avc_spoof_late_init() {}
#endif

static const char KERNEL_SU_RC[] =
	"\n"

	"on post-fs-data\n"
	"    start logd\n"
	// We should wait for the post-fs-data finish
	"    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " post-fs-data\n"
	"\n"

	"on nonencrypted\n"
	"    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " services\n"
	"\n"

	"on property:vold.decrypt=trigger_restart_framework\n"
	"    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " services\n"
	"\n"

	"on property:sys.boot_completed=1\n"
	"    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " boot-completed\n"
	"\n"

	"\n";

static void stop_vfs_read_hook();
static void stop_execve_hook();
static void stop_input_hook();

bool ksu_vfs_read_hook __read_mostly = true;
bool ksu_execveat_hook __read_mostly = true;
bool ksu_input_hook __read_mostly = true;

void on_post_fs_data(void)
{
	static bool done = false;
	if (done) {
		pr_info("on_post_fs_data already done\n");
		return;
	}
	done = true;
	pr_info("on_post_fs_data!\n");

	ksu_load_allow_list();
	// sanity check, this may influence the performance
	stop_input_hook();
}

#if defined(CONFIG_EXT4_FS) && ( LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) || defined(KSU_HAS_MODERN_EXT4) )
extern void ext4_unregister_sysfs(struct super_block *sb);
int nuke_ext4_sysfs(const char *mnt)
{
	struct path path;
	int err = kern_path(mnt, 0, &path);
	if (err) {
		pr_err("nuke path err: %d\n", err);
		return err;
	}

	struct super_block *sb = path.dentry->d_inode->i_sb;
	const char *name = sb->s_type->name;
	if (strcmp(name, "ext4") != 0) {
		pr_info("nuke but module aren't mounted\n");
		path_put(&path);
		return -EINVAL;
	}

	ext4_unregister_sysfs(sb);
	path_put(&path);
	return 0;
}
#else
int nuke_ext4_sysfs(const char* mnt) {
	pr_info("%s: feature not implemented!\n", __func__);
	return 0;
}
#endif

void on_module_mounted(void)
{
	pr_info("on_module_mounted!\n");
	ksu_module_mounted = true;
}

void on_boot_completed(void)
{
	ksu_boot_completed = true;
	pr_info("on_boot_completed!\n");
	track_throne(true);
	ksu_avc_spoof_late_init(); // slow_avc_init kp
}

// since _ksud handler only uses argv and envp for comparisons
// this can probably work
// adapted from ksu_handle_execveat_ksud
static int ksu_handle_bprm_ksud(const char *filename, const char *argv1, const char *envp, size_t envp_len)
{
	static const char app_process[] = "/system/bin/app_process";
	static bool first_app_process = true;

	/* This applies to versions Android 10+ */
	static const char system_bin_init[] = "/system/bin/init";
	/* This applies to versions between Android 6 ~ 9  */
	static const char old_system_init[] = "/init";
	static bool init_second_stage_executed = false;

	// return early when disabled
	if (!ksu_execveat_hook)
		return 0;

	if (!filename)
		return 0;

	// debug! remove me!
	pr_info("%s: filename: %s argv1: %s envp_len: %zu\n", __func__, filename, argv1, envp_len);

#ifdef CONFIG_KSU_DEBUG
	const char *envp_n = envp;
	unsigned int envc = 1;
	do {
		pr_info("%s: envp[%d]: %s\n", __func__, envc, envp_n);
		envp_n += strlen(envp_n) + 1;
		envc++;
	} while (envp_n < envp + 256);
#endif

	if (init_second_stage_executed)
		goto first_app_process;

	// /system/bin/init with argv1
	if (!strcmp(filename, system_bin_init) && argv1 && !strcmp(argv1, "second_stage")) {
		pr_info("%s: /system/bin/init second_stage executed\n", __func__);
		apply_kernelsu_rules();
		cache_sid();
		setup_ksu_cred();
		init_second_stage_executed = true;
	}

	// /init with argv1
	if (!strcmp(filename, old_system_init) && argv1 && !strcmp(argv1, "--second-stage")) {
		pr_info("%s: /init --second-stage executed\n", __func__);
		apply_kernelsu_rules();
		cache_sid();
		setup_ksu_cred();
		init_second_stage_executed = true;
	}

	if (!envp || !envp_len)
		goto first_app_process;

	// /init without argv1/useless-argv1 but usable envp
	// untested! TODO: test and debug me!
	if (!init_second_stage_executed && !strcmp(filename, old_system_init)) {

		// we hunt for "INIT_SECOND_STAGE"
		const char *envp_n = envp;
		unsigned int envc = 1;
		do {
			if (strstarts(envp_n, "INIT_SECOND_STAGE"))
				break;
			envp_n += strlen(envp_n) + 1;
			envc++;
		} while (envp_n < envp + envp_len);
		pr_info("%s: envp[%d]: %s\n", __func__, envc, envp_n);
		
		if (!strcmp(envp_n, "INIT_SECOND_STAGE=1")
			|| !strcmp(envp_n, "INIT_SECOND_STAGE=true") ) {
			pr_info("%s: /init +envp: INIT_SECOND_STAGE executed\n", __func__);
			apply_kernelsu_rules();
			cache_sid();
			setup_ksu_cred();
			init_second_stage_executed = true;
		}
	}

first_app_process:
	if (first_app_process && strstarts(filename, app_process)) {
		first_app_process = false;
		pr_info("%s: exec app_process, /data prepared, second_stage: %d\n", __func__, init_second_stage_executed);
		on_post_fs_data();
		stop_execve_hook();
	}

	return 0;
}

int ksu_handle_pre_ksud(const char *filename)
{
	if (likely(!ksu_execveat_hook))
		return 0;

	// not /system/bin/init, not /init, not /system/bin/app_process (64/32 thingy)
	// return 0;
	if (likely(strcmp(filename, "/system/bin/init") && strcmp(filename, "/init")
		&& !strstarts(filename, "/system/bin/app_process") ))
		return 0;

	if (!current || !current->mm)
		return 0;

	// https://elixir.bootlin.com/linux/v4.14.1/source/include/linux/mm_types.h#L429
	// unsigned long arg_start, arg_end, env_start, env_end;
	unsigned long arg_start = current->mm->arg_start;
	unsigned long arg_end = current->mm->arg_end;
	unsigned long env_start = current->mm->env_start;
	unsigned long env_end = current->mm->env_end;

	size_t arg_len = arg_end - arg_start;
	size_t envp_len = env_end - env_start;

	if (arg_len <= 0 || envp_len <= 0) // this wont make sense, filter it
		return 0;

#define ARGV_MAX 32 
#define ENVP_MAX 256
	char args[ARGV_MAX];
	char envp[ENVP_MAX];
	size_t argv_copy_len = (arg_len > ARGV_MAX) ? ARGV_MAX : arg_len;
	size_t envp_copy_len = (envp_len > ENVP_MAX) ? ENVP_MAX : envp_len;

	// we cant use strncpy on here, else it will truncate once it sees \0
	if (ksu_copy_from_user_retry(args, (void __user *)arg_start, argv_copy_len))
		return 0;

	if (ksu_copy_from_user_retry(envp, (void __user *)env_start, envp_copy_len))
		return 0;

	args[ARGV_MAX - 1] = '\0';
	envp[ENVP_MAX - 1] = '\0';

	// we only need argv1 !
	char *argv1 = args + strlen(args) + 1;
	if (argv1 >= args + argv_copy_len) // out of bounds!
		argv1 = "";

	return ksu_handle_bprm_ksud(filename, argv1, envp, envp_copy_len);
}

static ssize_t (*orig_read)(struct file *, char __user *, size_t, loff_t *);
static ssize_t (*orig_read_iter)(struct kiocb *, struct iov_iter *);
static struct file_operations fops_proxy;
static ssize_t ksu_rc_pos = 0;
const size_t ksu_rc_len = sizeof(KERNEL_SU_RC) - 1;

// https://cs.android.com/android/platform/superproject/main/+/main:system/core/init/parser.cpp;l=144;drc=61197364367c9e404c7da6900658f1b16c42d0da
// https://cs.android.com/android/platform/superproject/main/+/main:system/libbase/file.cpp;l=241-243;drc=61197364367c9e404c7da6900658f1b16c42d0da
// The system will read init.rc file until EOF, whenever read() returns 0,
// so we begin append ksu rc when we meet EOF.

static ssize_t read_proxy(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret = 0;
	size_t append_count;
	if (ksu_rc_pos && ksu_rc_pos < ksu_rc_len)
		goto append_ksu_rc;

	ret = orig_read(file, buf, count, pos);
	if (ret != 0 || ksu_rc_pos >= ksu_rc_len) {
		return ret;
	} else {
		pr_info("read_proxy: orig read finished, start append rc\n");
	}
append_ksu_rc:
	append_count = ksu_rc_len - ksu_rc_pos;
	if (append_count > count - ret)
		append_count = count - ret;
	// copy_to_user returns the number of not copied
	if (copy_to_user(buf + ret, KERNEL_SU_RC + ksu_rc_pos, append_count)) {
		pr_info("read_proxy: append error, totally appended %ld\n", ksu_rc_pos);
	} else {
		pr_info("read_proxy: append %ld\n", append_count);

		ksu_rc_pos += append_count;
		if (ksu_rc_pos == ksu_rc_len) {
			pr_info("read_proxy: append done\n");
		}
		ret += append_count;
	}

	return ret;
}

static ssize_t read_iter_proxy(struct kiocb *iocb, struct iov_iter *to)
{
	ssize_t ret = 0;
	size_t append_count;
	if (ksu_rc_pos && ksu_rc_pos < ksu_rc_len)
		goto append_ksu_rc;

	ret = orig_read_iter(iocb, to);
	if (ret != 0 || ksu_rc_pos >= ksu_rc_len) {
		return ret;
	} else {
		pr_info("read_iter_proxy: orig read finished, start append rc\n");
	}
append_ksu_rc:
	// copy_to_iter returns the number of copied bytes
	append_count = copy_to_iter(KERNEL_SU_RC + ksu_rc_pos, ksu_rc_len - ksu_rc_pos, to);
	if (!append_count) {
		pr_info("read_iter_proxy: append error, totally appended %ld\n", ksu_rc_pos);
	} else {
		pr_info("read_iter_proxy: append %ld\n", append_count);

		ksu_rc_pos += append_count;
		if (ksu_rc_pos == ksu_rc_len) {
			pr_info("read_iter_proxy: append done\n");
		}
		ret += append_count;
	}
	return ret;
}

static bool is_init_rc(struct file *fp)
{
	if (strcmp(current->comm, "init")) {
		// we are only interest in `init` process
		return false;
	}

	if (!d_is_reg(fp->f_path.dentry)) {
		return false;
	}

	const char *short_name = fp->f_path.dentry->d_name.name;
	if (strcmp(short_name, "init.rc")) {
		// we are only interest `init.rc` file name file
		return false;
	}
	char path[256] = {0};
	char *dpath = d_path(&fp->f_path, path, sizeof(path));

	if (IS_ERR(dpath)) {
		return false;
	}

	if (strcmp(dpath, "/system/etc/init/hw/init.rc")) {
		return false;
	}

	pr_info("%s: %s \n", __func__, dpath);

	return true;
}

static void ksu_handle_initrc(struct file *file)
{
	if (!ksu_vfs_read_hook) {
		return;
	}

	if (!is_init(get_current_cred()))
		return;

	if (!is_init_rc(file)) {
		return;
	}

	// we only process the first read
	static bool rc_hooked = false;
	if (rc_hooked) {
		// we don't need this kprobe, unregister it!
		stop_vfs_read_hook();
		return;
	}
	rc_hooked = true;

	// now we can sure that the init process is reading
	// `/system/etc/init/init.rc`

	pr_info("read init.rc, comm: %s, rc_count: %zu\n", current->comm, ksu_rc_len);

	// Now we need to proxy the read and modify the result!
	// But, we can not modify the file_operations directly, because it's in read-only memory.
	// We just replace the whole file_operations with a proxy one.
	memcpy(&fops_proxy, file->f_op, sizeof(struct file_operations));
	orig_read = file->f_op->read;
	if (orig_read) {
		fops_proxy.read = read_proxy;
	}
	orig_read_iter = file->f_op->read_iter;
	if (orig_read_iter) {
		fops_proxy.read_iter = read_iter_proxy;
	}
	// replace the file_operations
	file->f_op = &fops_proxy;

	return;
}

// NOTE: https://github.com/tiann/KernelSU/commit/df640917d11dd0eff1b34ea53ec3c0dc49667002
// - added 260110, seems needed for A17

#define STAT_NATIVE 0
#define STAT_STAT64 1

static __always_inline void ksu_common_newfstat_ret(unsigned long fd_long, void **statbuf_ptr, const int type)
{
	
	if (!ksu_vfs_read_hook) {
		return;
	}

	if (!is_init(get_current_cred()))
		return;

	struct file *file = fget(fd_long);
	if (!file)
		return;

	if (!is_init_rc(file)) {
		fput(file);
		return;
	}
	fput(file);

	pr_info("%s: stat init.rc \n", __func__);

	uintptr_t statbuf_ptr_local = (uintptr_t)*(void **)statbuf_ptr;
	void __user *statbuf = (void __user *)statbuf_ptr_local;
	if (!statbuf)
		return;

	void __user *st_size_ptr;
	long size, new_size;
	size_t len;

	st_size_ptr = statbuf + offsetof(struct stat, st_size);
	len = sizeof(long);

#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
	if (type) {
		st_size_ptr = statbuf + offsetof(struct stat64, st_size);
		len = sizeof(long long);
	}
#endif

	if (copy_from_user(&size, st_size_ptr, len)) {
		pr_info("%s: read statbuf 0x%lx failed \n", __func__, (unsigned long)st_size_ptr);
		return;
	}

	new_size = size + ksu_rc_len;
	pr_info("%s: adding ksu_rc_len: %ld -> %ld \n", __func__, size, new_size);
		
	if (!copy_to_user(st_size_ptr, &new_size, len))
		pr_info("%s: added ksu_rc_len \n", __func__);
	else
		pr_info("%s: add ksu_rc_len failed: statbuf 0x%lx \n", __func__, (unsigned long)st_size_ptr);
	
	return;
}

void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr)
{
	unsigned long fd_long = (unsigned long)*fd;

	// native
	ksu_common_newfstat_ret(fd_long, (void **)statbuf_ptr, STAT_NATIVE);
}

#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
void ksu_handle_fstat64_ret(unsigned long *fd, struct stat64 __user **statbuf_ptr)
{
	unsigned long fd_long = (unsigned long)*fd;

	// 32-bit call uses this!
	ksu_common_newfstat_ret(fd_long, (void **)statbuf_ptr, STAT_STAT64);
}
#endif

#ifdef CONFIG_COMPAT // this one is wrong, only keeping it for people that picked it up
void ksu_compat_newfstat_ret(unsigned int *fd, struct compat_stat __user **statbuf_ptr)
{
	return;
}
#endif

// working dummies for manual hooks
__attribute__((deprecated))
int ksu_handle_vfs_read(struct file **file_ptr, char __user **buf_ptr, size_t *count_ptr, loff_t **pos)
{
	return 0;
}

__attribute__((deprecated))
int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr, size_t *count_ptr)
{
	return 0;
}

__attribute__((deprecated))
int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value)
{
	return 0;
}

static bool safe_mode_flag = false;
#define VOLUME_PRESS_THRESHOLD_COUNT 3

bool ksu_is_safe_mode()
{
	// don't need to check again, userspace may call multiple times
	static bool already_checked = false;
	if (already_checked)
		return true;

	// stop hook first!
	stop_input_hook();


	if (!safe_mode_flag)
		return false;
		
	pr_info("volume keys pressed max times, safe mode detected!\n");
	already_checked = true;
	return true;
}

static void vol_detector_event(struct input_handle *handle, unsigned int type, unsigned int code, int value)
{
	static int vol_up_cnt = 0;
	static int vol_down_cnt = 0;

	if (!value)
		return;
	
	if (type != EV_KEY)
		return;
	
	if (code == KEY_VOLUMEDOWN) {
		vol_down_cnt++;
		pr_info("KEY_VOLUMEDOWN press detected!\n");
	}

	if (code == KEY_VOLUMEUP) {
		vol_up_cnt++;
		pr_info("KEY_VOLUMEUP press detected!\n");
	}

	pr_info("volume_pressed_count: vol_up: %d vol_down: %d\n", vol_up_cnt, vol_down_cnt);

	/*
	 * on upstream we call stop_input_hook() here but this is causing issues
	 * #1. unregistering an input handler inside the input handler is a bad meme
	 * #2. when I tried to defer unreg to a kthread, it also causes issues on some users? nfi.
	 * since unregging is done anyway on ksu_is_safe_mode() or on_post_fs_data() we just dont bother.
	 *
	 */
	if (vol_up_cnt >= VOLUME_PRESS_THRESHOLD_COUNT || vol_down_cnt >= VOLUME_PRESS_THRESHOLD_COUNT) {
		pr_info("volume keys pressed max times, safe mode detected!\n");
		safe_mode_flag = true;
	}
}

static int vol_detector_connect(struct input_handler *handler, struct input_dev *dev,
					  const struct input_device_id *id)
{
	struct input_handle *handle;
	int error;

	handle = kzalloc(sizeof(struct input_handle), GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	handle->dev = dev;
	handle->handler = handler;
	handle->name = "ksu_handle_input";

	error = input_register_handle(handle);
	if (error)
		goto err_free_handle;

	error = input_open_device(handle);
	if (error)
		goto err_unregister_handle;

	return 0;

err_unregister_handle:
	input_unregister_handle(handle);
err_free_handle:
	kfree(handle);
	return error;
}

static const struct input_device_id vol_detector_ids[] = { 
	// we add key volume up so that
	// 1. if you have broken volume down you get shit
	// 2. we can make sure to trigger only ksu safemode, not android's safemode.
	{
		.flags = INPUT_DEVICE_ID_MATCH_EVBIT | INPUT_DEVICE_ID_MATCH_KEYBIT,
		.evbit = { BIT_MASK(EV_KEY) },
		.keybit = { [BIT_WORD(KEY_VOLUMEUP)] = BIT_MASK(KEY_VOLUMEUP) },
	},
	{
		.flags = INPUT_DEVICE_ID_MATCH_EVBIT | INPUT_DEVICE_ID_MATCH_KEYBIT,
		.evbit = { BIT_MASK(EV_KEY) },
		.keybit = { [BIT_WORD(KEY_VOLUMEDOWN)] = BIT_MASK(KEY_VOLUMEDOWN) },
	},
	{ }
};

static void vol_detector_disconnect(struct input_handle *handle)
{
	input_close_device(handle);
	input_unregister_handle(handle);
	kfree(handle);
}

MODULE_DEVICE_TABLE(input, vol_detector_ids);

static struct input_handler vol_detector_handler = {
        .event =	vol_detector_event,
        .connect =	vol_detector_connect,
        .disconnect =	vol_detector_disconnect,
        .name =		"ksu",
        .id_table =	vol_detector_ids,
};

static int vol_detector_init()
{
	pr_info("vol_detector: init\n");
	return input_register_handler(&vol_detector_handler);
}

static int vol_detector_exit()
{
	pr_info("vol_detector: exit\n");
	input_unregister_handler(&vol_detector_handler);
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0) // is_ksu_transition
u32 ksud_init_sid = 0;
u32 ksud_su_sid = 0;

int grab_transition_sids()
{
	int error = security_secctx_to_secid("u:r:init:s0", strlen("u:r:init:s0"), &ksud_init_sid);
	if (error)
		return 1;

	pr_info("is_ksu_transition: got init sid: %d\n", ksud_init_sid);

	error = security_secctx_to_secid(KERNEL_SU_CONTEXT, strlen(KERNEL_SU_CONTEXT), &ksud_su_sid);
	if (error)
		return 1;

	pr_info("is_ksu_transition: got su sid: %d\n", ksud_su_sid);
	
	return 0;
}

bool is_ksu_transition(const struct task_security_struct *old_tsec,
			const struct task_security_struct *new_tsec)
{

	// we don't need this hook anymore after the third ksud run, which is boot-complete.
	if (likely(ksu_boot_completed))
		return false;

	if (!ksud_su_sid || !ksud_init_sid) {
		int ret = grab_transition_sids();
		if (ret)
			return false;
	}

	// if its init transitioning to su, allow it
	if (old_tsec->sid == ksud_init_sid && new_tsec->sid == ksud_su_sid) {
		pr_info("%s: allowing init (%d) -> su (%d)\n", __func__, ksud_init_sid, ksud_su_sid);
		return true;
	}

	return false;
}
#endif // is_ksu_transition

static void stop_vfs_read_hook()
{
	ksu_vfs_read_hook = false;
	pr_info("stop vfs_read_hook\n");
}

static void stop_execve_hook()
{
	ksu_execveat_hook = false;
	pr_info("stop execve_hook\n");
}

static void stop_input_hook()
{
	if (!ksu_input_hook) { return; }
	ksu_input_hook = false;
	pr_info("stop input_hook\n");
	
	vol_detector_exit();
}

void ksu_ksud_init()
{
	vol_detector_init();
}

