#include <asm/current.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
#include <linux/input-event-codes.h>
#else
#include <uapi/linux/input.h>
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

bool ksu_module_mounted __read_mostly = false;
bool ksu_boot_completed __read_mostly = false;

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

u32 ksu_file_sid;

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

	ksu_file_sid = ksu_get_ksu_file_sid();
	pr_info("ksu_file sid: %d\n", ksu_file_sid);
}

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
		setup_ksu_cred();
		init_second_stage_executed = true;
		// ksu_android_ns_fs_check();
	}

	// /init with argv1
	if (!strcmp(filename, old_system_init) && argv1 && !strcmp(argv1, "--second-stage")) {
		pr_info("%s: /init --second-stage executed\n", __func__);
		apply_kernelsu_rules();
		setup_ksu_cred();
		init_second_stage_executed = true;
		// ksu_android_ns_fs_check();
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
			setup_ksu_cred();
			init_second_stage_executed = true;
			// ksu_android_ns_fs_check();
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
static ssize_t read_count_append = 0;

static ssize_t read_proxy(struct file *file, char __user *buf, size_t count,
			  loff_t *pos)
{
	bool first_read = file->f_pos == 0;
	ssize_t ret = orig_read(file, buf, count, pos);
	if (first_read) {
		pr_info("read_proxy append %ld + %ld\n", ret,
			read_count_append);
		ret += read_count_append;
	}
	return ret;
}

static ssize_t read_iter_proxy(struct kiocb *iocb, struct iov_iter *to)
{
	bool first_read = iocb->ki_pos == 0;
	ssize_t ret = orig_read_iter(iocb, to);
	if (first_read) {
		pr_info("read_iter_proxy append %ld + %ld\n", ret,
			read_count_append);
		ret += read_count_append;
	}
	return ret;
}

int ksu_handle_vfs_read(struct file **file_ptr, char __user **buf_ptr,
			size_t *count_ptr, loff_t **pos)
{

	if (!ksu_vfs_read_hook) {
		return 0;
	}

	struct file *file;
	char __user *buf;
	size_t count;

	if (strcmp(current->comm, "init")) {
		// we are only interest in `init` process
		return 0;
	}

	file = *file_ptr;
	if (IS_ERR(file)) {
		return 0;
	}

	if (!d_is_reg(file->f_path.dentry)) {
		return 0;
	}

	const char *short_name = file->f_path.dentry->d_name.name;
	if (strcmp(short_name, "atrace.rc")) {
		// we are only interest `atrace.rc` file name file
		return 0;
	}
	char path[256];
	char *dpath = d_path(&file->f_path, path, sizeof(path));

	if (IS_ERR(dpath)) {
		return 0;
	}

	if (strcmp(dpath, "/system/etc/init/atrace.rc")) {
		return 0;
	}

	// we only process the first read
	static bool rc_inserted = false;
	if (rc_inserted) {
		// we don't need this hook, unregister it!
		stop_vfs_read_hook();
		return 0;
	}
	rc_inserted = true;

	// now we can sure that the init process is reading
	// `/system/etc/init/atrace.rc`
	buf = *buf_ptr;
	count = *count_ptr;

	size_t rc_count = strlen(KERNEL_SU_RC);

	pr_info("vfs_read: %s, comm: %s, count: %zu, rc_count: %zu\n", dpath,
		current->comm, count, rc_count);

	if (count < rc_count) {
		pr_err("count: %zu < rc_count: %zu\n", count, rc_count);
		return 0;
	}

	size_t ret = copy_to_user(buf, KERNEL_SU_RC, rc_count);
	if (ret) {
		pr_err("copy ksud.rc failed: %zu\n", ret);
		return 0;
	}

	// we've succeed to insert ksud.rc, now we need to proxy the read and modify the result!
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
	read_count_append = rc_count;

	*buf_ptr = buf + rc_count;
	*count_ptr = count - rc_count;

	return 0;
}

int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr,
			size_t *count_ptr)
{
	struct file *file = fget(fd);
	if (!file) {
		return 0;
	}
	int result = ksu_handle_vfs_read(&file, buf_ptr, count_ptr, NULL);
	fput(file);
	return result;
}

static unsigned int volumedown_pressed_count = 0;

static bool is_volumedown_enough(unsigned int count)
{
	return count >= 3;
}

int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code,
				  int *value)
{
	if (!ksu_input_hook) {
		return 0;
	}

	if (*type == EV_KEY && *code == KEY_VOLUMEDOWN) {
		int val = *value;
		pr_info("KEY_VOLUMEDOWN val: %d\n", val);
		if (val) {
			// key pressed, count it
			volumedown_pressed_count += 1;
			if (is_volumedown_enough(volumedown_pressed_count)) {
				stop_input_hook();
			}
		}
	}

	return 0;
}

bool ksu_is_safe_mode()
{
	static bool safe_mode = false;
	if (safe_mode) {
		// don't need to check again, userspace may call multiple times
		return true;
	}

	// stop hook first!
	stop_input_hook();

	pr_info("volumedown_pressed_count: %d\n", volumedown_pressed_count);
	if (is_volumedown_enough(volumedown_pressed_count)) {
		// pressed over 3 times
		pr_info("KEY_VOLUMEDOWN pressed max times, safe mode detected!\n");
		safe_mode = true;
		return true;
	}

	return false;
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
}

