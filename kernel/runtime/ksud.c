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
static void stop_input_hook();

static bool ksu_module_mounted __read_mostly = false;
static bool ksu_boot_completed __read_mostly = false;
static bool ksu_vfs_read_hook __read_mostly = true;
static bool ksu_input_hook __read_mostly = true;

#ifdef KSU_CAN_USE_JUMP_LABEL
DEFINE_STATIC_KEY_TRUE(ksud_vfs_read_key);
static inline void ksu_disable_vfs_read_branch()
{
	pr_info("vfs_read_hook: remove vfs_read branches\n");
	static_branch_disable(&ksud_vfs_read_key);
	smp_mb();
}
#else
#define ksu_disable_vfs_read_branch()	do { } while (0)
#endif

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

	if (!!strcmp(dpath, "/init.rc") && !!strcmp(dpath, "/system/etc/init/hw/init.rc")) {
		return false;
	}

	pr_info("%s: %s \n", __func__, dpath);

	return true;
}

__attribute__((cold))
static noinline void ksu_install_rc_hook(struct file *file)
{
	if (!is_init(current_cred()))
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

// for sys_read kp / syscall table
__attribute__((cold))
static noinline void ksu_handle_sys_read_fd(unsigned int fd)
{
	if (likely(!ksu_vfs_read_hook))
		return;

	if (!is_init(current_cred()))
		return;

	struct file *file = fget(fd);
	if (!file) {
		return;
	}
	ksu_install_rc_hook(file);
	fput(file);
}

#define STAT_NATIVE 0
#define STAT_STAT64 1

__attribute__((cold))
static noinline void ksu_common_newfstat_ret(unsigned int fd_int, void **statbuf_ptr, 
			const int type, const char *syscall_name)
{
	if (!is_init(current_cred()))
		return;

	struct file *file = fget(fd_int);
	if (!file)
		return;

	if (!is_init_rc(file)) {
		fput(file);
		return;
	}
	fput(file);

	pr_info("%s: stat init.rc \n", syscall_name);

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

	// we do this for kretprobe's reusability
	// this is pretty short, so nbd
	bool got_flipped = false;
	if (!preemptible()) {
		preempt_enable();
		got_flipped = true;
	}
	int old_nice = task_nice(current);
	set_user_nice(current, -20);

	if (ksu_copy_from_user_retry(&size, st_size_ptr, len)) {
		pr_info("%s: read statbuf 0x%lx failed \n", syscall_name, (unsigned long)st_size_ptr);
		goto out;
	}

	new_size = size + ksu_rc_len;
	pr_info("%s: adding ksu_rc_len: %ld -> %ld \n", syscall_name, size, new_size);
		
	if (!copy_to_user(st_size_ptr, &new_size, len))
		pr_info("%s: added ksu_rc_len \n", syscall_name);
	else
		pr_info("%s: add ksu_rc_len failed: statbuf 0x%lx \n", syscall_name, (unsigned long)st_size_ptr);
	
out:
	set_user_nice(current, old_nice);
	if (got_flipped)
		preempt_disable();

	return;
}

void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr)
{
#ifdef KSU_CAN_USE_JUMP_LABEL
	if (static_branch_likely(&ksud_vfs_read_key))
		ksu_common_newfstat_ret(*fd, (void **)statbuf_ptr, STAT_NATIVE, "sys_newfstat");
#else
	if (unlikely(ksu_vfs_read_hook))
		ksu_common_newfstat_ret(*fd, (void **)statbuf_ptr, STAT_NATIVE, "sys_newfstat");
#endif
}

#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
void ksu_handle_fstat64_ret(unsigned long *fd, struct stat64 __user **statbuf_ptr)
{
#ifdef KSU_CAN_USE_JUMP_LABEL
	if (static_branch_likely(&ksud_vfs_read_key))
		ksu_common_newfstat_ret(*(unsigned int *)fd, (void **)statbuf_ptr, STAT_STAT64, "sys_fstat64"); // WARNING: LE-only!!!
#else
	if (unlikely(ksu_vfs_read_hook))
		ksu_common_newfstat_ret(*(unsigned int *)fd, (void **)statbuf_ptr, STAT_STAT64, "sys_fstat64"); // WARNING: LE-only!!!
#endif
}
#endif

static void stop_vfs_read_hook()
{
	ksu_vfs_read_hook = false;
	pr_info("stop vfs_read_hook\n");
	ksu_disable_vfs_read_branch();
}

static void stop_input_hook()
{
	if (!ksu_input_hook) { return; }
	ksu_input_hook = false;
	pr_info("stop input_hook\n");
}

void __init ksu_ksud_init() { }

