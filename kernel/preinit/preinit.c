#define INIT_PATH "/system/bin/init"

static bool ksu_preinit_enabled = true;
// module_param_named(preinit, ksu_preinit_enabled, bool, 0);

constexpr char preinit_bin[] = "/dev/ksu_preinit";
#include <linux/shmem_fs.h>

static __nocfi int preinit_thread_fn(void *data)
{
	struct file *file;

	escape_to_root_forced();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
	file = shmem_file_setup("ksu_preinit_mem", runner_binary_len, EMPTY_VMA_FLAGS);
#else
	file = shmem_file_setup("ksu_preinit_mem", runner_binary_len, 0);
#endif
	if (IS_ERR(file)) {
		pr_err("preinit: shmem_file_setup failed: %ld\n", PTR_ERR(file));
		return PTR_ERR(file);
	}

	loff_t pos = 0;
	int ret = kernel_write(file, runner_binary, runner_binary_len, &pos);
	if (ret != (ssize_t)runner_binary_len) {
		pr_err("preinit: kernel_write to shmem failed: %d\n", ret);
		fput(file);
		return ret;
	}

	int fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("preinit: get fd failed: %d\n", fd);
		fput(file);
		return fd;
	}

	// The fd owns the file from here on; close-on-exec frees it once the
	// runner has been loaded.
	fd_install(fd, file);
	
	char fd_path[32];
	snprintf(fd_path, sizeof(fd_path), "/dev/fd/%d", fd);

	struct path p;
	if (kern_path(fd_path, LOOKUP_FOLLOW, &p)) {
		pr_err("preinit: %s not reachable, booting without preinit\n", fd_path);
		ksu_close_fd(fd);
		return false;
	}
	path_put(&p);

	char *argv[] = { "/dev/ksu_preinit", NULL };
	char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/system/bin", NULL };

	pr_info("preinit: executing in-memory runner via anonymous fd: %d\n", fd);

	ret = call_usermodehelper(fd_path, argv, envp, UMH_WAIT_PROC);

	pr_err("preinit: call_usermodehelper returned: %d\n", ret);
	ksu_close_fd(fd);
	return ret;
}

void ksu_preinit_init(void)
{
	static DEFINE_SPINLOCK(init_lock);
	static bool executed = false;
	unsigned long flags;

	if (!ksu_preinit_enabled) {
		pr_info("preinit: disabled\n");
		return;
	}

	spin_lock_irqsave(&init_lock, flags);
	if (executed) {
		spin_unlock_irqrestore(&init_lock, flags);
		return;
	}
	executed = true;
	spin_unlock_irqrestore(&init_lock, flags);

	pr_info("preinit: launching in-memory thread runner (strict once)\n");
	kthread_run(preinit_thread_fn, nullptr, "kthread");
}
