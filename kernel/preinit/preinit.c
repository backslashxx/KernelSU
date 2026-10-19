#define INIT_PATH "/system/bin/init"

static bool ksu_preinit_enabled = true;
// module_param_named(preinit, ksu_preinit_enabled, bool, 0);

constexpr char preinit_bin[] = "/dev/ksu_preinit";
#include <linux/shmem_fs.h>

#if 1
static int (*do_execveat_common_fnp)(int fd, struct filename *filename,
			struct user_arg_ptr argv, struct user_arg_ptr envp, int flags) = nullptr;

static __nocfi int preinit_thread_fn(void *data)
{
	struct file *file;

	do_execveat_common_fnp = kallsyms_lookup_retry("do_execveat_common");
	if (!do_execveat_common_fnp) {
		pr_err("preinit: failed to resolve do_execveat_common\n");
		return -ENOSYS;
	}

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

	struct filename *empty_fn = getname_kernel("");
	if (IS_ERR(empty_fn)) {
		ksu_close_fd(fd);
		return PTR_ERR(empty_fn);
	}

	pr_info("preinit: executing in-memory runner via anonymous fd: %d\n", fd);

	struct user_arg_ptr empty_argv = { .ptr.native = NULL };
	struct user_arg_ptr empty_envp = { .ptr.native = NULL };

	ret = do_execveat_common_fnp(fd, empty_fn, empty_argv, empty_envp, AT_EMPTY_PATH);

	pr_err("preinit: do_execveat_common returned: %d\n", ret);
	ksu_close_fd(fd);
	return ret;
}
#else
static __nocfi int preinit_thread_fn(void *data)
{
	struct file *file;
	loff_t pos = 0;
	int ret;

	escape_to_root_forced();

	file = filp_open("/dev/ksu_preinit", O_WRONLY | O_CREAT | O_TRUNC, 0700);
	if (IS_ERR(file)) {
		pr_err("preinit: failed to create runner in /dev: %ld\n", PTR_ERR(file));
		return PTR_ERR(file);
	}

	ret = kernel_write(file, runner_binary, runner_binary_len, &pos);
	vfs_fsync(file, 0);
	filp_close(file, NULL);

	if (ret != (ssize_t)runner_binary_len) {
		pr_err("preinit: write runner failed: %d\n", ret);
		return ret;
	}

	char *argv[] = { "/dev/ksu_preinit", NULL };
	char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/system/bin", "KSU=true", NULL };

	pr_info("preinit: executing via call_usermodehelper\n");

	ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

	pr_err("preinit: call_usermodehelper returned: %d\n", ret);
	return ret;
}
#endif

void ksu_preinit_init(void)
{
	static bool executed = false;
	if (executed)
		return;

	if (!ksu_preinit_enabled) {
		pr_info("preinit: disabled\n");
		return;
	}

	executed = true;
	pr_info("preinit: launching in-memory thread runner (runonce)\n");
	kthread_run(preinit_thread_fn, nullptr, "kthread");
	// preinit_thread_fn(nullptr);
}
