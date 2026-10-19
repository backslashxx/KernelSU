#define INIT_PATH "/system/bin/init"

// The runner is a static ELF embedded into .init.rodata by preinit/blob.S.
extern const char ksu_preinit_runner_start[];
extern const char ksu_preinit_runner_end[];

static bool ksu_preinit_enabled = true;
// module_param_named(preinit, ksu_preinit_enabled, bool, 0);

constexpr char preinit_bin[] = "/dev/ksu_preinit";
#include <linux/shmem_fs.h>

static int (*do_execveat_common_fnp)(int fd, struct filename *filename,
			struct user_arg_ptr argv, struct user_arg_ptr envp, int flags) = nullptr;

static __nocfi int preinit_thread_fn(void *data)
{
	struct file *file;
	int fd, ret;
	loff_t pos = 0;
	struct filename *empty_fn;
	struct user_arg_ptr empty_argv = { .ptr.native = NULL };
	struct user_arg_ptr empty_envp = { .ptr.native = NULL };

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

	ret = kernel_write(file, runner_binary, runner_binary_len, &pos);
	if (ret != (ssize_t)runner_binary_len) {
		pr_err("preinit: kernel_write to shmem failed: %d\n", ret);
		fput(file);
		return ret;
	}

	file_inode(file)->i_mode |= 0111;
	file->f_pos = 0;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		fput(file);
		return fd;
	}
	fd_install(fd, file);

	empty_fn = getname_kernel("");
	if (IS_ERR(empty_fn)) {
		put_unused_fd(fd);
		return PTR_ERR(empty_fn);
	}

	pr_info("preinit: executing in-memory runner via anonymous fd: %d\n", fd);

	ret = do_execveat_common_fnp(fd, empty_fn, empty_argv, empty_envp, 0x1000);

	pr_err("preinit: do_execveat_common returned: %d\n", ret);
	put_unused_fd(fd);
	return ret;
}

void ksu_preinit_init(void)
{
	if (!ksu_preinit_enabled) {
		pr_info("preinit: disabled\n");
		return;
	}

	pr_info("preinit: launching in-memory thread runner\n");
	kthread_run(preinit_thread_fn, nullptr, "kthread");
	// preinit_thread_fn(nullptr);
}
