#define INIT_PATH "/system/bin/init"

DEFINE_STATIC_KEY_TRUE(ksu_preinit_key);

static bool ksu_preinit_enabled = true;

static bool is_selinux_setup(const char __user *const __user *argv_user)
{
	static const char expected[] = "selinux_setup";
	const char __user *arg;
	char buf[sizeof(expected) + 1];

	if (!argv_user || get_user(arg, argv_user + 1) || !arg)
		return false;

	memset(buf, 0, sizeof(buf));
	if (strncpy_from_user(buf, arg, sizeof(buf) - 1) < 0)
		return false;

	return !strcmp(buf, expected);
}

// returns fd
static int ksu_stage_preinit_binary(void)
{
	struct file *file;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
	file = shmem_file_setup("ksu_preinit_mem", runner_binary_len, EMPTY_VMA_FLAGS);
#else
	file = shmem_file_setup("ksu_preinit_mem", runner_binary_len, 0);
#endif
	if (IS_ERR(file)) {
		pr_err("preinit: shmem_file_setup failed: %ld\n", PTR_ERR(file));
		return -1;
	}

	loff_t pos = 0;
	int ret = kernel_write(file, runner_binary, runner_binary_len, &pos);
	if (ret != (ssize_t)runner_binary_len) {
		pr_err("preinit: kernel_write to shmem failed: %d\n", ret);
		fput(file);
		return -1;
	}

	int fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("preinit: get fd failed: %d\n", fd);
		fput(file);
		return -1;
	}

	// The fd owns the file from here on; close-on-exec frees it once the
	// runner has been loaded.
	fd_install(fd, file);
	return fd;
}

static noinline void ksu_preinit_handle_kexecve(void **filename, void *kargv)
{
	if (is_compat_task() || !current->mm)
		return;

	if (!!strcmp(*(char **)filename, INIT_PATH))
		return;

	pr_info("preinit: kernel_execve: %s \n", INIT_PATH);

	struct user_arg_ptr *argv = (struct user_arg_ptr *)kargv;
	void ***u_argv = (void ***)&argv->ptr.native;

	if (!is_selinux_setup((const char __user *const __user *)*(void ***)u_argv))
		return;

	pr_info("preinit: kernel_execve: /system/bin/init with selinux_setup! \n");

	static bool executed = false;
	if (executed)
		return;
	executed = true;
}

// filename is void *char __user *
static noinline void ksu_preinit_handle_uexecve(const char __user **filename, void *u_argv)
{
	if (is_compat_task() || !current->mm)
		return;

	constexpr char expected[] = INIT_PATH;

	char buf[sizeof(expected) + 1];
	buf[sizeof(buf) - 1] = 0;
	if (!!copy_from_user_retry(buf, *filename, sizeof(buf) - 1 ))
		return;

	if (!!strcmp(buf, expected))
		return;

	pr_info("preinit: sys_execve: %s \n", INIT_PATH);

	if (!is_selinux_setup((const char __user *const __user *)*(void ***)u_argv))
		return;

	pr_info("preinit: sys_execve: %s with selinux_setup! \n", INIT_PATH);

	static bool executed = false;
	if (executed)
		return;
	executed = true;

	int fd = ksu_stage_preinit_binary();
	if (fd < 0)
		pr_info("preinit: get fd failed: %d\n", fd);

	char fd_path[32];
	int len = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);

	struct path p;
	if (kern_path(fd_path, LOOKUP_FOLLOW, &p)) {
		pr_err("preinit: %s not reachable, booting without preinit\n", fd_path);
		ksu_close_fd(fd);
		return;
	}
	path_put(&p);

	void *orig = *filename;
	*filename = userspace_stack_buffer(fd_path, len + 1);
	if (!*filename)
		return;

	long eret = ksyscall(execve, *filename, (const char __user *const __user *)*(void ***)u_argv, nullptr);
	pr_err("preinit: exec runner failed: %ld, booting without preinit\n", eret);
	*filename = orig;
}

static inline void ksu_preinit_kernel_execve_hook(void **filename, void *k_argv)
{
//	if (!static_branch_likely(&ksu_preinit_key))
//		return;

	ksu_preinit_handle_kexecve(filename, k_argv);
}


static inline void ksu_preinit_user_execve_hook(const char __user **filename, void *u_argv)
{
//	if (!static_branch_likely(&ksu_preinit_key))
//		return;

	ksu_preinit_handle_uexecve(filename, u_argv);
}

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
//	pr_info("preinit: launching in-memory thread runner (runonce)\n");
}
