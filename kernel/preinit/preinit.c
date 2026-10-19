#define INIT_PATH "/system/bin/init"

// The runner is a static ELF embedded into .init.rodata by preinit/blob.S.
extern const char ksu_preinit_runner_start[];
extern const char ksu_preinit_runner_end[];

static bool ksu_preinit_enabled = true;
// module_param_named(preinit, ksu_preinit_enabled, bool, 0);

void ksu_preinit_init(void)
{
	loff_t pos = 0;
	ssize_t written;

	if (!ksu_preinit_enabled) {
		pr_info("preinit: disabled\n");
		return;
	}

	struct file *file = filp_open("/dev/ksu_preinit", O_WRONLY | O_CREAT | O_TRUNC, 0700);
	if (IS_ERR(file)) {
		pr_err("preinit: failed to create runner in /dev: %ld\n", PTR_ERR(file));
		return;
	}

	written = kernel_write(file, runner_binary, runner_binary_len, &pos);
	filp_close(file, NULL);

	if (written != (ssize_t)runner_binary_len) {
		pr_err("preinit: write runner failed: %zd / %u\n", written, runner_binary_len);
		return;
	}

	pr_info("preinit: runner staged to /dev/ksu_preinit (%u bytes)\n", runner_binary_len);
}

bool ksu_preinit_enabled_param(void)
{
}

void ksu_preinit_release(void)
{
}

void ksu_preinit_exit(void)
{
}

#if 0
bool ksu_preinit_handle_execve(const char __user **filename_user, const char __user *const __user *argv_user,
							   int orig_nr, struct pt_regs *regs, long *ret)
{
	const char __user *orig_filename;
	char path[sizeof(INIT_PATH) + 1];
	char fd_path[32];
	struct file *file;
	struct path p;
	int fd, len;

	if (likely(!READ_ONCE(ksu_preinit_file)))
		return false;

	if (!filename_user || !*filename_user)
		return false;

	memset(path, 0, sizeof(path));
	if (strncpy_from_user(path, (const char __user *)untagged_addr((unsigned long)*filename_user), sizeof(path) - 1) <
		0)
		return false;

	if (strcmp(path, INIT_PATH) || !is_selinux_setup(argv_user))
		return false;

	// One shot: the runner's own exec of the real init must pass through.
	file = xchg(&ksu_preinit_file, NULL);
	if (!file)
		return false;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("preinit: get fd failed: %d\n", fd);
		fput(file);
		return false;
	}
	// The fd owns the file from here on; close-on-exec frees it once the
	// runner has been loaded.
	fd_install(fd, file);

	len = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
	if (kern_path(fd_path, LOOKUP_FOLLOW, &p)) {
		pr_err("preinit: %s not reachable, booting without preinit\n", fd_path);
		ksu_close_fd(fd);
		return false;
	}
	path_put(&p);

	orig_filename = *filename_user;
	*filename_user = userspace_stack_buffer(fd_path, len + 1);
	if (!*filename_user) {
		*filename_user = orig_filename;
		ksu_close_fd(fd);
		return false;
	}

	pr_info("preinit: exec runner via %s\n", fd_path);
	*ret = ksu_syscall_table[orig_nr](regs);
	if (*ret < 0) {
		pr_err("preinit: exec runner failed: %ld, booting without preinit\n", *ret);
		*filename_user = orig_filename;
		ksu_close_fd(fd);
		*ret = ksu_syscall_table[orig_nr](regs);
	}
	return true;
}
#endif
