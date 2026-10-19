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

static noinline void ksu_preinit_handle_kexecve(void *filename, void *kargv)
{
	if (is_compat_task())
		return;

	if (!!strcmp(*(char **)filename, INIT_PATH))
		return;

	struct user_arg_ptr *argv = (struct user_arg_ptr *)kargv;
	void ***argv_addr = (void ***)&argv->ptr.native;
#ifdef CONFIG_COMPAT
	if (unlikely(argv->is_compat))
		argv_addr = (void ***)&argv->ptr.compat;
#endif

	if (!is_selinux_setup((const char __user *const __user *)*(void ***)argv_addr))
		return;

	pr_info("preinit: kexecve: /system/bin/init with selinux_setup!");
}


// filename is void *char __user *
static noinline void ksu_preinit_handle_uexecve(void *filename, void *u_argv)
{
	if (is_compat_task())
		return;

	constexpr char expected[] = INIT_PATH;
	char buf[sizeof(expected) + 1];
	if (strncpy_from_user(buf, *(void **)filename, sizeof(buf) - 1) < 0)
		return;

	if (!is_selinux_setup((const char __user *const __user *)*(void ***)u_argv))
		return;

	pr_info("preinit: sys_execve: /system/bin/init with selinux_setup!");
}

static inline void ksu_preinit_kernel_execve_hook(void *filename, void *k_argv)
{
	if (!static_branch_likely(&ksu_preinit_key))
		return;

	ksu_preinit_handle_kexecve(filename, k_argv);
}


static inline void ksu_preinit_user_execve_hook(void *filename, void *u_argv)
{
	if (!static_branch_likely(&ksu_preinit_key))
		return;

	// filename is void *char __user *
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
