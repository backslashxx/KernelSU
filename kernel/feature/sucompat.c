#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

static bool ksu_su_compat_enabled __read_mostly = true;

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	/* To avoid having to mmap a page in userspace, just write below the stack
   * pointer. */
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *sh_user_path(void)
{
	static const char sh_path[] = "/system/bin/sh";

	return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static char __user *ksud_user_path(void)
{
	static const char ksud_path[] = KSUD_PATH;

	return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

__attribute__((hot))
static __always_inline bool is_su_allowed(const void **ptr_to_check)
{
	barrier();
	if (!ksu_su_compat_enabled)
		return false;

	barrier();
	if (likely(!!current->seccomp.mode))
		return false;

	// with seccomp check above, we can make this neutral
	if (!ksu_is_allow_uid_for_current(current_uid().val))
		return false;

	// first check the pointer-to-pointer
	if (unlikely(!ptr_to_check))
		return false;

	// now dereference pointer-to-pointer to check actual pointer
	if (unlikely(!*ptr_to_check))
		return false;

	return true;
}

static noinline int ksu_sucompat_user_common(const char __user **filename_user,
				const char *syscall_name,
				const bool escalate)
{
	const char su[] = SU_PATH;
	char path[sizeof(su)];

	// it seems this is actually the slowest part
	// so we peek a word first.
	if (ksu_copy_from_user_retry(path, *filename_user, sizeof(uintptr_t)))
		return 0;

	if (*(uintptr_t *)path != *(uintptr_t *)su)
		return 0;

	if (ksu_copy_from_user_retry(path + sizeof(uintptr_t), *filename_user + sizeof(uintptr_t), sizeof(path) - sizeof(uintptr_t)))
		return 0;

	if (!!__builtin_memcmp(path + sizeof(uintptr_t), su + sizeof(uintptr_t), sizeof(su) - sizeof(uintptr_t) ))
		return 0;

	if (!escalate)
		goto no_escalate;

	if (!!escape_with_root_profile())
		return 0;

	// NOTE: we only check file existence, not exec success!
	struct path kpath;
	if (!!kern_path("/data/adb/ksud", 0, &kpath))
		goto no_ksud;

	path_put(&kpath);
	pr_info("%s su->ksud!\n", syscall_name);
	*filename_user = ksud_user_path();
	return 0;

no_ksud:
no_escalate:
	pr_info("%s su->sh!\n", syscall_name);
	*filename_user = sh_user_path();
	return 0;

}

// sys_faccessat
int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *__unused_flags)
{
	if (!is_su_allowed((const void **)filename_user))
		return 0;

	return ksu_sucompat_user_common(filename_user, "faccessat", false);
}

// sys_newfstatat, sys_fstat64
int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	if (!is_su_allowed((const void **)filename_user))
		return 0;

	return ksu_sucompat_user_common(filename_user, "newfstatat", false);
}

// sys_execve, compat_sys_execve
static int ksu_handle_execve_sucompat(int *fd, const char __user **filename_user, void *argv, void *envp, int *flags)
{
	sys_execve_escape_ksud((void *)filename_user);

	if (!is_su_allowed((const void **)filename_user))
		return 0;

	return ksu_sucompat_user_common(filename_user, "sys_execve", true);
}

static __always_inline int ksu_sucompat_kernel_common(void **filename_ptr, void *argv, void *envp, const char *function_name)
{
	kernel_execve_escape_ksud((void *)filename_ptr);

	if (!is_su_allowed((const void **)filename_ptr))
		return 0;

	const char su[] = SU_PATH;

	// it seems this is actually the slowest part
	// so we peek a word first.
	if (*(uintptr_t *)(*filename_ptr) != *(uintptr_t *)su)
		return 0;

	// getname_flags pads this so nothing to worry about
	if (likely(!!__builtin_memcmp(*filename_ptr + sizeof(uintptr_t), su + sizeof(uintptr_t), sizeof(su) - sizeof(uintptr_t) )))
		return 0;

	if (!!escape_with_root_profile())
		return 0;

	// NOTE: we only check file existence, not exec success!
	struct path kpath;
	if (!!kern_path("/data/adb/ksud", 0, &kpath))
		goto no_ksud;

	path_put(&kpath);
	pr_info("%s su->ksud!\n", function_name);
	memcpy(*filename_ptr, KSUD_PATH, sizeof(KSUD_PATH));
	return 0;

no_ksud:
	pr_info("%s su->sh!\n", function_name);
	memcpy(*filename_ptr, SH_PATH, sizeof(SH_PATH));
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
// for do_execveat_common / do_execve_common on >= 3.14
// take note: struct filename **filename
int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)
{
	return ksu_sucompat_kernel_common((void **)&(*filename_ptr)->name, argv, envp, "do_execveat_common");
}
#else
// for do_execve_common on < 3.14
// take note: char **filename
int ksu_legacy_execve_sucompat(const char **filename_ptr, void *argv, void *envp)
{
	return ksu_sucompat_kernel_common((void **)filename_ptr, argv, envp, "do_execve_common");
}
#endif

static void ksu_sucompat_enable()
{
	ksu_su_compat_enabled = true;
	pr_info("%s: hooks enabled: exec, faccessat, stat\n", __func__);
}

static void ksu_sucompat_disable()
{
	ksu_su_compat_enabled = false;
	pr_info("%s: hooks disabled: exec, faccessat, stat\n", __func__);
}

static int su_compat_feature_get(u64 *value)
{
	*value = ksu_su_compat_enabled ? 1 : 0;
	return 0;
}

static int su_compat_feature_set(u64 value)
{
	bool enable = value != 0;

	if (enable == ksu_su_compat_enabled) {
		pr_info("su_compat: no need to change\n");
	return 0;
	}

	if (enable) {
		ksu_sucompat_enable();
	} else {
		ksu_sucompat_disable();
	}

	ksu_su_compat_enabled = enable;
	pr_info("su_compat: set to %d\n", enable);

	return 0;
}

static const struct ksu_feature_handler su_compat_handler = {
	.feature_id = KSU_FEATURE_SU_COMPAT,
	.name = "su_compat",
	.get_handler = su_compat_feature_get,
	.set_handler = su_compat_feature_set,
};

// sucompat: permited process can execute 'su' to gain root access.
void __init ksu_sucompat_init()
{
	if (ksu_register_feature_handler(&su_compat_handler)) {
		pr_err("Failed to register su_compat feature handler\n");
	}
}

void __exit ksu_sucompat_exit()
{
	ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
