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

#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) && defined(KSU_CAN_USE_JUMP_LABEL)
DEFINE_STATIC_KEY_TRUE(ksud_sucompat_key);
static inline void ksu_sucompat_enable_branch()
{
	pr_info("su_compat: enable sucompat branches\n");
	static_branch_enable(&ksud_sucompat_key);
	smp_mb();
}
static inline void ksu_sucompat_disable_branch()
{
	pr_info("su_compat: remove sucompat branches\n");
	static_branch_disable(&ksud_sucompat_key);
	smp_mb();
}
#else
static inline void ksu_sucompat_enable_branch() { } // no-op
static inline void ksu_sucompat_disable_branch() { } // no-op
#endif

__attribute__((hot))
static __always_inline bool is_su_allowed(const void **ptr_to_check)
{
#ifndef CONFIG_KSU_TAMPER_SYSCALL_TABLE
#ifdef KSU_CAN_USE_JUMP_LABEL
	// read as: if not 'likely' disabled
	if (!!!static_branch_likely(&ksud_sucompat_key))
		return false;
#else
	if (!ksu_su_compat_enabled)
		return false;
#endif // KSU_CAN_USE_JUMP_LABEL
#endif

	if (likely(test_thread_flag(TIF_SECCOMP)))
		return false;

	// see seccomp check above
	// so if its root but not ksu domain, deny, see __ksu_is_allow_uid_for_current
	// actually, we can likely skip this step?
	uid_t uid = current_uid().val;
	if (!!uid)
		goto uid_check;

	if (!is_ksu_domain())
		return false;
	goto check_ptr;

	// NOTE: shell has its seccomp disabled, so we only need to check for this thing
	// short-circuit if not shell! as we allow apps on setuid lsm by disabling seccomp
uid_check:
	if (likely(uid != 2000))
		goto check_ptr;

	// use internal function, not the macro
	if (!__ksu_is_allow_uid(uid))
		return false;

check_ptr:
	// first check the pointer-to-pointer
	if (unlikely(!ptr_to_check))
		return false;

	// now dereference pointer-to-pointer to check actual pointer
	if (unlikely(!*ptr_to_check))
		return false;

	return true;
}

static __always_inline void ksu_sucompat_user_common(const char __user **filename_user,
				const char *syscall_name,
				const bool escalate)
{
	uintptr_t buf;
	const char su[] = SU_PATH;

	// sugar prep
	uintptr_t *su_p = (uintptr_t *)su;
	uintptr_t __user *fn_p = (uintptr_t *)untagged_addr(*(char **)filename_user);

	// assert /system/bin/su\0 = 15 bytes.
	BUILD_BUG_ON(sizeof(su) > 16); // compielr might to pad
	BUILD_BUG_ON(sizeof(su) < 15);

	/*
	 * it seems this is actually the slowest part, we peek last word first to speed it up
	 * NOTE: get_user rets EFAULT on err, so if we are copying a pointer
	 * that goes to nothing, we also detect that and ret fast
	 *
	 * first read overreads, reading 8 bytes, "bin/su\0?" /  4 bytes, "su\0?" when we only need 7/3
	 * but this is fine as we are guaranteed alignment, hardware provides trailing garbeg
	 * if it is specially crafted and hits a page guard, we just get EFAULT anyway
	 *
	 * on 64-bit we do this in 2 word compare, 4 on 32-bit
	 *
	 * we can do some bitmasking 0xFFFFFF blah blah to do that tail compare (7 or 3 bytes), 
	 * but hot damn I hate that shit, lets just have __builtin_memcmp do it for us
	 *
	 */

#ifdef CONFIG_64BIT
	if (get_user(buf, &fn_p[1]))
		return;

	if (likely(!!__builtin_memcmp(&buf, su + sizeof(uintptr_t), sizeof(su) - sizeof(uintptr_t) )))
		return;
#else
	if (get_user(buf, &fn_p[3]))
		return;

	if (likely(!!__builtin_memcmp(&buf, su +  (3 * sizeof(uintptr_t)), sizeof(su) - (3 * sizeof(uintptr_t)) )))
		return;

	if (unlikely(get_user(buf, &fn_p[2])))
		return;

	if (buf != su_p[2])
		return;

	if (unlikely(get_user(buf, &fn_p[1])))
		return;

	if (unlikely(buf != su_p[1]))
		return;
#endif
	// last word
	if (unlikely(get_user(buf, &fn_p[0])))
		return;

	if (unlikely(buf != su_p[0]))
		return;

	if (!escalate)
		goto no_escalate;

#ifdef CONFIG_KSU_FEATURE_SULOG
	ksu_sulog_emit(KSU_SULOG_EVENT_SUCOMPAT, NULL, NULL, GFP_KERNEL);
#endif
	if (!!escape_with_root_profile())
		return;

	// NOTE: we only check file existence, not exec success!
	struct path kpath;
	if (!!kern_path("/data/adb/ksud", 0, &kpath))
		goto no_ksud;

	path_put(&kpath);
	pr_info("%s su->ksud!\n", syscall_name);
	*filename_user = ksud_user_path();
	return;

no_ksud:
no_escalate:
	pr_info("%s su->sh!\n", syscall_name);
	*filename_user = sh_user_path();
	return;

}

// sys_faccessat
int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *__unused_flags)
{
	if (!is_su_allowed((const void **)filename_user))
		return 0;

	ksu_sucompat_user_common(filename_user, "faccessat", false);
	return 0;
}

// sys_newfstatat, sys_fstat64
int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	if (!is_su_allowed((const void **)filename_user))
		return 0;

	ksu_sucompat_user_common(filename_user, "newfstatat", false);
	return 0;
}

// sys_execve, compat_sys_execve
int ksu_handle_execve(const char __user **filename_user, void *argv, void *envp)
{
	sys_execve_escape_ksud((void *)filename_user);

	if (!is_su_allowed((const void **)filename_user))
		return 0;

	ksu_sucompat_user_common(filename_user, "sys_execve", true);
	return 0;
}

static __always_inline void ksu_sucompat_kernel_common(void **filename_ptr, void *argv, void *envp, const char *function_name)
{
	kernel_execve_escape_ksud((void *)filename_ptr);

	if (!is_su_allowed((const void **)filename_ptr))
		return;

	// it seems this is actually the slowest part, we peek last word first to speed it up
	// sugar prep
	const char su[] = SU_PATH;
	uintptr_t *su_p = (uintptr_t *)su;
	uintptr_t *fn_p = (uintptr_t *)*(char **)filename_ptr;

	// assert /system/bin/su\0 = 15 bytes.
	BUILD_BUG_ON(sizeof(su) > 16); // compielr might to pad
	BUILD_BUG_ON(sizeof(su) < 15);

	// getname_flags pads this so nothing to worry about, dereference with confidence!
#ifdef CONFIG_64BIT
	if (likely(!!__builtin_memcmp(&fn_p[1], &su_p[1], sizeof(su) - sizeof(uintptr_t) )))
		return;
#else
	if (likely(!!__builtin_memcmp(&fn_p[3], &su_p[3], sizeof(su) - (3 * sizeof(uintptr_t)) )))
		return;

	if (fn_p[2] != su_p[2])
		return;

	if (fn_p[1] != su_p[1])
		return;
#endif

	if (unlikely(fn_p[0] != su_p[0]))
		return;

#ifdef CONFIG_KSU_FEATURE_SULOG
	ksu_sulog_emit(KSU_SULOG_EVENT_SUCOMPAT, NULL, NULL, GFP_KERNEL);
#endif
	if (!!escape_with_root_profile())
		return;

	// NOTE: we only check file existence, not exec success!
	struct path kpath;
	if (!!kern_path("/data/adb/ksud", 0, &kpath))
		goto no_ksud;

	path_put(&kpath);
	pr_info("%s su->ksud!\n", function_name);
	memcpy(*filename_ptr, KSUD_PATH, sizeof(KSUD_PATH));
	return;

no_ksud:
	pr_info("%s su->sh!\n", function_name);
	memcpy(*filename_ptr, SH_PATH, sizeof(SH_PATH));
	return;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
// take note: struct filename **filename, for do_execveat_common / do_execve_common on >= 3.14
int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)
{
	struct filename *filename = *filename_ptr;
	if (IS_ERR(filename)) // see getname_flags
		return 0;

	ksu_sucompat_kernel_common((void **)&filename->name, argv, envp, "do_execveat_common");
	return 0;
}
#else
// take note: char **filename, for do_execve_common on < 3.14
int ksu_legacy_execve_sucompat(const char **filename_ptr, void *argv, void *envp)
{
	ksu_sucompat_kernel_common((void **)filename_ptr, argv, envp, "do_execve_common");
	return 0;
}
#endif

#ifdef CONFIG_KSU_TAMPER_SYSCALL_TABLE
static void syscall_table_sucompat_enable();
static void syscall_table_sucompat_disable();
#else
static inline void syscall_table_sucompat_enable() { } // no-op
static inline void syscall_table_sucompat_disable() { } // no-op
#endif

static void ksu_sucompat_enable()
{

	ksu_sucompat_enable_branch();
	syscall_table_sucompat_enable();

	ksu_su_compat_enabled = true;
	pr_info("%s: hooks enabled: exec, faccessat, stat\n", __func__);
}

static void ksu_sucompat_disable()
{

	ksu_sucompat_disable_branch();
	syscall_table_sucompat_disable();

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
