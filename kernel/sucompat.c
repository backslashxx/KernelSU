#include <linux/dcache.h>
#include <linux/security.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#else
#include <linux/sched.h>
#endif

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

static bool ksu_su_compat_enabled __read_mostly = true;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	/* To avoid having to mmap a page in userspace, just write below the stack
   * pointer. */
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}
#else
static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	if (!current->mm)
		return NULL;

	volatile unsigned long start_stack = current->mm->start_stack;
	unsigned int step = 32;
	char __user *p = NULL;
	
	do {
		p = (void __user *)(start_stack - step - len);
		if (!copy_to_user(p, d, len)) {
			/* pr_info("%s: start_stack: %lx p: %lx len: %zu\n",
				__func__, start_stack, (unsigned long)p, len ); */
			return p;
		}
		step = step + step;
	} while (step <= 2048);
	return NULL;
}
#endif

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

	if (likely(!!current->seccomp.mode))
		return false;

	// with seccomp check above, we can make this neutral
	if (!ksu_is_allow_uid_for_current(current_uid().val))
		return false;

	// first check the pointer-to-pointer
	if (unlikely(!(volatile void *)ptr_to_check))
		return false;

	// now dereference pointer-to-pointer to check actual pointer
	if (unlikely(!(volatile void *)*ptr_to_check))
		return false;

	return true;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static inline void sys_execve_escape_ksud(const char __user **filename_user)
{
	if (likely(ksu_boot_completed))
		return;

	// see if its init
	if (!is_init(get_current_cred()))
		return;

	const char ksud_path[] = KSUD_PATH;
	char path[sizeof(ksud_path)];

	// see if its trying to execute ksud
	if (ksu_copy_from_user_retry(path, *filename_user, sizeof(path)))
		return;

	if (memcmp(ksud_path, path, sizeof(path)))
		return;

	pr_info("sys_execve: escape init executing ksud with pid: %d\n", current->pid);

	escape_to_root_forced(); // give this context all permissions
	
	return;
}

static inline void kernel_execve_escape_ksud(void *filename_ptr)
{
	if (likely(ksu_boot_completed))
		return;

	// see if its init
	if (!is_init(get_current_cred()))
		return;

	if (likely(memcmp(filename_ptr, KSUD_PATH, sizeof(KSUD_PATH))))
		return;

	pr_info("kernel_execve: escape init executing ksud with pid: %d\n", current->pid);

	escape_to_root_forced(); // give this context all permissions
	
	return;
}
#else
static inline void sys_execve_escape_ksud(const char __user **filename_user) { } // no-op
static inline void kernel_execve_escape_ksud(void *filename_ptr) {} // no-op
#endif

static int ksu_sucompat_user_common(const char __user **filename_user,
				const char *syscall_name,
				const bool escalate,
				const uint8_t sym)
{
	const char su[] = SU_PATH;

	char path[sizeof(su)]; // sizeof includes nullterm already!
	if (ksu_copy_from_user_retry(path, *filename_user, sizeof(path)))
		return 0;

	// what we shouldve copied should've been preterminated!
	// path[sizeof(path) - 1] = '\0';

	if (memcmp(path, su, sizeof(su)))
		return 0;

	write_sulog(sym);

	if (escalate) {
		pr_info("%s su found\n", syscall_name);
		*filename_user = ksud_user_path();
		escape_with_root_profile(); // escalate !!
	} else {
		pr_info("%s su->sh!\n", syscall_name);
		*filename_user = sh_user_path();
	}

	return 0;
}

// sys_faccessat
int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
			 int *__unused_flags)
{
	if (!is_su_allowed((const void **)filename_user))
		return 0;

	return ksu_sucompat_user_common(filename_user, "faccessat", false, 'a');
}

// sys_newfstatat, sys_fstat64
int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	if (!is_su_allowed((const void **)filename_user))
		return 0;

	return ksu_sucompat_user_common(filename_user, "newfstatat", false, 's');
}

// sys_execve, compat_sys_execve
int ksu_handle_execve_sucompat(int *fd, const char __user **filename_user,
			       void *__never_use_argv, void *__never_use_envp,
			       int *__never_use_flags)
{
	sys_execve_escape_ksud(filename_user);

	if (!is_su_allowed((const void **)filename_user))
		return 0;

	return ksu_sucompat_user_common(filename_user, "sys_execve", true, 'x');
}

// getname_flags on fs/namei.c, this hooks ALL fs-related syscalls.
// NOT RECOMMENDED for daily use. mostly for debugging purposes.
int ksu_getname_flags_user(const char __user **filename_user, int flags)
{
	if (!is_su_allowed((const void **)filename_user))
		return 0;

	// sys_execve always calls getname, which sets flags = 0 on getname_flags
	// we can use it to deduce if caller is likely execve

	uint8_t sym = '$';
	bool escalate = false;
	
	if (!flags) {
		escalate = true;
		sym = 'x';
	}

	return ksu_sucompat_user_common(filename_user, "getname_flags", escalate, sym);
}

static int ksu_sucompat_kernel_common(void *filename_ptr, const char *function_name, bool escalate, const uint8_t sym)
{

	if (likely(memcmp(filename_ptr, SU_PATH, sizeof(SU_PATH))))
		return 0;

	write_sulog(sym);

	if (escalate) {
		pr_info("%s su found\n", function_name);
		memcpy(filename_ptr, KSUD_PATH, sizeof(KSUD_PATH));
		escape_with_root_profile();
	} else {
		pr_info("%s su->sh\n", function_name);
		memcpy(filename_ptr, SH_PATH, sizeof(SH_PATH));
	}
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
// for do_execveat_common / do_execve_common on >= 3.14
// take note: struct filename **filename
int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *__never_use_argv, void *__never_use_envp,
				 int *__never_use_flags)
{
	kernel_execve_escape_ksud((void *)(*filename_ptr)->name);

	if (!is_su_allowed((const void **)filename_ptr))
		return 0;

	// struct filename *filename = *filename_ptr;
	// return ksu_do_execveat_common((void *)filename->name, "do_execveat_common");
	// nvm this, just inline

	return ksu_sucompat_kernel_common((void *)(*filename_ptr)->name, "do_execveat_common", true, 'x');
}

// for compatibility to old hooks
int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
			void *envp, int *flags)
{
	kernel_execve_escape_ksud((void *)(*filename_ptr)->name);

	if (!is_su_allowed((const void **)filename_ptr))
		return 0;

	return ksu_sucompat_kernel_common((void *)(*filename_ptr)->name, "do_execveat_common", true, 'x');
}
#else
// for do_execve_common on < 3.14
// take note: char **filename
int ksu_legacy_execve_sucompat(const char **filename_ptr,
				 void *__never_use_argv,
				 void *__never_use_envp)
{
	kernel_execve_escape_ksud((void *)*filename_ptr);

	if (!is_su_allowed((const void **)filename_ptr))
		return 0;

	return ksu_sucompat_kernel_common((void *)*filename_ptr, "do_execve_common", true, 'x');
}
#endif

// vfs_statx for 5.18+
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
int ksu_handle_vfs_statx(void *__never_use_dfd, struct filename **filename_ptr,
			void *__never_use_flags, void **__never_use_stat,
			void *__never_use_request_mask)
{
	if (!is_su_allowed((const void **)filename_ptr))
		return 0;

	return ksu_sucompat_kernel_common((void *)(*filename_ptr)->name, "vfs_statx", false, 's');
}
#endif

// getname_flags on fs/namei.c, this hooks ALL fs-related syscalls.
// put the hook right after usercopy
// NOT RECOMMENDED for daily use. mostly for debugging purposes.
int ksu_getname_flags_kernel(char **kname, int flags)
{
	if (!is_su_allowed((const void **)kname))
		return 0;

	uint8_t sym = '$';
	bool escalate = false;
	
	if (!flags) {
		escalate = true;
		sym = 'x';
	}

	return ksu_sucompat_kernel_common((void *)*kname, "getname_flags", escalate, sym);
}

#ifdef CONFIG_KSU_TAMPER_SYSCALL_TABLE
static void syscall_table_sucompat_enable();
static void syscall_table_sucompat_disable();
#endif

#ifdef CONFIG_KSU_KRETPROBES_SUCOMPAT
static void rp_sucompat_exit();
static void rp_sucompat_init();
#endif

static void ksu_sucompat_enable()
{

#ifdef CONFIG_KSU_TAMPER_SYSCALL_TABLE
	syscall_table_sucompat_enable();
#endif

#ifdef CONFIG_KSU_KRETPROBES_SUCOMPAT
	rp_sucompat_init();
#endif

	ksu_su_compat_enabled = true;
	pr_info("%s: hooks enabled: exec, faccessat, stat\n", __func__);
}

static void ksu_sucompat_disable()
{

#ifdef CONFIG_KSU_TAMPER_SYSCALL_TABLE
	syscall_table_sucompat_disable();
#endif

#ifdef CONFIG_KSU_KRETPROBES_SUCOMPAT
	rp_sucompat_exit();
#endif

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
void ksu_sucompat_init()
{
	if (ksu_register_feature_handler(&su_compat_handler)) {
		pr_err("Failed to register su_compat feature handler\n");
	}
}

void ksu_sucompat_exit()
{
	ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
