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

#include "objsec.h"
#include "allowlist.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "kernel_compat.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

extern void escape_to_root();

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

static long ksu_strncpy_from_user_retry(char *dst, 
			const void __user *unsafe_addr, long count)
{
	long ret = ksu_strncpy_from_user_nofault(dst, unsafe_addr, count);
	if (likely(ret >= 0))
		return ret;

	// we faulted! fallback to slow path
	if (unlikely(!ksu_access_ok(unsafe_addr, count)))
		return -EFAULT;

	return strncpy_from_user(dst, unsafe_addr, count);
}

// every little bit helps here
__attribute__((hot, no_stack_protector))
static __always_inline bool is_su_allowed(const void *ptr_to_check)
{
	barrier();

	if (likely(!ksu_is_allow_uid(current_uid().val)))
		return false;

	if (unlikely(!ptr_to_check))
		return false;

	return true;
}

static int ksu_sucompat_user_common(const char __user **filename_user,
				const char *syscall_name,
				const bool escalate)
{
	const char su[] = SU_PATH;

	char path[sizeof(su)]; // sizeof includes nullterm already!
	long len = ksu_strncpy_from_user_retry(path, *filename_user, sizeof(path));
	if (len <= 0) // sizeof(su) is not zero
		return 0;

	path[sizeof(path) - 1] = '\0';

	if (memcmp(path, su, sizeof(su)))
		return 0;

	if (escalate) {
		pr_info("%s su found\n", syscall_name);
		*filename_user = ksud_user_path();
		escape_to_root(); // escalate !!
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
	if (!is_su_allowed((const void *)filename_user))
		return 0;

	return ksu_sucompat_user_common(filename_user, "faccessat", false);
}

// sys_newfstatat, sys_fstat64
int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	if (!is_su_allowed((const void *)filename_user))
		return 0;

	return ksu_sucompat_user_common(filename_user, "newfstatat", false);
}

// sys_execve, compat_sys_execve
int ksu_handle_execve_sucompat(int *fd, const char __user **filename_user,
			       void *__never_use_argv, void *__never_use_envp,
			       int *__never_use_flags)
{
	if (!is_su_allowed((const void *)filename_user))
		return 0;

	return ksu_sucompat_user_common(filename_user, "sys_execve", true);
}

// the call from execve_handler_pre won't provided correct value for __never_use_argument, use them after fix execve_handler_pre, keeping them for consistence for manually patched code
int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *__never_use_argv, void *__never_use_envp,
				 int *__never_use_flags)
{
	struct filename *filename;
	const char sh[] = KSUD_PATH;
	const char su[] = SU_PATH;

	if (!is_su_allowed((const void *)filename_ptr))
		return 0;

	filename = *filename_ptr;
	if (IS_ERR(filename)) {
		return 0;
	}

	if (likely(memcmp(filename->name, su, sizeof(su))))
		return 0;

	pr_info("do_execveat_common su found\n");
	memcpy((void *)filename->name, sh, sizeof(sh));

	escape_to_root();

	return 0;
}

int ksu_handle_devpts(struct inode *inode)
{
	barrier();

	if (!current->mm) {
		return 0;
	}

	uid_t uid = current_uid().val;
	if (uid % 100000 < 10000) {
		// not untrusted_app, ignore it
		return 0;
	}

	if (!ksu_is_allow_uid(uid))
		return 0;

	if (ksu_devpts_sid) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
		struct inode_security_struct *sec = selinux_inode(inode);
#else
		struct inode_security_struct *sec =
			(struct inode_security_struct *)inode->i_security;
#endif
		if (sec) {
			sec->sid = ksu_devpts_sid;
		}
	}

	return 0;
}

// sucompat: permited process can execute 'su' to gain root access.
void ksu_sucompat_init()
{
}

void ksu_sucompat_exit()
{
}
