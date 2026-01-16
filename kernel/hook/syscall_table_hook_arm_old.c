#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <asm/ptrace.h>

#ifndef CONFIG_ARM
#error "only meant for ARM"
#endif

#define FORCE_VOLATILE(x) *(volatile typeof(x) *)&(x)

extern void *sys_call_table[];

#define __ARMEABI_reboot	88
#define __ARMEABI_execve	11
#define __ARMEABI_faccessat	334
#define __ARMEABI_fstatat64	327
#define __ARMEABI_fstat64	197
#define __ARMEABI_read		3

asmlinkage long (*armeabi_reboot)(int magic1, int magic2, unsigned int cmd, void __user *arg) __read_mostly = NULL;
asmlinkage long hook_armeabi_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
	return armeabi_reboot(magic1, magic2, cmd, arg);
}

// only used as storage!
uintptr_t armeabi_execve __read_mostly = NULL;

__attribute__((used))
asmlinkage long hook_armeabi_execve(const char __user *filenamei,
			  const char __user *const __user *argv,
			  const char __user *const __user *envp, struct pt_regs *regs)
{
	ksu_handle_execve(&filenamei, (void ***)&argv, (void ***)&envp);
	return sys_execve(filenamei, argv, envp, regs);
}

/* // arch/arm/kernel/entry-common.S
 *
 * sys_execve_wrapper:
 *		add	r3, sp, #S_OFF
 *		b	sys_execve
 * ENDPROC(sys_execve_wrapper)
 *
 */
#define S_OFF "8"
__attribute__((used, naked))
static noinline void ksu_sys_execve_wrapper()
{
	asm volatile(
		"add r3, sp, #" S_OFF "\n"
		"b   hook_armeabi_execve\n"
	);
}

asmlinkage long (*armeabi_faccessat)(int dfd, const char __user * filename, int mode) __read_mostly = NULL;
asmlinkage long hook_armeabi_faccessat(int dfd, const char __user * filename, int mode)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return armeabi_faccessat(dfd, filename, mode);
}

asmlinkage long (*armeabi_fstatat64)(int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag) __read_mostly = NULL;
asmlinkage long hook_armeabi_fstatat64(int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag)
{
	ksu_handle_stat(&dfd, &filename, &flag);
	return armeabi_fstatat64(dfd, filename, statbuf, flag);
}

asmlinkage long (*armeabi_fstat64)(unsigned long fd, struct stat64 __user * statbuf) __read_mostly = NULL;
asmlinkage long hook_armeabi_fstat64_ret(unsigned long fd, struct stat64 __user * statbuf)
{
	// we handle it like rp
	long ret = armeabi_fstat64(fd, statbuf);
	ksu_handle_fstat64_ret(&fd, &statbuf);
	return ret;
}

asmlinkage long (*armeabi_read)(unsigned int fd, char __user *buf, size_t count) __read_mostly = NULL;
asmlinkage long hook_armeabi_read(unsigned int fd, char __user *buf, size_t count)
{
	ksu_handle_sys_read_fd(fd);
	return armeabi_read(fd, buf, count);
}

static DEFINE_MUTEX(sucompat_toggle_mutex);

static void syscall_table_sucompat_enable()
{
	void **sctable = (void **)sys_call_table;

	mutex_lock(&sucompat_toggle_mutex);

	preempt_disable();
	local_irq_disable();

	if (!armeabi_execve) {
		*(void **)&armeabi_execve = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_execve]);
		FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_execve]) = ksu_sys_execve_wrapper;
	}

	if (!armeabi_faccessat) {
		*(void **)&armeabi_faccessat = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_faccessat]);
		FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_faccessat]) = hook_armeabi_faccessat;
	}

	if (!armeabi_fstatat64) {
		*(void **)&armeabi_fstatat64 = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_fstatat64]);
		FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_fstatat64]) = hook_armeabi_fstatat64;
	}

	local_irq_enable();
	preempt_enable();

	flush_cache_all();
	smp_mb();

	mutex_unlock(&sucompat_toggle_mutex);
}

static void syscall_table_sucompat_disable()
{
	void **sctable = (void **)sys_call_table;

	mutex_lock(&sucompat_toggle_mutex);

	preempt_disable();
	local_irq_disable();

	if (armeabi_execve) {
		FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_execve]) = armeabi_execve;
		*(void **)&armeabi_execve = NULL;
	}

	if (armeabi_faccessat) {
		FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_faccessat]) = armeabi_faccessat;
		*(void **)&armeabi_faccessat = NULL;
	}

	if (armeabi_fstatat64) {
		FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_fstatat64]) = armeabi_fstatat64;
		*(void **)&armeabi_fstatat64 = NULL;
	}

	local_irq_enable();
	preempt_enable();

	flush_cache_all();
	smp_mb();

	mutex_unlock(&sucompat_toggle_mutex);
}

static int patch_sctable_stop_machine(void *data)
{
	void **sctable = (void **)sys_call_table;

	*(void **)&armeabi_reboot = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_reboot]);
	FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_reboot]) = hook_armeabi_reboot;

	*(void **)&armeabi_execve = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_execve]);
	FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_execve]) = ksu_sys_execve_wrapper;

	*(void **)&armeabi_faccessat = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_faccessat]);
	FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_faccessat]) = hook_armeabi_faccessat;

	*(void **)&armeabi_fstatat64 = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_fstatat64]);
	FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_fstatat64]) = hook_armeabi_fstatat64;

	*(void **)&armeabi_read = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_read]);
	FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_read]) = hook_armeabi_read;

	// *(void **)&armeabi_fstat64 = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_fstat64]);
	// FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_fstat64]) = hook_armeabi_fstat64_ret;

	flush_cache_all(); // this is important!
	smp_mb();

	pr_info("%s: patched syscall table! \n", __func__);
	return 0;
}

static int ksu_syscall_table_restore()
{
	if (!sys_call_table)
		return 0;

	set_user_nice(current, 19); // low prio

loop_start:

	msleep(1000);

	if (*(volatile bool *)&ksu_vfs_read_hook)
		goto loop_start;

	if (!hook_armeabi_read)
		return 0;

	pr_info("%s: restore read syscall! \n", __func__);
	
	void **sctable = (void **)sys_call_table;

	preempt_disable();

	FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_read]) = armeabi_read;

	preempt_enable();

	flush_cache_all(); // this is important!
	smp_mb();

	return 0;
}

static __init int ksu_syscall_table_hook_init()
{
	stop_machine(patch_sctable_stop_machine, NULL, NULL);
	kthread_run(ksu_syscall_table_restore, NULL, "unhook");
	return 0;
}
late_initcall(ksu_syscall_table_hook_init);

// EOF
