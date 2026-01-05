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

static uintptr_t armeabi_reboot __read_mostly = NULL;
static long hook_armeabi_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
	return sys_reboot(magic1, magic2, cmd, arg);
}

static uintptr_t armeabi_execve __read_mostly = NULL;
__attribute__((used, noipa))
static long hook_armeabi_execve(const char __user *filenamei,
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

static uintptr_t armeabi_faccessat __read_mostly = NULL;
static long hook_armeabi_faccessat(int dfd, const char __user * filename, int mode)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return sys_faccessat(dfd, filename, mode);
}

static uintptr_t armeabi_fstatat64 __read_mostly = NULL;
static long hook_armeabi_fstatat64(int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag)
{
	ksu_handle_stat(&dfd, &filename, &flag);
	return sys_fstatat64(dfd, filename, statbuf, flag);
}

static uintptr_t armeabi_fstat64 __read_mostly = NULL;
static long hook_armeabi_fstat64_ret(unsigned long fd, struct stat64 __user * statbuf)
{
	// we handle it like rp
	long ret = sys_fstat64(fd, statbuf);
	ksu_handle_fstat64_ret(&fd, &statbuf);
	return ret;
}

static uintptr_t armeabi_read __read_mostly = NULL;
static long hook_armeabi_read(unsigned int fd, char __user *buf, size_t count)
{
	ksu_handle_sys_read_fd(fd);
	return sys_read(fd, buf, count);
}

static inline int patch_sctable()
{
	void **sctable = (void **)sys_call_table;

	preempt_disable();
	local_irq_disable();

	*(void **)&armeabi_reboot = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_reboot]);
	FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_reboot]) = hook_armeabi_reboot;

	*(void **)&armeabi_execve = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_execve]);
	FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_execve]) = ksu_sys_execve_wrapper;

	*(void **)&armeabi_faccessat = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_faccessat]);
	FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_faccessat]) = hook_armeabi_faccessat;

	*(void **)&armeabi_fstatat64 = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_fstatat64]);
	FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_fstatat64]) = hook_armeabi_fstatat64;

	// TODO: unhook this
	*(void **)&armeabi_read = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_read]);
	FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_read]) = hook_armeabi_read;

	// *(void **)&armeabi_fstat64 = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_fstat64]);
	// FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_fstat64]) = hook_armeabi_fstat64_ret;

	local_irq_enable();
	preempt_enable();

	flush_cache_all(); // this is important!
	smp_mb();

	pr_info("%s: patched syscall table! \n", __func__);
	return 0;
}

#if 0
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
#endif

static __init int ksu_syscall_table_hook_init()
{
	patch_sctable();

	// kthread_run(ksu_syscall_table_restore, NULL, "unhook");
	return 0;
}
late_initcall(ksu_syscall_table_hook_init);

// EOF
