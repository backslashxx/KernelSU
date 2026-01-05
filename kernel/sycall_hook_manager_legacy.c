#include <asm/syscall.h>

#define FORCE_VOLATILE(x) *(volatile typeof(x) *)&(x)

// on 4.19+ its is no longer just a void *sys_call_table[]
// it becomes syscall_fn_t sys_call_table[];
// ref: https://github.com/wszxl516/syscall_hook/blob/master/src/custom_syscall.c

// compiles but not tested!!
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)

// reboot
static syscall_fn_t old_reboot; // int magic1, int magic2, unsigned int cmd, void __user *arg
static long hook_sys_reboot(const struct pt_regs *regs)
{
	int magic1 = (int)regs->regs[0];
	int magic2 = (int)regs->regs[1];
	unsigned int cmd = (unsigned int)regs->regs[2];
	void __user *arg = (void __user *)regs->regs[3];

	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
	return old_reboot(regs);
}

// execve
static syscall_fn_t old_execve; // const char __user * filename, const char __user *const __user * argv, const char __user *const __user * envp
static long hook_sys_execve(const struct pt_regs *regs)
{
	const char __user *filename = (const char __user *)regs->regs[0];
	const char __user *const __user *argv = (const char __user *const __user *)regs->regs[1];
	const char __user *const __user *envp = (const char __user *const __user *)regs->regs[2];

	ksu_handle_execve_sucompat((int *)AT_FDCWD, &filename, NULL, NULL, NULL);
	return old_execve(regs);
}

// access
static syscall_fn_t old_faccessat; // int dfd, const char __user * filename, int mode
static long hook_sys_faccessat(const struct pt_regs *regs)
{
	int dfd = (int)regs->regs[0];
	const char __user *filename = (const char __user *)regs->regs[1];
	int mode = (int)regs->regs[2];

	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return old_faccessat(regs);
}

// stat
#ifdef __NR_newfstatat
static syscall_fn_t old_newfstatat; // int dfd, const char __user * filename, struct stat __user * statbuf, int flag);
static long hook_sys_newfstatat(const struct pt_regs *regs)
{
	int dfd = (int)regs->regs[0];
	const char __user *filename = (const char __user *)regs->regs[1];
	struct stat __user *statbuf = (struct stat __user *)regs->regs[2];
	int flag = (int)regs->regs[3];

	ksu_handle_stat(&dfd, &filename, &flag);
	return old_newfstatat(regs);
}
#endif

#ifdef __NR_fstatat64
static syscall_fn_t old_fstatat64; // int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag
static long hook_sys_fstatat64(const struct pt_regs *regs)
{
	int dfd = (int)regs->regs[0];
	const char __user *filename = (const char __user *)regs->regs[1];
	struct stat64 __user *statbuf = (struct stat64 __user *)regs->regs[2];
	int flag = (int)regs->regs[3];

	ksu_handle_stat(&dfd, &filename, &flag);
	return old_fstatat64(regs);
}
#endif // __NR_fstatat64

// old_ptr is actually syscall_fn_t *
static void read_and_replace_syscall(void *old_ptr, unsigned long syscall_nr, void *new_ptr)
{
	// arch/arm64/include/asm/syscall.h
	// typedef long (*syscall_fn_t)(const struct pt_regs *regs);
	// extern const syscall_fn_t sys_call_table[];

	// so technically its just a ** / *sys_call_table[];
	syscall_fn_t *syscall_addr = (syscall_fn_t *)&sys_call_table[syscall_nr];

	vm_unmap_aliases();
	set_memory_rw(((unsigned long)syscall_addr), 1); // unlock whole page
	
	flush_tlb_kernel_range((unsigned long)syscall_addr, (unsigned long)syscall_addr + PAGE_SIZE);

	smp_mb();
	*(syscall_fn_t *)old_ptr = FORCE_VOLATILE(*syscall_addr);
	smp_mb();
	FORCE_VOLATILE(*syscall_addr) = (syscall_fn_t)new_ptr;
	smp_mb();

	vm_unmap_aliases();
	set_memory_ro(((unsigned long)syscall_addr), 1); // relock it
	
	flush_tlb_kernel_range((unsigned long)syscall_addr, (unsigned long)syscall_addr + PAGE_SIZE);

	smp_mb();
}

#else // 4.19+

// sys_reboot
static long (*old_reboot)(int magic1, int magic2, unsigned int cmd, void __user *arg);
static long hook_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
	return old_reboot(magic1, magic2, cmd, arg);
}


// execve
static long (*old_execve)(const char __user * filename, const char __user *const __user * argv, const char __user *const __user * envp);
static long hook_sys_execve(const char __user * filename,
				const char __user *const __user * argv,
				const char __user *const __user * envp)
{
	ksu_handle_execve_sucompat((int *)AT_FDCWD, &filename, NULL, NULL, NULL);
	return old_execve(filename, argv, envp);
}

// access
static long (*old_faccessat)(int dfd, const char __user * filename, int mode);
static long hook_sys_faccessat(int dfd, const char __user * filename, int mode)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return old_faccessat(dfd, filename, mode);
}


// stat
#ifdef __NR_newfstatat
static long (*old_newfstatat)(int dfd, const char __user * filename, struct stat __user * statbuf, int flag);
static long hook_sys_newfstatat(int dfd, const char __user * filename, struct stat __user * statbuf, int flag)
{
	ksu_handle_stat(&dfd, &filename, &flag);
	return old_newfstatat(dfd, filename, statbuf, flag);
}
#endif

#ifdef __NR_fstatat64
static long (*old_fstatat64)(int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag);
static long hook_sys_fstatat64(int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag)
{
	ksu_handle_stat(&dfd, &filename, &flag);
	return old_fstatat64(dfd, filename, statbuf, flag);
}
#endif // __NR_fstatat64

#if 0
#ifdef CONFIG_COMPAT
#define __NR_compat_execve 11
extern const void *compat_sys_call_table[];
static long (*old_compat_execve)(const char __user * filename, const compat_uptr_t __user * argv, const compat_uptr_t __user * envp);
static long hook_compat_sys_execve(const char __user * filename,
				const compat_uptr_t __user * argv,
				const compat_uptr_t __user * envp)
{
	ksu_handle_execve_sucompat(NULL, &filename, NULL, NULL, NULL);
	return old_compat_execve(filename, argv, envp);
}
static void read_and_replace_compat_syscall(void **old_ptr, unsigned long syscall_nr, void *new_ptr)
{
	void **syscall_addr = (void **)(compat_sys_call_table + syscall_nr);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
	set_memory_rw(((unsigned long)syscall_addr), 1); // unlock whole page
#endif
	barrier();
	*old_ptr = FORCE_VOLATILE(*syscall_addr);
	barrier();
	FORCE_VOLATILE(*syscall_addr) = new_ptr;
	barrier();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
	set_memory_ro(((unsigned long)syscall_addr), 1); // relock it
#endif

}
#endif
#endif

// old_ptr is actually void **
static void read_and_replace_syscall(void *old_ptr, unsigned long syscall_nr, void *new_ptr)
{
	// *old_ptr = READ_ONCE(*((void **)sys_call_table + syscall_nr));
	// WRITE_ONCE(*((void **)sys_call_table + syscall_nr), new_ptr);

	// the one from zx2c4 looks like above, but the issue is that we dont have 
	// READ_ONCE and WRITE_ONCE on 3.x kernels, here we just force volatile everything
	// since those are actually just forced-aligned-volatile-rw

	// void **syscall_addr = (void **)(sys_call_table + syscall_nr);
	// *(a + b) == a[b]; , a + b == &a[b];
	void **syscall_addr = (void **)&sys_call_table[syscall_nr];

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
	set_memory_rw(((unsigned long)syscall_addr), 1); // unlock whole page
#endif

	barrier();
	*(void **)old_ptr = FORCE_VOLATILE(*syscall_addr);
	barrier();
	FORCE_VOLATILE(*syscall_addr) = new_ptr;
	barrier();

	// pr_info("syscall_slot: 0x%p syscall_addr: 0x%p \n", (void *)syscall_addr, (void *)*syscall_addr);	

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
	set_memory_ro(((unsigned long)syscall_addr), 1); // relock it
#endif

	return;
}
#endif // 4.19+

void ksu_syscall_table_hook_init()
{
	preempt_disable();

	// reboot
	read_and_replace_syscall((void *)&old_reboot, __NR_reboot, &hook_sys_reboot);

	// exec
	read_and_replace_syscall((void *)&old_execve, __NR_execve, &hook_sys_execve);
	// access
	read_and_replace_syscall((void *)&old_faccessat, __NR_faccessat, &hook_sys_faccessat);

#ifdef __NR_newfstatat
	// newfstatat
	read_and_replace_syscall((void *)&old_newfstatat, __NR_newfstatat, &hook_sys_newfstatat);
#endif

#ifdef __NR_fstatat64
	// newfstatat
	read_and_replace_syscall((void *)&old_fstatat64, __NR_fstatat64, &hook_sys_fstatat64);
#endif

#if 0
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && defined(CONFIG_COMPAT)
	read_and_replace_compat_syscall((void **)&old_compat_execve, __NR_compat_execve, &hook_compat_sys_execve);
#endif
#endif

	preempt_enable();
}
