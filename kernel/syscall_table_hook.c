#include <asm/syscall.h>

#define FORCE_VOLATILE(x) *(volatile typeof(x) *)&(x)

// compiles but not tested!!
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)

#error "syscall table tampering is probably broken on 4.19+ !!! unfixed! might fail!" // remove this shit if you really want it

// on 4.19+ its is no longer just a void *sys_call_table[]
// it becomes syscall_fn_t sys_call_table[];
// ref: https://github.com/wszxl516/syscall_hook/blob/master/src/custom_syscall.c

#if 0

// reboot
#define __NATIVE_reboot 142 //__NR_reboot
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
#define __NATIVE_execve 221 // __NR_execve
static syscall_fn_t old_execve; // const char __user * filename, const char __user *const __user * argv, const char __user *const __user * envp
static long hook_sys_execve(const struct pt_regs *regs)
{
	const char __user *filename = (const char __user *)regs->regs[0];
	//const char __user *const __user *argv = (const char __user *const __user *)regs->regs[1];
	//const char __user *const __user *envp = (const char __user *const __user *)regs->regs[2];

	ksu_handle_execve_sucompat((int *)AT_FDCWD, &filename, NULL, NULL, NULL);
	return old_execve(regs);
}

// access
#define __NATIVE_faccessat 48 // __NR_faccessat
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
#define __NATIVE_newfstatat 79 // __NR_newfstatat, __NR3264_fstatat
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

// old_ptr is actually syscall_fn_t *
static void read_and_replace_syscall(void *old_ptr, unsigned long syscall_nr, void *new_ptr, void *unused_ptr)
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
#endif

void ksu_syscall_table_hook_init() { }

#else // 4.19+

// native syscalls
// ref: https://elixir.bootlin.com/linux/v4.14.1/source/include/uapi/asm-generic/unistd.h

// sys_reboot
#define __NATIVE_reboot 142 //__NR_reboot
static long (*old_reboot)(int magic1, int magic2, unsigned int cmd, void __user *arg);
static long hook_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
	return old_reboot(magic1, magic2, cmd, arg);
}

// execve
#define __NATIVE_execve 221 // __NR_execve
static long (*old_execve)(const char __user * filename,
				const char __user *const __user * argv,
				const char __user *const __user * envp);
static long hook_sys_execve(const char __user * filename,
				const char __user *const __user * argv,
				const char __user *const __user * envp)
{
	ksu_handle_execve_sucompat((int *)AT_FDCWD, &filename, NULL, NULL, NULL);
	return old_execve(filename, argv, envp);
}

// access
#define __NATIVE_faccessat 48 // __NR_faccessat
static long (*old_faccessat)(int dfd, const char __user * filename, int mode);
static long hook_sys_faccessat(int dfd, const char __user * filename, int mode)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return old_faccessat(dfd, filename, mode);
}

// stat
#define __NATIVE_newfstatat 79 // __NR_newfstatat, __NR3264_fstatat
static long (*old_newfstatat)(int dfd, const char __user * filename, struct stat __user * statbuf, int flag);
static long hook_sys_newfstatat(int dfd, const char __user * filename, struct stat __user * statbuf, int flag)
{
	ksu_handle_stat(&dfd, &filename, &flag);
	return old_newfstatat(dfd, filename, statbuf, flag);
}

#define __NATIVE_newfstat 80 // __NR3264_fstat
static long (*old_newfstat)(unsigned int fd, struct stat __user * statbuf);
static long hook_sys_newfstat_ret(unsigned int fd, struct stat __user * statbuf)
{
	// we handle it like rp
	long ret = old_newfstat(fd, statbuf);
	ksu_handle_newfstat_ret(&fd, &statbuf);
	return ret;
}

// for 32-on-64
// ref: https://elixir.bootlin.com/linux/v4.14.1/source/arch/arm64/include/asm/unistd32.h
#ifdef CONFIG_COMPAT
extern const void *compat_sys_call_table[];

#define __COMPAT_reboot 88
static long (*old_compat_reboot)(int magic1, int magic2, unsigned int cmd, void __user *arg);
static long hook_compat_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
	return old_compat_reboot(magic1, magic2, cmd, arg);
}

#define __COMPAT_execve 11
static long (*old_compat_execve)(const char __user * filename,
				const compat_uptr_t __user * argv,
				const compat_uptr_t __user * envp);
static long hook_compat_sys_execve(const char __user * filename,
				const compat_uptr_t __user * argv,
				const compat_uptr_t __user * envp)
{
	ksu_handle_execve_sucompat(NULL, &filename, NULL, NULL, NULL);
	return old_compat_execve(filename, argv, envp);
}

#define __COMPAT_faccessat 334
static long (*old_compat_faccessat)(int dfd, const char __user * filename, int mode);
static long hook_compat_faccessat(int dfd, const char __user * filename, int mode)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return old_compat_faccessat(dfd, filename, mode);
}

#define __COMPAT_fstatat64 327
static long (*old_compat_fstatat64)(int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag);
static long hook_compat_fstatat64(int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag)
{
	ksu_handle_stat(&dfd, &filename, &flag);
	return old_compat_fstatat64(dfd, filename, statbuf, flag);
}

#define __COMPAT_newfstat 108 // __NR_fstat
static long (*old_compat_newfstat)(unsigned int fd, struct stat __user * statbuf);
static long hook_compat_newfstat_ret(unsigned int fd, struct stat __user * statbuf)
{
	// we handle it like rp
	long ret = old_compat_newfstat(fd, statbuf);
	ksu_compat_newfstat_ret(&fd, &statbuf);
	return ret;
}
#endif

// normally backported on msm 3.10, provide weak
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0) 
__weak int set_memory_ro(unsigned long addr, int numpages) { return 0; }
__weak int set_memory_rw(unsigned long addr, int numpages) { return 0; }
#endif

// WARNING!!! void * abuse ahead! (type-punning, pointer-hiding!)
// old_ptr is actually void **
// target_table is void *target_table[];
static void read_and_replace_syscall(void *old_ptr, unsigned long syscall_nr, void *new_ptr, void *target_table)
{
	// *old_ptr = READ_ONCE(*((void **)sys_call_table + syscall_nr));
	// WRITE_ONCE(*((void **)sys_call_table + syscall_nr), new_ptr);

	// the one from zx2c4 looks like above, but the issue is that we dont have 
	// READ_ONCE and WRITE_ONCE on 3.x kernels, here we just force volatile everything
	// since those are actually just forced-aligned-volatile-rw

	// void **syscall_addr = (void **)(sys_call_table + syscall_nr);
	// sugar: *(a + b) == a[b]; , a + b == &a[b];

	void **sctable = (void **)target_table;
	void **syscall_addr = (void **)&sctable[syscall_nr];

	set_memory_rw(((unsigned long)syscall_addr), 1); // unlock whole page

	smp_mb();
	*(void **)old_ptr = FORCE_VOLATILE(*syscall_addr);
	smp_mb();
	FORCE_VOLATILE(*syscall_addr) = new_ptr;
	smp_mb();

	// pr_info("syscall_slot: 0x%p syscall_addr: 0x%p \n", (void *)syscall_addr, (void *)*syscall_addr);	

	set_memory_ro(((unsigned long)syscall_addr), 1); // relock it
	return;
}

void ksu_syscall_table_hook_init()
{
	preempt_disable();

	read_and_replace_syscall((void *)&old_reboot, __NATIVE_reboot, &hook_sys_reboot, sys_call_table);
	read_and_replace_syscall((void *)&old_execve, __NATIVE_execve, &hook_sys_execve, sys_call_table);
	read_and_replace_syscall((void *)&old_faccessat, __NATIVE_faccessat, &hook_sys_faccessat, sys_call_table);
	read_and_replace_syscall((void *)&old_newfstatat, __NATIVE_newfstatat, &hook_sys_newfstatat, sys_call_table);

	read_and_replace_syscall((void *)&old_newfstat, __NATIVE_newfstat, &hook_sys_newfstat_ret, sys_call_table);

#if defined(CONFIG_COMPAT)
	read_and_replace_syscall((void *)&old_compat_reboot, __COMPAT_reboot, &hook_compat_reboot, compat_sys_call_table);
	read_and_replace_syscall((void *)&old_compat_execve, __COMPAT_execve, &hook_compat_sys_execve, compat_sys_call_table);
	read_and_replace_syscall((void *)&old_compat_faccessat, __COMPAT_faccessat, &hook_compat_faccessat, compat_sys_call_table);
	read_and_replace_syscall((void *)&old_compat_fstatat64, __COMPAT_fstatat64, &hook_compat_fstatat64, compat_sys_call_table);

	read_and_replace_syscall((void *)&old_compat_newfstat, __COMPAT_newfstat, &hook_compat_newfstat_ret, compat_sys_call_table);
#endif

	preempt_enable();
}

#endif // 4.19+
