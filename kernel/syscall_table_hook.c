#include <asm/syscall.h>

#ifndef CONFIG_ARM64
#error "only meant for ARM64"
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)

// on 4.19+ its is no longer just a void *sys_call_table[]
// it becomes syscall_fn_t sys_call_table[];

// reboot
#define __AARCH64_reboot 142 //__NR_reboot
static syscall_fn_t old_reboot; // int magic1, int magic2, unsigned int cmd, void __user *arg
static long hook_sys_reboot(const struct pt_regs *regs)
{
	int magic1 = (int)regs->regs[0];
	int magic2 = (int)regs->regs[1];
	unsigned int cmd = (unsigned int)regs->regs[2];
	void __user **arg = (void __user **)&regs->regs[3];

	ksu_handle_sys_reboot(magic1, magic2, cmd, arg);
	return old_reboot(regs);
}

// execve
#define __AARCH64_execve 221 // __NR_execve
static syscall_fn_t old_execve; // const char __user * filename, const char __user *const __user * argv, const char __user *const __user * envp
static long hook_sys_execve(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[0];

	ksu_handle_execve_sucompat(NULL, filename, NULL, NULL, NULL);
	return old_execve(regs);
}

// access
#define __AARCH64_faccessat 48 // __NR_faccessat
static syscall_fn_t old_faccessat; // int dfd, const char __user * filename, int mode
static long hook_sys_faccessat(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	ksu_handle_faccessat(NULL, filename, NULL, NULL);
	return old_faccessat(regs);
}

// stat
#define __AARCH64_newfstatat 79 // __NR_newfstatat, __NR3264_fstatat
static syscall_fn_t old_newfstatat; // int dfd, const char __user * filename, struct stat __user * statbuf, int flag);
static long hook_sys_newfstatat(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	ksu_handle_stat(NULL, filename, NULL);
	return old_newfstatat(regs);
}

#define __AARCH64_newfstat 80 // __NR3264_fstat
static syscall_fn_t old_newfstat; // unsigned int fd, struct stat __user * statbuf
static long hook_sys_newfstat_ret(const struct pt_regs *regs)
{
	// we handle it like rp
	unsigned int *fd = (unsigned int *)&regs->regs[0];
	struct stat __user **statbuf = (struct stat __user **)&regs->regs[1];

	long ret = old_newfstat(regs);
	ksu_handle_newfstat_ret(fd, statbuf);
	return ret;
}

#ifdef CONFIG_COMPAT
#define __ARMEABI_reboot 88
static syscall_fn_t old_compat_reboot; // int magic1, int magic2, unsigned int cmd, void __user *arg
static long hook_compat_reboot(const struct pt_regs *regs)
{
	int magic1 = (int)regs->regs[0];
	int magic2 = (int)regs->regs[1];
	unsigned int cmd = (unsigned int)regs->regs[2];
	void __user **arg = (void __user **)&regs->regs[3];

	ksu_handle_sys_reboot(magic1, magic2, cmd, arg);
	return old_compat_reboot(regs);
}

#define __ARMEABI_execve 11
static syscall_fn_t old_compat_execve;// (const char __user * filename, const compat_uptr_t __user * argv, const compat_uptr_t __user * envp);
static long hook_compat_sys_execve(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[0];

	ksu_handle_execve_sucompat(NULL, filename, NULL, NULL, NULL);
	return old_compat_execve(regs);
}

#define __ARMEABI_faccessat 334
static syscall_fn_t old_compat_faccessat; //int dfd, const char __user * filename, int mode
static long hook_compat_faccessat(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	ksu_handle_faccessat(NULL, filename, NULL, NULL);
	return old_compat_faccessat(regs);
}

// NOTE: CONFIG_COMPAT implies __ARCH_WANT_COMPAT_STAT64
#define __ARMEABI_fstatat64 327 // __NR_fstatat64
static syscall_fn_t old_compat_fstatat64; //int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag
static long hook_compat_fstatat64(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	ksu_handle_stat(NULL, filename, NULL);
	return old_compat_fstatat64(regs);
}

// NOTE: CONFIG_COMPAT implies __ARCH_WANT_COMPAT_STAT64
#define __ARMEABI_fstat64 197 // __NR_fstat64
static syscall_fn_t old_compat_fstat64; //unsigned int fd, struct stat64 __user * statbuf
static long hook_compat_fstat64_ret(const struct pt_regs *regs)
{
	// we handle it like rp
	unsigned long *fd = (unsigned long *)&regs->regs[0];
	struct stat64 __user **statbuf = (struct stat64 __user **)&regs->regs[1];

	long ret = old_compat_fstat64(regs);
	ksu_handle_fstat64_ret(fd, statbuf);
	return ret;
}
#endif // CONFIG_COMPAT

#else // END OF 4.19+ SYSCALL HANDLERS

// native syscalls
// ref: https://elixir.bootlin.com/linux/v4.14.1/source/include/uapi/asm-generic/unistd.h

// sys_reboot
#define __AARCH64_reboot 142 //__NR_reboot
static long (*old_reboot)(int magic1, int magic2, unsigned int cmd, void __user *arg);
static long hook_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
	return old_reboot(magic1, magic2, cmd, arg);
}

// execve
#define __AARCH64_execve 221 // __NR_execve
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
#define __AARCH64_faccessat 48 // __NR_faccessat
static long (*old_faccessat)(int dfd, const char __user * filename, int mode);
static long hook_sys_faccessat(int dfd, const char __user * filename, int mode)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return old_faccessat(dfd, filename, mode);
}

// stat
#define __AARCH64_newfstatat 79 // __NR_newfstatat, __NR3264_fstatat
static long (*old_newfstatat)(int dfd, const char __user * filename, struct stat __user * statbuf, int flag);
static long hook_sys_newfstatat(int dfd, const char __user * filename, struct stat __user * statbuf, int flag)
{
	ksu_handle_stat(&dfd, &filename, &flag);
	return old_newfstatat(dfd, filename, statbuf, flag);
}

#define __AARCH64_newfstat 80 // __NR3264_fstat
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
// ref: https://elixir.bootlin.com/linux/v4.14.1/source/arch/arm64/include/asm/unistd.h
#ifdef CONFIG_COMPAT
extern const void *compat_sys_call_table[];

#define __ARMEABI_reboot 88
static long (*old_compat_reboot)(int magic1, int magic2, unsigned int cmd, void __user *arg);
static long hook_compat_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
	return old_compat_reboot(magic1, magic2, cmd, arg);
}

#define __ARMEABI_execve 11
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

#define __ARMEABI_faccessat 334
static long (*old_compat_faccessat)(int dfd, const char __user * filename, int mode);
static long hook_compat_faccessat(int dfd, const char __user * filename, int mode)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return old_compat_faccessat(dfd, filename, mode);
}

// NOTE: CONFIG_COMPAT implies __ARCH_WANT_COMPAT_STAT64
#define __ARMEABI_fstatat64 327 // __NR_fstatat64
static long (*old_compat_fstatat64)(int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag);
static long hook_compat_fstatat64(int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag)
{
	ksu_handle_stat(&dfd, &filename, &flag);
	return old_compat_fstatat64(dfd, filename, statbuf, flag);
}

// NOTE: CONFIG_COMPAT implies __ARCH_WANT_COMPAT_STAT64
#define __ARMEABI_fstat64 197 // __NR_fstat64
static long (*old_compat_fstat64)(unsigned long fd, struct stat64 __user * statbuf);
static long hook_compat_fstat64_ret(unsigned long fd, struct stat64 __user * statbuf)
{
	// we handle it like rp
	long ret = old_compat_fstat64(fd, statbuf);
	ksu_handle_fstat64_ret(&fd, &statbuf);
	return ret;
}
#endif // CONFIG_COMPAT

#endif // SYSCALL HANDLERS

// 'vmapping for writable' idea copied from upstream's LSM_HOOK_HACK, override_security_head
// no more "Unable to handle kernel write to read-only memory at virtual address ffffffuckyou"

// WARNING!!! void * abuse ahead! (type-punning, pointer-hiding!)
// for 4.19+ old_ptr is actually syscall_fn_t *, which is just long * so we can consider this void **
// for 4.19- old_ptr is actually void **
// target_table is void *target_table[];
static void read_and_replace_syscall(void *old_ptr, unsigned long syscall_nr, void *new_ptr, void *target_table)
{
	void **sctable = (void **)target_table;
	void **syscall_slot_addr = &sctable[syscall_nr];

	if (!*syscall_slot_addr)
		return;

	pr_info("%s: hooking syscall #%d at 0x%lx\n", __func__, syscall_nr, (long)syscall_slot_addr);

	// prep vmap alias
	unsigned long addr = (unsigned long)syscall_slot_addr;
	unsigned long base = addr & PAGE_MASK;
	unsigned long offset = addr & ~PAGE_MASK; // offset_in_page

	// this is impossible for our case because the page alignment
	// but be careful for other cases!
	// BUG_ON(offset + len > PAGE_SIZE);
	if (offset + sizeof(void *) > PAGE_SIZE) {
		pr_info("%s: syscall slot crosses page boundary! aborting.\n", __func__);
		return;
	}

	// virtual mapping of a physical page 
	struct page *page = phys_to_page(__pa(base));
	if (!page)
		return;

	// create a "writabel address" which is mapped to teh same address
	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		return;

	// swap on the alias
	void **target_slot = (void **)((unsigned long)writable_addr + offset);

	preempt_disable();
	local_irq_disable();

	*(void **)old_ptr = *target_slot; 

	*target_slot = new_ptr; 

	local_irq_enable();
	preempt_enable();

	vunmap(writable_addr);

	smp_mb(); 
}

static void restore_syscall(void *old_ptr, unsigned long syscall_nr, void *new_ptr, void *target_table)
{
	void **sctable = (void **)target_table;
	void **syscall_slot_addr = &sctable[syscall_nr];

	if (!*syscall_slot_addr)
		return;

	pr_info("%s: restore syscall #%d at 0x%lx\n", __func__, syscall_nr, (long)syscall_slot_addr);

	// prep vmap alias
	unsigned long addr = (unsigned long)syscall_slot_addr;
	unsigned long base = addr & PAGE_MASK;
	unsigned long offset = addr & ~PAGE_MASK; // offset_in_page

	// this is impossible for our case because the page alignment
	// but be careful for other cases!
	// BUG_ON(offset + len > PAGE_SIZE);
	if (offset + sizeof(void *) > PAGE_SIZE) {
		pr_info("%s: syscall slot crosses page boundary! aborting.\n", __func__);
		return;
	}

	// virtual mapping of a physical page 
	struct page *page = phys_to_page(__pa(base));
	if (!page)
		return;

	// create a "writabel address" which is mapped to teh same address
	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		return;

	// swap on the alias
	void **target_slot = (void **)((unsigned long)writable_addr + offset);

	// check if its ours
	if (*target_slot != new_ptr) {
		pr_info("%s: syscall is not ours!\n", __func__);
		goto out;
	}
	
	pr_info("%s: syscall is ours! *target_slot: 0x%lx new_ptr: 0x%lx\n", __func__, (long)*target_slot, (long)new_ptr );

	preempt_disable();
	local_irq_disable();

	*target_slot = *(void **)old_ptr; // yeah this is the only difference

	local_irq_enable();
	preempt_enable();

out:
	vunmap(writable_addr);

	smp_mb(); 
}

static int ksu_syscall_table_restore()
{
loop_start:

	msleep(1000);

	if ((volatile bool)ksu_vfs_read_hook)
		goto loop_start;

#ifndef CONFIG_KSU_KPROBES_KSUD
	restore_syscall((void *)&old_newfstat, __AARCH64_newfstat, &hook_sys_newfstat_ret, (void *)sys_call_table);

#if defined(CONFIG_COMPAT)
	restore_syscall((void *)&old_compat_fstat64, __ARMEABI_fstat64, &hook_compat_fstat64_ret, (void *)compat_sys_call_table);
#endif
#endif
	
	return 0;
}

static struct task_struct *syscall_restore_thread;
static void vfs_read_hook_wait_thread()
{
	syscall_restore_thread = kthread_run(ksu_syscall_table_restore, NULL, "unhook");
	if (IS_ERR(syscall_restore_thread)) {
		syscall_restore_thread = NULL;
		return;
	}
}

static void ksu_syscall_table_hook_init()
{
	read_and_replace_syscall((void *)&old_reboot, __AARCH64_reboot, &hook_sys_reboot, (void *)sys_call_table);
	read_and_replace_syscall((void *)&old_execve, __AARCH64_execve, &hook_sys_execve, (void *)sys_call_table);
	read_and_replace_syscall((void *)&old_faccessat, __AARCH64_faccessat, &hook_sys_faccessat, (void *)sys_call_table);
	read_and_replace_syscall((void *)&old_newfstatat, __AARCH64_newfstatat, &hook_sys_newfstatat, (void *)sys_call_table);

#ifndef CONFIG_KSU_KPROBES_KSUD
	read_and_replace_syscall((void *)&old_newfstat, __AARCH64_newfstat, &hook_sys_newfstat_ret, (void *)sys_call_table);
#endif

#if defined(CONFIG_COMPAT)
	read_and_replace_syscall((void *)&old_compat_reboot, __ARMEABI_reboot, &hook_compat_reboot, (void *)compat_sys_call_table);
	read_and_replace_syscall((void *)&old_compat_execve, __ARMEABI_execve, &hook_compat_sys_execve, (void *)compat_sys_call_table);
	read_and_replace_syscall((void *)&old_compat_faccessat, __ARMEABI_faccessat, &hook_compat_faccessat, (void *)compat_sys_call_table);
	read_and_replace_syscall((void *)&old_compat_fstatat64, __ARMEABI_fstatat64, &hook_compat_fstatat64, (void *)compat_sys_call_table);

#ifndef CONFIG_KSU_KPROBES_KSUD
	read_and_replace_syscall((void *)&old_compat_fstat64, __ARMEABI_fstat64, &hook_compat_fstat64_ret, (void *)compat_sys_call_table);
#endif

#endif // COMPAT

	vfs_read_hook_wait_thread(); // start unreg kthread
}


// EOF

#if 0 // these are kept for posterity
static int override_security_head(void *head, const void *new_head, size_t len)
{
	unsigned long base = (unsigned long)head & PAGE_MASK;
	unsigned long offset = offset_in_page(head);

	// this is impossible for our case because the page alignment
	// but be careful for other cases!
	BUG_ON(offset + len > PAGE_SIZE);
	struct page *page = phys_to_page(__pa(base));
	if (!page) {
		return -EFAULT;
	}

	void *addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!addr) {
		return -ENOMEM;
	}
	local_irq_disable();
	memcpy(addr + offset, new_head, len);
	local_irq_enable();
	vunmap(addr);
	return 0;
}

// normally backported on msm 3.10, provide weak
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0) 
__weak int set_memory_ro(unsigned long addr, int numpages) { return 0; }
__weak int set_memory_rw(unsigned long addr, int numpages) { return 0; }
#endif

#define FORCE_VOLATILE(x) *(volatile typeof(x) *)&(x)

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

	// dont hook non-existing syscall
	if (!FORCE_VOLATILE(*syscall_addr))
		return;

	pr_info("%s: syscall: #%d slot: 0x%lx new_ptr: 0x%lx \n", __func__, syscall_nr, *(long *)syscall_addr, (long)new_ptr);

	set_memory_rw(((unsigned long)syscall_addr & PAGE_MASK), 1);

	barrier();
	*(void **)old_ptr = FORCE_VOLATILE(*syscall_addr);

	barrier();
	preempt_disable();
	FORCE_VOLATILE(*syscall_addr) = new_ptr;
	preempt_enable();

	set_memory_ro(((unsigned long)syscall_addr & PAGE_MASK), 1);
	smp_mb();

	return;
}
#endif
