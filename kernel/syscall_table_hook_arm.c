#include <asm/syscall.h>
#include <linux/vmalloc.h>

#ifndef CONFIG_ARM
#error "only meant for ARM"
#endif

// ref: https://elixir.bootlin.com/linux/v4.14.1/source/include/uapi/asm-generic/unistd.h
// ref: https://elixir.bootlin.com/linux/v4.14.1/source/arch/arm64/include/asm/unistd32.h
// ref: https://elixir.bootlin.com/linux/v4.14.1/source/arch/arm64/include/asm/unistd.h

#define FORCE_VOLATILE(x) *(volatile typeof(x) *)&(x)

#define __ARMEABI_reboot	88
#define __ARMEABI_execve	11
#define __ARMEABI_faccessat	334
#define __ARMEABI_fstatat64	327
#define __ARMEABI_fstat64	197

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)

// on 4.19+ its is no longer just a void *sys_call_table[]
// it becomes syscall_fn_t sys_call_table[];

static syscall_fn_t armeabi_reboot = NULL;
static long hook_armeabi_reboot(const struct pt_regs *regs)
{
	int magic1 = (int)regs->regs[0];
	int magic2 = (int)regs->regs[1];
	unsigned int cmd = (unsigned int)regs->regs[2];
	void __user **arg = (void __user **)&regs->regs[3];

	ksu_handle_sys_reboot(magic1, magic2, cmd, arg);
	return armeabi_reboot(regs);
}

static syscall_fn_t armeabi_execve = NULL;
static long hook_armeabi_execve(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[0];

	ksu_handle_execve_sucompat(NULL, filename, NULL, NULL, NULL);
	return armeabi_execve(regs);
}

static syscall_fn_t armeabi_faccessat = NULL;
static long hook_armeabi_faccessat(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	ksu_handle_faccessat(NULL, filename, NULL, NULL);
	return armeabi_faccessat(regs);
}

static syscall_fn_t armeabi_fstatat64 = NULL;
static long hook_armeabi_fstatat64(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	ksu_handle_stat(NULL, filename, NULL);
	return armeabi_fstatat64(regs);
}

static syscall_fn_t armeabi_fstat64 = NULL;
static long hook_armeabi_fstat64_ret(const struct pt_regs *regs)
{
	// we handle it like rp
	unsigned long *fd = (unsigned long *)&regs->regs[0];
	struct stat64 __user **statbuf = (struct stat64 __user **)&regs->regs[1];

	long ret = armeabi_fstat64(regs);
	ksu_handle_fstat64_ret(fd, statbuf);
	return ret;
}

#else // END OF 4.19+ SYSCALL HANDLERS

static long (*armeabi_reboot)(int magic1, int magic2, unsigned int cmd, void __user *arg) = NULL;
static long hook_armeabi_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
	return armeabi_reboot(magic1, magic2, cmd, arg);
}

static long (*armeabi_execve)(const char __user * filename,
				const char __user *const __user * argv,
				const char __user *const __user * envp) = NULL;
static long hook_armeabi_execve(const char __user * filename,
				const char __user *const __user * argv,
				const char __user *const __user * envp)
{
	ksu_handle_execve_sucompat(NULL, &filename, NULL, NULL, NULL);
	return armeabi_execve(filename, argv, envp);
}

static long (*armeabi_faccessat)(int dfd, const char __user * filename, int mode) = NULL;
static long hook_armeabi_faccessat(int dfd, const char __user * filename, int mode)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return armeabi_faccessat(dfd, filename, mode);
}

static long (*armeabi_fstatat64)(int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag) = NULL;
static long hook_armeabi_fstatat64(int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag)
{
	ksu_handle_stat(&dfd, &filename, &flag);
	return armeabi_fstatat64(dfd, filename, statbuf, flag);
}

static long (*armeabi_fstat64)(unsigned long fd, struct stat64 __user * statbuf) = NULL;
static long hook_armeabi_fstat64_ret(unsigned long fd, struct stat64 __user * statbuf)
{
	// we handle it like rp
	long ret = armeabi_fstat64(fd, statbuf);
	ksu_handle_fstat64_ret(&fd, &statbuf);
	return ret;
}


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

	/*
	 * basically the trick is
	 * addr, say 0xffff1234, this is READ-ONLY
	 * align it, 0xffff0000
	 * ptrdiff 0xffff1234 - 0xffff0000, 0x00001234
	 * vmap 0xffff0000, say we get 0xcccc0000 , now WRITABLE
	 * write on 0xcccc0000 + 0x00001234
	 *
	 */

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
	smp_mb(); // ^^

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

	/*
	 * we do this to make sure that old_ptr is filled.
	 * we risk a dead syscall !!!
	 * if read_and_replace failed or we restore again, it wont be pointing to anything
	 * it just copies wordsize of whatever is in *old_ptr, it should fill up a wordzie atleast
	 * yeah it really just dummy copies machine instructions at this point.
	 *
	 * normally we use probe_kernel_address / get_kernel_nofault here but the API is 
	 * so inconsistent across kernel versions, and since its just a dummied wrapper 
	 * for copy_from_kernel_nofault we can do it ourselves
	 *
	 */

	long dummy = 0;
	if (copy_from_kernel_nofault((void *)&dummy, *(void **)old_ptr, sizeof(long)))
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

	*target_slot = *(void **)old_ptr;	
	smp_mb(); // ^^

	*(void **)old_ptr = NULL; // explicit reset

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

	if (FORCE_VOLATILE(ksu_vfs_read_hook))
		goto loop_start;

#ifndef CONFIG_KSU_KPROBES_KSUD
	restore_syscall((void *)&armeabi_fstat64, __ARMEABI_fstat64, (void *)hook_armeabi_fstat64_ret, (void *)sys_call_table);
#endif
	
	return 0;
}

static struct task_struct *syscall_restore_thread;
static void vfs_read_hook_wait_thread()
{
	syscall_restore_thread = kthread_run(ksu_syscall_table_restore, NULL, "unhook");
	if (IS_ERR(syscall_restore_thread)) {
		return;
	}
}

static void ksu_syscall_table_hook_init()
{

	read_and_replace_syscall((void *)&armeabi_reboot, __ARMEABI_reboot, (void *)hook_armeabi_reboot, (void *)sys_call_table);
	read_and_replace_syscall((void *)&armeabi_execve, __ARMEABI_execve, (void *)hook_armeabi_execve, (void *)sys_call_table);
	read_and_replace_syscall((void *)&armeabi_faccessat, __ARMEABI_faccessat, (void *)hook_armeabi_faccessat, (void *)sys_call_table);
	read_and_replace_syscall((void *)&armeabi_fstatat64, __ARMEABI_fstatat64, (void *)hook_armeabi_fstatat64, (void *)sys_call_table);

#ifndef CONFIG_KSU_KPROBES_KSUD
	read_and_replace_syscall((void *)&armeabi_fstat64, __ARMEABI_fstat64, (void *)hook_armeabi_fstat64_ret, (void *)sys_call_table);
#endif

	vfs_read_hook_wait_thread(); // start unreg kthread
}

// EOF
