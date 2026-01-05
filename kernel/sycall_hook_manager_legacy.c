extern const unsigned long sys_call_table[];

// fn pointers
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

static void read_and_replace_syscall(void **old_ptr, unsigned long syscall_nr, void *new_ptr)
{
	// *old_ptr = READ_ONCE(*((void **)sys_call_table + syscall_nr));
	// WRITE_ONCE(*((void **)sys_call_table + syscall_nr), new_ptr);

	// the one from zx2c4 looks like above, but the issue is that we dont have 
	// READ_ONCE and WRITE_ONCE on 3.x kernels, here we just force volatile everything
	// since those are actually just forced-aligned-volatile-rw

#define FORCE_VOLATILE(x) *(volatile typeof(x) *)&(x)

	void **syscall_addr = (void **)(sys_call_table + syscall_nr);

	barrier();
	*old_ptr = FORCE_VOLATILE(*syscall_addr);

	barrier();
	FORCE_VOLATILE(*syscall_addr) = new_ptr;

	// pr_info("syscall_slot: 0x%p syscall_addr: 0x%p \n", (void *)syscall_addr, (void *)*syscall_addr);	

}

void ksu_syscall_table_hook_init()
{
	preempt_disable();

	// reboot
	read_and_replace_syscall((void **)&old_reboot, __NR_reboot, &hook_sys_reboot);

	// exec
	read_and_replace_syscall((void **)&old_execve, __NR_execve, &hook_sys_execve);
	// access
	read_and_replace_syscall((void **)&old_faccessat, __NR_faccessat, &hook_sys_faccessat);

#ifdef __NR_newfstatat
	// newfstatat
	read_and_replace_syscall((void **)&old_newfstatat, __NR_newfstatat, &hook_sys_newfstatat);
#endif

#ifdef __NR_fstatat64
	// newfstatat
	read_and_replace_syscall((void **)&old_fstatat64, __NR_fstatat64, &hook_sys_fstatat64);
#endif

	preempt_enable();
}
