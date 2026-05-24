#ifndef CONFIG_ARM64
#error "only meant for ARM64!"
#endif

#ifndef CONFIG_KALLSYMS
#error "kallsyms is required for branch link hack!"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
#error "probably impossible for sub 4.17, unless you have backported do_faccessat"
#endif

/**
 *  NOTE: theres no way to hijack sys_reboot and sys_newfstat cleanly.
 *
 *  however, we will require kprobes for this feature. and this is still highly experimental. (260524)
 *  this works the same as lsm_hooks_static.c, where we patch caller's site
 *
 *  as of now this has been tested to work on 6.12 aarch64 GKI
 *
 *  Changelog:
 *	- init, 260524
 *	- partial/probably-broken 4.19/5.4 compat, 260525
 *
 * TODO: 
 *	try to fixup for 4.19 / 5.4
 *	wire compat syscalls maybe?
 *	reduce kallsyms dependece
 *
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
// on some kernels vfs_fstatat calls gets inlined, so we have to handle it
static int (*vfs_statx_fn)(int dfd, struct filename *filename, int flags, struct kstat *stat, u32 request_mask) __read_mostly = NULL;
static __nocfi int ksu_vfs_statx(int dfd, struct filename *filename, int flags, struct kstat *stat, u32 request_mask)
{
	// TODO: optimize maybe

	if (IS_ERR(filename))
		goto orig_fn;

	char *filename_ptr = (char *)filename->name;
	if (!is_su_allowed((const void **)&filename_ptr))
		goto orig_fn;

	if (likely(memcmp(filename_ptr, SU_PATH, sizeof(SU_PATH))))
		goto orig_fn;
	
	pr_info("vfs_statx su->sh\n");
	memcpy(filename_ptr, SH_PATH, sizeof(SH_PATH));

orig_fn:
	return vfs_statx_fn(dfd, filename, flags, stat, request_mask);
}

#endif

extern int vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat, int flags);
__attribute__((hot))
static __nocfi int ksu_vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat, int flags)
{
	ksu_handle_stat(&dfd, &filename, &flags);
	return vfs_fstatat(dfd, filename, stat, flags);
}
#else
extern int vfs_statx(int dfd, const char __user *filename, int flags, struct kstat *stat, u32 request_mask);
static int ksu_vfs_statx(int dfd, const char __user *filename, int flags, struct kstat *stat, u32 request_mask)
{
	ksu_handle_stat(&dfd, &filename, &flags);
	return vfs_statx(dfd, filename, flags, stat, request_mask);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static long (*do_faccessat_fn)(int dfd, const char __user *filename, int mode, int flags) __read_mostly = NULL;
__attribute__((hot))
static __nocfi long ksu_do_faccessat(int dfd, const char __user *filename, int mode, int flags)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return do_faccessat_fn(dfd, filename, mode, flags);
}
#else
extern long do_faccessat(int dfd, const char __user *filename, int mode);
static __nocfi long ksu_do_faccessat(int dfd, const char __user *filename, int mode)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return do_faccessat(dfd, filename, mode);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
static int (*do_execveat_common_fn)(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags) __read_mostly = NULL;
__attribute__((hot))
static __nocfi int ksu_do_execveat_common(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags)
{
	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
	return do_execveat_common_fn(fd, filename, argv, envp, flags);
}
#else
static int (*__do_execve_file_fn)(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags, struct file *file) __read_mostly = NULL;
static __nocfi int ksu_do_execve_file(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags, struct file *file)
{
	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
	return __do_execve_file_fn(fd, filename, argv, envp, flags, file);
}
extern int do_execve(struct filename *filename, const char __user *const __user *__argv, const char __user *const __user *__envp);
static __nocfi int ksu_do_execve(struct filename *filename, const char __user *const __user *__argv, const char __user *const __user *__envp)
{
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct user_arg_ptr envp = { .ptr.native = __envp };
	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);

	return do_execve(filename, __argv, __envp);
}
#endif

static int ksu_branch_link_patch_init()
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t symbol_addr;

// newfstatat
	extern long __arm64_sys_newfstatat(const struct pt_regs *regs);
	target_callsite = (uintptr_t)&__arm64_sys_newfstatat;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	symbol_addr = (uintptr_t)&vfs_fstatat;
	ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_fstatat);
	pr_info("sucompat_hijack: vfs_fstatat: ret %d \n", ret);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
	if (ret) {
		symbol_addr = (uintptr_t)kallsyms_lookup_name("vfs_statx");
		vfs_statx_fn = symbol_addr;
		ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_statx);
		pr_info("sucompat_hijack: vfs_statx: ret %d \n", ret);
	}
#endif

#else
	symbol_addr = (uintptr_t)&vfs_statx;
	ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_statx);
	pr_info("sucompat_hijack: vfs_statx: ret %d \n", ret);
#endif
	symbol_addr = NULL;

// faccessat
	extern long __arm64_sys_faccessat(const struct pt_regs *regs);
	target_callsite = (uintptr_t)&__arm64_sys_faccessat;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
	symbol_addr = (uintptr_t)kallsyms_lookup_name("do_faccessat");
	do_faccessat_fn = symbol_addr;
	ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_faccessat);
#else
	symbol_addr = (uintptr_t)&do_faccessat;
	ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_faccessat);
#endif
	pr_info("sucompat_hijack: do_faccessat: ret %d \n", ret);
	symbol_addr = NULL;

// execve
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	extern long __arm64_sys_execve(const struct pt_regs *regs);
	target_callsite = (uintptr_t)&__arm64_sys_execve;
	symbol_addr = (uintptr_t)kallsyms_lookup_name("do_execveat_common");
	do_execveat_common_fn = symbol_addr;
	ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_execveat_common);
	pr_info("sucompat_hijack: do_execveat_common: ret %d \n", ret);
#else
	extern long __arm64_sys_execve(const struct pt_regs *regs);
	target_callsite = (uintptr_t)&__arm64_sys_execve;
	symbol_addr = (uintptr_t)kallsyms_lookup_name("__do_execve_file.cfi_jt");
	if (!symbol_addr)
		symbol_addr = (uintptr_t)kallsyms_lookup_name("__do_execve_file");

	__do_execve_file_fn = symbol_addr;
	ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_execve_file);
	pr_info("sucompat_hijack: __do_execve_file: ret %d \n", ret);
	if (ret) {
		symbol_addr = (uintptr_t)&do_execve;
		ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_execve);
		pr_info("sucompat_hijack: do_execve: ret %d \n", ret);
	}
#endif
	symbol_addr = NULL;

	return 0;
}
