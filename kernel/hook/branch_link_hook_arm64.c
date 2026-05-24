#ifndef CONFIG_ARM64
#error "only meant for ARM64!"
#endif

#if !defined(CONFIG_KPROBES)
#error "kprobes is required for branch link hack!"
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
 *      - fixups for 4.19 ~ 6.6 CFI, resolve symbols via kprobe. (260630)
 *      - optimize ksu_vfs_statx (260630)
 *
 *
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0) // on some kernels vfs_fstatat calls gets inlined, so we have to handle it
static int (*vfs_statx_fn)(int dfd, struct filename *filename, int flags, struct kstat *stat, u32 request_mask) __read_mostly = NULL;
static __nocfi int ksu_vfs_statx(int dfd, struct filename *filename, int flags, struct kstat *stat, u32 request_mask)
{
	if (IS_ERR(filename))
		goto orig_fn;

	char *filename_ptr = (char *)filename->name;
	if (!is_su_allowed((const void **)&filename_ptr))
		goto orig_fn;

	// see sucompat.c
	const char su[16] = SU_PATH;
	uint64_t *su_p = (uint64_t *)su;
	uint64_t *fn_p = (uint64_t *)filename_ptr;

	if (likely((fn_p[1] & 0x00FFFFFFFFFFFFFFULL) != (su_p[1] & 0x00FFFFFFFFFFFFFFULL)))
		goto orig_fn;

	if (unlikely(fn_p[0] != su_p[0]))
		goto orig_fn;
	
	pr_info("vfs_statx su->sh\n");
	memcpy(filename_ptr, SH_PATH, sizeof(SH_PATH));

orig_fn:
	return vfs_statx_fn(dfd, filename, flags, stat, request_mask);
}
#endif
extern int vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat, int flags);
static __nocfi int ksu_vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat, int flags)
{
	ksu_handle_stat(&dfd, &filename, &flags);
	return vfs_fstatat(dfd, filename, stat, flags);
}
#else // < 5.10
extern int vfs_statx(int dfd, const char __user *filename, int flags, struct kstat *stat, u32 request_mask);
static __nocfi int ksu_vfs_statx(int dfd, const char __user *filename, int flags, struct kstat *stat, u32 request_mask)
{
	ksu_handle_stat(&dfd, &filename, &flags);
	return vfs_statx(dfd, filename, flags, stat, request_mask);
}
#endif // 5.10+

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0) || defined(KSU_HAS_FACCESSAT2)
static long (*do_faccessat_fn)(int dfd, const char __user *filename, int mode, int flags) __read_mostly = NULL;
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
#endif // 5.7+ || faccessat2

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
static int (*do_execveat_common_fn)(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags) __read_mostly = NULL;
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

#ifdef CONFIG_COMPAT 
static int (*compat_do_execve_fn)(struct filename *filename, const compat_uptr_t __user *__argv, const compat_uptr_t __user *__envp) __read_mostly = NULL;
static __nocfi int ksu_compat_do_execve(struct filename *filename, const compat_uptr_t __user *__argv, const compat_uptr_t __user *__envp)
{
	struct user_arg_ptr argv = { .is_compat = true, .ptr.compat = __argv, };
	struct user_arg_ptr envp = { .is_compat = true, .ptr.compat = __envp, };

	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
	return compat_do_execve_fn(filename, __argv, __envp);
}
#endif

#endif // 5.9+

static int ksu_branch_link_patch_init()
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t symbol_addr;

// faccessat
	target_callsite = kp_syscall_lookup("__arm64_sys_faccessat");
	symbol_addr = kp_cfi_kallsyms_lookup_name("do_faccessat");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0) || defined(KSU_HAS_FACCESSAT2)
	do_faccessat_fn = symbol_addr;
	ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_faccessat);
#else
	ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_faccessat);
#endif
	pr_info("sys_faccessat: do_faccessat: ret %d \n", ret);

// newfstatat
	target_callsite = kp_syscall_lookup("__arm64_sys_newfstatat");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	symbol_addr = kp_cfi_kallsyms_lookup_name("vfs_fstatat");
	ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_fstatat);
	pr_info("sys_newfstatat: vfs_fstatat: ret %d \n", ret);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
	if (ret) {
		symbol_addr = kp_cfi_kallsyms_lookup_name("vfs_statx");
		vfs_statx_fn = symbol_addr;
		ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_statx);
		pr_info("sys_newfstatat: vfs_statx: ret %d \n", ret);
	}
#endif

#else // < 5.10
	symbol_addr = kp_cfi_kallsyms_lookup_name("vfs_statx");
	ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_statx);
	pr_info("sys_newfstatat: vfs_statx: ret %d \n", ret);
#endif


#ifdef CONFIG_COMPAT // fstatat64
	target_callsite = kp_syscall_lookup("__arm64_sys_fstatat64");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	symbol_addr = kp_cfi_kallsyms_lookup_name("vfs_fstatat");
	ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_fstatat);
	pr_info("sys_fstatat64: vfs_fstatat: ret %d \n", ret);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
	if (ret) {
		symbol_addr = kp_cfi_kallsyms_lookup_name("vfs_statx");
		vfs_statx_fn = symbol_addr;
		ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_statx);
		pr_info("sys_fstatat64: vfs_statx: ret %d \n", ret);
	}
#endif

#else // < 5.10
	symbol_addr = kp_cfi_kallsyms_lookup_name("vfs_statx");
	ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_statx);
	pr_info("sys_fstatat64: vfs_statx: ret %d \n", ret);
#endif
#endif // CONFIG_COMPAT // fstatat64

// execve
	target_callsite = kp_syscall_lookup("__arm64_sys_execve");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	symbol_addr = kp_cfi_kallsyms_lookup_name("do_execveat_common");
	do_execveat_common_fn = symbol_addr;
	ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_execveat_common);
	pr_info("sys_execve: do_execveat_common: ret %d \n", ret);
#else
	symbol_addr = kp_cfi_kallsyms_lookup_name("__do_execve_file");

	__do_execve_file_fn = symbol_addr;
	ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_execve_file);
	pr_info("sys_execve: __do_execve_file: ret %d \n", ret);
	if (ret) {
		symbol_addr = (uintptr_t)&do_execve;
		ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_execve);
		pr_info("sys_execve: do_execve: ret %d \n", ret);
	}
#endif

#ifdef CONFIG_COMPAT // compat_sys_execve
	target_callsite = kp_syscall_lookup("__arm64_compat_sys_execve");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	symbol_addr = kp_cfi_kallsyms_lookup_name("do_execveat_common");
	do_execveat_common_fn = symbol_addr;
	ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_execveat_common);
	pr_info("compat_sys_execve: do_execveat_common: ret %d \n", ret);
#else
	symbol_addr = kp_cfi_kallsyms_lookup_name("__do_execve_file");
	__do_execve_file_fn = symbol_addr;
	ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_execve_file);
	pr_info("compat_sys_execve: __do_execve_file: ret %d \n", ret);
	if (ret) {
		symbol_addr = kp_cfi_kallsyms_lookup_name("compat_do_execve");
		compat_do_execve_fn = symbol_addr;
		ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_compat_do_execve);
		pr_info("compat_sys_execve: compat_do_execve: ret %d \n", ret);
	}
#endif
#endif // CONFIG_COMPAT // compat_sys_execve

	return 0;
}
