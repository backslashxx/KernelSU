// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 \xx
 *
 * This file is a downstream extension and NOT affiliated, endorsed by,
 * or maintained by the official KernelSU developers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#ifndef READ_ONCE
#define READ_ONCE(x) (*(const volatile typeof(x) *)&(x))
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(x, y) (*(volatile typeof(x) *)&(x) = (typeof(x))(y))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static void *ksu_kvmalloc(size_t size, gfp_t flags)
{
	void *buf = kmalloc(size, flags);
	if (!buf)
		buf = vmalloc(size);
	
	return buf;
}
#define kvmalloc ksu_kvmalloc

static void ksu_kvfree(const void *buf)
{
	if (is_vmalloc_addr(buf))
		vfree(buf);
	else
		kfree(buf);
}
#define kvfree ksu_kvfree
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
__weak long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
{
	// https://elixir.bootlin.com/linux/v5.2.21/source/mm/maccess.c#L27
	long ret;
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	pagefault_disable();
	ret = __copy_from_user_inatomic(dst, (__force const void __user *)src, size);
	pagefault_enable();
	set_fs(old_fs);

	return ret ? -EFAULT : 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0) 
__weak long copy_from_user_nofault(void *dst, const void __user *src, size_t size)
{
	// https://elixir.bootlin.com/linux/v5.8/source/mm/maccess.c#L205
	long ret = -EFAULT;
	mm_segment_t old_fs = get_fs();

	set_fs(USER_DS);

	// normally theres an access_ok check here
	// but for what we use it, it will always be true.
	// so we skip it
	pagefault_disable();
	ret = __copy_from_user_inatomic(dst, src, size);
	pagefault_enable();

	set_fs(old_fs);

	if (ret)
		return -EFAULT;
	return 0;
}
#endif

/**
 * copy_from_user_retry(): try nofault copy first, then fall back to faulting copy
 * return: 0 on success
 */
static __always_inline long copy_from_user_retry(void *to, const void __user *from, unsigned long count)
{
	long ret = copy_from_user_nofault(to, from, count);
	if (likely(!ret))
		return ret;

	// we faulted! fallback to slow path
	return copy_from_user(to, from, count);
}

/**
 * memmove_user(): memmove user memory through a temp buffer
 * return: 0 on success
 */
static __always_inline long memmove_user(void __user *dst, const void __user *src, size_t count)
{
	char *buf __offstack(count);
	if (!buf)
		return -ENOMEM;

	if (!!copy_from_user_retry(buf, src, count))
		return -EFAULT;

	if (!!copy_to_user(dst, buf, count))
		return -EFAULT;

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
__weak void memzero_explicit(void *s, size_t count) { memset_explicit(s, 0, count); }
#endif

#ifdef TIF_SECCOMP
#define ksu_is_seccomp_enabled() test_thread_flag(TIF_SECCOMP)
#else
#define ksu_is_seccomp_enabled() (!!current->seccomp.mode)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
#define d_inode(dentry) ((dentry)->d_inode)
#endif

// for supercalls.c fd install tw
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0) && !defined(TWA_RESUME)
#define TWA_RESUME 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#define ksu_close_fd close_fd
// this is ksys_close, however that is spotty to use, as 5.10 backported close_fd and rekt ksys_close
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#define ksu_close_fd(fd) __close_fd(current->files, fd)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
#define ksu_close_fd sys_close
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0)
static inline struct file *ksu_dentry_open(const struct path *path, int flags, const struct cred *cred)
{
	return dentry_open((*path).dentry, (*path).mnt, flags, cred);
}
#define dentry_open ksu_dentry_open
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
__weak int path_mount(const char *dev_name, struct path *path, const char *type_page, unsigned long flags, void *data_page)
{
	char *buf __zoffstack(PATH_MAX);
	if (!buf)
		return -ENOMEM;

	char *realpath = d_path(path, buf, PATH_MAX - 1);
	if (IS_ERR(realpath) || realpath == buf)
		return -ENOENT;

	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	long ret = do_mount(dev_name, (const char __user *)realpath, type_page, flags, data_page);
	set_fs(old_fs);
	return ret;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
#ifndef replace_fops
#define replace_fops(f, fops) \
	do {	\
		struct file *__file = (f); \
		fops_put(__file->f_op); \
		BUG_ON(!(__file->f_op = (fops))); \
	} while(0)
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
__weak int path_umount(struct path *path, int flags)
{
	char buf[256] = {0};
	int ret = -ENOENT;

	char *usermnt = d_path(path, buf, sizeof(buf) - 1);
	if (IS_ERR(usermnt) || usermnt == buf)
		goto out;

	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	ret = ksys_umount((char __user *)usermnt, flags);
#else
	ret = (int)sys_umount((char __user *)usermnt, flags);
#endif

	set_fs(old_fs);

	// release ref here! user_path_at increases it
	// then only cleans for itself
out:
	path_put(path); 
	return ret;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0) && defined(CONFIG_JUMP_LABEL)
#define KSU_CAN_USE_JUMP_LABEL

// https://elixir.bootlin.com/linux/v3.10.108/source/include/linux/jump_label.h#L211
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
static inline void ksu_static_key_enable(struct static_key *key)
{
	int count = atomic_read(&key->enabled);
	if (!count)
		static_key_slow_inc(key);
}

static inline void ksu_static_key_disable(struct static_key *key)
{
	int count = atomic_read(&key->enabled);
	if (count)
		static_key_slow_dec(key);
}

#define static_branch_enable(k)		ksu_static_key_enable(k)
#define static_branch_disable(k)	ksu_static_key_disable(k)

#define static_branch_unlikely(k)	static_key_false(k)
#define static_branch_likely(k)		static_key_true(k)

#ifndef DEFINE_STATIC_KEY_FALSE
#define DEFINE_STATIC_KEY_FALSE(k)	struct static_key k = STATIC_KEY_INIT_FALSE
#endif

#ifndef DEFINE_STATIC_KEY_TRUE
#define DEFINE_STATIC_KEY_TRUE(k)	struct static_key k = STATIC_KEY_INIT_TRUE
#endif

#endif // < 4.3
#endif // >= 3.4 && CONFIG_JUMP_LABEL

#endif // __KSU_H_KERNEL_COMPAT
