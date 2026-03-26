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

#endif // __KSU_H_KERNEL_COMPAT
