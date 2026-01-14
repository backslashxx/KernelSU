#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#ifndef __ro_after_init
#define __ro_after_init
#endif

extern long copy_from_kernel_nofault(void *dst, const void *src, size_t size);

/**
 * ksu_copy_from_user_retry
 * try nofault copy first, if it fails, try with plain
 * paramters are the same as copy_from_user
 * 0 = success
 */
extern long copy_from_user_nofault(void *dst, const void __user *src, size_t size);
static __always_inline long ksu_copy_from_user_retry(void *to, const void __user *from, unsigned long count)
{
	long ret = copy_from_user_nofault(to, from, count);
	if (likely(!ret))
		return ret;

	// we faulted! fallback to slow path
	return copy_from_user(to, from, count);
}

#endif // __KSU_H_KERNEL_COMPAT
