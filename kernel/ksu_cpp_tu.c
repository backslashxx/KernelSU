#define asmlinkage extern "C"

#define _Bool  char
#define bool  __ksu_bool
#define false __ksu_false
#define true  __ksu_true
#include <linux/types.h>
#include <linux/stddef.h>
#undef false
#undef true
#undef bool
#undef _Bool

// typedef __UINTPTR_TYPE__ ssize_t;

#define E2BIG 7

constexpr ssize_t cpp_strscpy(char *dest, const char *src, size_t count)
{
	if (!count)
		return -E2BIG;

	// look for the first null terminator w/in count
	// alternatively, strnlen?
	const char *end = (const char *)__builtin_memchr(src, '\0', count);
	if (end) {
		size_t copy_len = end - src;
		__builtin_memcpy(dest, src, copy_len);
		dest[copy_len] = '\0';
		return copy_len;
	}

	__builtin_memcpy(dest, src, count - 1);
	dest[count - 1] = '\0';
	return -E2BIG;
}

asmlinkage ssize_t constexpr_strscpy(char *dest, const char *src, size_t count)
{
	return cpp_strscpy(dest, src, count);
}
