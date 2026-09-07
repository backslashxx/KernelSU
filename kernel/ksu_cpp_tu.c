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

asmlinkage void ksu_c_print(unsigned);

constexpr uint32_t ksu_cpp_constexpr(void)
{
	return 0xCAFEBABE;
}

__attribute__((used))
asmlinkage void ksu_cpp_test(void)
{
	ksu_c_print(ksu_cpp_constexpr());
}
