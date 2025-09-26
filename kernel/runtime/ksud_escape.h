#ifndef __KSU_H_KSUD_ESCAPE
#define __KSU_H_KSUD_ESCAPE

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0) && !defined(CONFIG_KRETPROBES)
__attribute__((cold)) static noinline void sys_execve_escape_ksud_internal(void *filename);
__attribute__((cold)) static noinline void kernel_execve_escape_ksud_internal(void *filename);

#ifdef KSU_CAN_USE_JUMP_LABEL
DEFINE_STATIC_KEY_TRUE(ksud_escape_key);
static inline void sys_execve_escape_ksud(void *filename)
{
	if (static_branch_likely(&ksud_escape_key))
		sys_execve_escape_ksud_internal(filename);
}
static inline void kernel_execve_escape_ksud(void *filename)
{
	if (static_branch_likely(&ksud_escape_key))
		kernel_execve_escape_ksud_internal(filename);
}
#else
static inline void sys_execve_escape_ksud(void *filename)
{
	if (unlikely(!ksu_boot_completed))
		sys_execve_escape_ksud_internal(filename);
}
static inline void kernel_execve_escape_ksud(void *filename)
{
	if (unlikely(!ksu_boot_completed))
		kernel_execve_escape_ksud_internal(filename);
}
#endif

#else
static inline void sys_execve_escape_ksud(void *filename) { } // no-op
static inline void kernel_execve_escape_ksud(void *filename) { } // no-op
#endif // < 4.14 && >= 4.2 && !KRETPROBES

static void ksud_escape_init();
static void ksud_escape_exit();

#endif // __KSU_H_KSUD_ESCAPE
