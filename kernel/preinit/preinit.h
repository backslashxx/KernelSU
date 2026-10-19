#ifndef __KSU_H_PREINIT
#define __KSU_H_PREINIT

#ifndef KSU_NO_PREINIT

void ksu_preinit_init(void);
void ksu_preinit_exit(void);

DEFINE_STATIC_KEY_TRUE(ksu_preinit_key);

static inline void ksu_preinit_kernel_execve_hook(void **filename, void *k_argv);
static inline void ksu_preinit_user_execve_hook(const char __user **filename, void *u_argv);

static inline void ksu_disable_preinit_branch()
{
	pr_info("preinit: remove preinit execve branches\n");
	static_branch_disable(&ksu_preinit_key);
	kick_all_cpus_sync();
}

#else

#define ksu_preinit_init() do { } while (0)
#define ksu_preinit_exit() do { } while (0)

#define ksu_preinit_kernel_execve_hook(...)	do { } while (0)
#define ksu_preinit_user_execve_hook(...)	do { } while (0)

#define ksu_disable_preinit_branch()	do { } while (0)

#endif // KSU_NO_PREINIT

#endif // __KSU_H_PREINIT
