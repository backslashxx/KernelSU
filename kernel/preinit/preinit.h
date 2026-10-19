#ifndef __KSU_H_PREINIT
#define __KSU_H_PREINIT

#include <linux/types.h>
#include <asm/ptrace.h>

#ifndef KSU_NO_PREINIT
void ksu_preinit_init(void);
void ksu_preinit_exit(void);

// Drop the staged runner if selinux_setup was never seen.
void ksu_preinit_release(void);

// Whether the runner is built in and not disabled with preinit=0.
bool ksu_preinit_enabled_param(void);

#else

static inline void ksu_preinit_init(void) { }
static inline void ksu_preinit_exit(void) { }
static inline void ksu_preinit_release(void) { }
static inline bool ksu_preinit_enabled_param(void) { return false; }
#endif

#endif // __KSU_H_PREINIT
