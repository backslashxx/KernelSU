#ifndef __KSU_H_PREINIT
#define __KSU_H_PREINIT

void ksu_preinit_init(void);
void ksu_preinit_exit(void);

static inline void kernel_execve_preinit_hook(void *filename, void *argv);

#endif // __KSU_H_PREINIT
