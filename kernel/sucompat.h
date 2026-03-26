#ifndef __KSU_H_SUCOMPAT
#define __KSU_H_SUCOMPAT

extern bool ksu_su_compat_enabled;

void ksu_sucompat_init(void);
void ksu_sucompat_exit(void);

void ksu_sucompat_enable(void);
void ksu_sucompat_disable(void);

#endif
