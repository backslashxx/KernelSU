#ifndef __KSU_H_SUCOMPAT
#define __KSU_H_SUCOMPAT
#include <linux/sched.h>
#include <linux/thread_info.h>
#include <linux/version.h>

void ksu_sucompat_init(void);
void ksu_sucompat_exit(void);

#endif
