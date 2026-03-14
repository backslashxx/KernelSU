#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#include <linux/fs.h>
#include <linux/key.h>
#include <linux/version.h>
#include <linux/key.h>

extern struct file *ksu_filp_open_compat(const char *filename, int flags,
					 umode_t mode);

#endif
