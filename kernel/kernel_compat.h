#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#ifndef __ro_after_init
#define __ro_after_init
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
#define d_inode(dentry) ((dentry)->d_inode)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0) && defined(CONFIG_ARM64)
#ifndef TIF_SECCOMP
#define TIF_SECCOMP		11
#endif
#endif

#endif // __KSU_H_KERNEL_COMPAT
