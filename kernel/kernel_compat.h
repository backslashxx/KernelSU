#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
#define d_inode(dentry) ((dentry)->d_inode)
#endif

#endif // __KSU_H_KERNEL_COMPAT
