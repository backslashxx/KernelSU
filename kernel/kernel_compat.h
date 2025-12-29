#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/key.h>
#include <linux/version.h>
#include <linux/key.h>
#include <linux/syscalls.h>
#include <linux/cred.h>

extern struct file *ksu_filp_open_compat(const char *filename, int flags,
					 umode_t mode);
extern ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count,
				      loff_t *pos);
extern ssize_t ksu_kernel_write_compat(struct file *p, const void *buf,
				       size_t count, loff_t *pos);

// for supercalls.c fd install tw
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#ifndef TWA_RESUME
#define TWA_RESUME 1
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
__weak int close_fd(unsigned fd)
{
	return sys_close(fd);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
__weak int close_fd(unsigned fd)
{
	// this is ksys_close, but that shit is inline
	// its problematic to cascade a weak symbol for it
	return __close_fd(current->files, fd);
}
#endif

extern long copy_from_user_nofault(void *dst, const void __user *src, size_t size);

/*
 * ksu_copy_from_user_retry
 * try nofault copy first, if it fails, try with plain
 * paramters are the same as copy_from_user
 * 0 = success
 * + hot since this is reused on sucompat
 */
__attribute__((hot))
static long ksu_copy_from_user_retry(void *to, const void __user *from, unsigned long count)
{
	long ret = copy_from_user_nofault(to, from, count);
	if (likely(!ret))
		return ret;

	// we faulted! fallback to slow path
	return copy_from_user(to, from, count);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0) && !defined(KSU_HAS_ITERATE_DIR)
struct dir_context {
	const filldir_t actor;
	loff_t pos;
};

static int iterate_dir(struct file *file, struct dir_context *ctx)
{
	return vfs_readdir(file, ctx->actor, ctx);
}
#endif // KSU_HAS_ITERATE_DIR

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
__weak char *bin2hex(char *dst, const void *src, size_t count)
{
	const unsigned char *_src = src;
	while (count--)
		dst = pack_hex_byte(dst, *_src++);
	return dst;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
static inline struct inode *file_inode(struct file *f)
{
	return f->f_path.dentry->d_inode;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
static inline struct inode_security_struct *selinux_inode(const struct inode *inode)
{
	return inode->i_security;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
static inline struct task_security_struct *selinux_cred(const struct cred *cred)
{
	return cred->security;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION (4, 15, 0)
__weak void groups_sort(struct group_info *group_info)
{
	return;
}
#endif

#endif
