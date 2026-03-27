#ifndef __KSU_H_UTIL
#define __KSU_H_UTIL

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#define ksu_close_fd close_fd
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#define ksu_close_fd(fd) __close_fd(current->files, fd)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
#define ksu_close_fd sys_close
#endif

static inline struct file *ksu_filp_open_nonotify(const char *path, int flags)
{
	struct path p;
	struct file *f;
	int ret;
	ret = kern_path(path, (flags & O_NOFOLLOW) ? 0 : LOOKUP_FOLLOW, &p);
	if (ret) {
		return ERR_PTR(ret);
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
	f = dentry_open_nonotify(&p, flags, current_cred());
#else
	f = dentry_open(&p, flags | __FMODE_NONOTIFY, current_cred());
#endif

	path_put(&p);
	return f;
}

#endif // __KSU_H_UTIL
