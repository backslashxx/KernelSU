#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#if defined(CONFIG_KEYS) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)

extern int install_session_keyring_to_cred(struct cred *cred, struct key *keyring);
struct key *init_session_keyring = NULL;

bool is_init(const struct cred* cred);

static inline int install_session_keyring(struct key *keyring)
{
	struct cred *new;
	int ret;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	ret = install_session_keyring_to_cred(new, keyring);
	if (ret < 0) {
		abort_creds(new);
		return ret;
	}

	return commit_creds(new);
}

// this is on tgcred on < 3.8
// while we can grab that one, it seems to not actually be needed 
static void ksu_grab_init_session_keyring(const char *filename)
{
	if (init_session_keyring)
		return;
		
	if (!strstr(filename, "init")) 
		return;

	if (!!strcmp(current->comm, "init"))
		return;

	if (!!!is_init(current_cred()))
		return;

	// thats surely some exclamation comedy
	// and now we are sure that this is the key we want
	// up to 5.1, struct key __rcu *session_keyring; /* keyring inherited over fork */
	// so we need to grab this using rcu_dereference
	struct key *keyring = rcu_dereference(current->cred->session_keyring);
	if (!keyring)
		return;

	init_session_keyring = key_get(keyring);

	pr_info("%s: init_session_keyring: 0x%p \n", __func__, init_session_keyring);

}
struct file *ksu_filp_open_compat(const char *filename, int flags, umode_t mode)
{
	// normally we only put this on ((current->flags & PF_WQ_WORKER) || (current->flags & PF_KTHREAD))
	// but in the grand scale of things, this does NOT matter.
	// pr_info("installing init session keyring for older kernel\n");
	if (init_session_keyring && !current_cred()->session_keyring)
		install_session_keyring(init_session_keyring);

	return filp_open(filename, flags, mode);
}
#else
#define ksu_filp_open_compat filp_open
static inline void ksu_grab_init_session_keyring(const char *filename) {} // no-op
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#define ksu_kernel_read_compat kernel_read
#define ksu_kernel_write_compat kernel_write
#else
// https://elixir.bootlin.com/linux/v4.14.336/source/fs/read_write.c#L418
ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count, loff_t *pos)
{
	mm_segment_t old_fs;
	old_fs = get_fs();
	set_fs(get_ds());
	ssize_t result = vfs_read(p, (void __user *)buf, count, pos);
	set_fs(old_fs);
	return result;
}
// https://elixir.bootlin.com/linux/v4.14.336/source/fs/read_write.c#L512
ssize_t ksu_kernel_write_compat(struct file *p, const void *buf, size_t count, loff_t *pos)
{
	mm_segment_t old_fs;
	old_fs = get_fs();
	set_fs(get_ds());
	ssize_t res = vfs_write(p, (__force const char __user *)buf, count, pos);
	set_fs(old_fs);
	return res;
}
#endif

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
#include <linux/fdtable.h>
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
 *
 */
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
#define ksu_file_inode file_inode
#else
static inline struct inode *ksu_file_inode(struct file *f)
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

#endif
