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

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static inline void *ksu_kvmalloc(size_t size, gfp_t flags)
{
	void *buf = kmalloc(size, flags);
	if (!buf)
		buf = vmalloc(size);
	
	return buf;
}

static inline void ksu_kvfree(void *buf)
{
	if (is_vmalloc_addr(buf))
		vfree(buf);
	else
		kfree(buf);
}
#define kvmalloc ksu_kvmalloc
#define kvfree ksu_kvfree
#endif

// for supercalls.c fd install tw
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0) && !defined(TWA_RESUME)
#define TWA_RESUME 1
#endif

// this is ksys_close, however that is spotty to use 
// as 5.10 backported close_fd and rekt ksys_close
// so we use what it does internally, __close_fd
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#define close_fd(fd) __close_fd(current->files, fd)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
#define close_fd sys_close
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0)
static inline struct file *ksu_dentry_open(const struct path *path, int flags, const struct cred *cred)
{
	return dentry_open((*path).dentry, (*path).mnt, flags, cred);
}
#define dentry_open ksu_dentry_open
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
#ifndef replace_fops
#define replace_fops(f, fops) \
	do {	\
		struct file *__file = (f); \
		fops_put(__file->f_op); \
		BUG_ON(!(__file->f_op = (fops))); \
	} while(0)
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0) && defined(CONFIG_JUMP_LABEL)
#define KSU_CAN_USE_JUMP_LABEL

// https://elixir.bootlin.com/linux/v3.10.108/source/include/linux/jump_label.h#L211
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
static inline void ksu_static_key_enable(struct static_key *key)
{
	int count = atomic_read(&key->enabled);
	if (!count)
		static_key_slow_inc(key);
}

static inline void ksu_static_key_disable(struct static_key *key)
{
	int count = atomic_read(&key->enabled);
	if (count)
		static_key_slow_dec(key);
}

#define static_branch_enable(k)		ksu_static_key_enable(k)
#define static_branch_disable(k)	ksu_static_key_disable(k)

#define static_branch_unlikely(k)	static_key_false(k)
#define static_branch_likely(k)		static_key_true(k)

#ifndef DEFINE_STATIC_KEY_FALSE
#define DEFINE_STATIC_KEY_FALSE(k)	struct static_key k = STATIC_KEY_INIT_FALSE
#endif

#ifndef DEFINE_STATIC_KEY_TRUE
#define DEFINE_STATIC_KEY_TRUE(k)	struct static_key k = STATIC_KEY_INIT_TRUE
#endif

#endif // < 4.3
#endif // >= 3.4 && CONFIG_JUMP_LABEL

#endif // __KSU_H_KERNEL_COMPAT
