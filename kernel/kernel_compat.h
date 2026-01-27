#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#if defined(CONFIG_KEYS) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
extern int install_session_keyring_to_cred(struct cred *cred, struct key *keyring);
static struct key *init_session_keyring = NULL;

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

// up to 5.1, struct key __rcu *session_keyring; /* keyring inherited over fork */
// so we need to grab this using rcu_dereference
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
static inline struct key *ksu_get_current_session_keyring() { return rcu_dereference(current->cred->session_keyring); }
#else
static inline struct key *ksu_get_current_session_keyring() { return rcu_dereference(current->cred->tgcred->session_keyring); }
#endif

__attribute__((cold))
static noinline void ksu_grab_init_session_keyring()
{
	if (init_session_keyring)
		return;

	if (!!strcmp(current->comm, "init"))
		return;

	if (!!!is_init(current_cred()))
		return;

	// now we are sure that this is the key we want
	struct key *keyring = ksu_get_current_session_keyring();
	if (!keyring)
		return;

	init_session_keyring = key_get(keyring);

	pr_info("%s: init_session_keyring: 0x%lx \n", __func__, (uintptr_t)init_session_keyring);
}

static noinline struct file *ksu_filp_open_compat(const char *filename, int flags, umode_t mode)
{
	// it used to be that we put this on (current->flags & PF_WQ_WORKER)
	// but since things actually needing this has been offloaded to kthread
	// like allowlist write, we check for that instead.
	if (!(current->flags & PF_KTHREAD))
		goto filp_open;

	if (!!ksu_get_current_session_keyring())
		goto filp_open;
	
	if (!!!init_session_keyring)
		goto filp_open;

	// thats surely some exclamation comedy, pt. 2
	// now we are sure that we need to install init keyring to current
	install_session_keyring(init_session_keyring);

filp_open:
	return filp_open(filename, flags, mode);
}
#define filp_open ksu_filp_open_compat
#else
static inline void ksu_grab_init_session_keyring() {} // no-op
#endif // KEYS && < 5.2

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

struct user_arg_ptr {
#ifdef CONFIG_COMPAT
	bool is_compat;
#endif
	union {
		const char __user *const __user *native;
#ifdef CONFIG_COMPAT
		const compat_uptr_t __user *compat;
#endif
	} ptr;
};

extern long copy_from_kernel_nofault(void *dst, const void *src, size_t size);

/**
 * ksu_copy_from_user_retry
 * try nofault copy first, if it fails, try with plain
 * paramters are the same as copy_from_user
 * 0 = success
 */
extern long copy_from_user_nofault(void *dst, const void __user *src, size_t size);
static __always_inline long ksu_copy_from_user_retry(void *to, const void __user *from, unsigned long count)
{
	long ret = copy_from_user_nofault(to, from, count);
	if (likely(!ret))
		return ret;

	// we faulted! fallback to slow path
	return copy_from_user(to, from, count);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0) // caller is reponsible for sanity!
static inline void ksu_zeroed_strncpy(char *dest, const char *src, size_t count)
{
	// this is actually faster due to dead store elimination
	// count - 1 as implicit null termination
	__builtin_memset(dest, 0, count);
	__builtin_strncpy(dest, src, count - 1);
}
#define strscpy_pad ksu_zeroed_strncpy
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
#define strscpy ksu_zeroed_strncpy
#endif

#endif // __KSU_H_KERNEL_COMPAT
