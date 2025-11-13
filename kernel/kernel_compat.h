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

#ifndef untagged_addr
#define untagged_addr(addr) (addr)
#endif

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
#define d_is_reg(dentry) S_ISREG((dentry)->d_inode->i_mode)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)
struct user_struct *ksu_alloc_uid(kuid_t uid) { return alloc_uid(current_user_ns(), uid); }
#define alloc_uid ksu_alloc_uid
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0) && !defined(KSU_HAS_ITERATE_DIR)
struct dir_context { const filldir_t actor; loff_t pos; };
#define iterate_dir(file, ctx) vfs_readdir(file, (ctx)->actor, ctx)
#endif

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
#define file_inode(f) ((f)->f_path.dentry->d_inode)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0) && !defined(CONFIG_LSM)
#define selinux_inode(inode) ((inode)->i_security)
#define selinux_cred(cred) ((cred)->security)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION (4, 15, 0)
__weak void groups_sort(struct group_info *group_info) { } // no-op
#endif

#ifndef U16_MAX
#define	U16_MAX	((u16)(~0U))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION (4, 12, 0) && !defined(EPOLLIN)
#define EPOLLIN		0x00000001
#define EPOLLPRI	0x00000002
#define EPOLLOUT	0x00000004
#define EPOLLERR	0x00000008
#define EPOLLHUP	0x00000010
#define EPOLLRDNORM	0x00000040
#define EPOLLRDBAND	0x00000080
#define EPOLLWRNORM	0x00000100
#define EPOLLWRBAND	0x00000200
#define EPOLLMSG	0x00000400
#define EPOLLRDHUP	0x00002000
#endif // < 4.12 && !EPOLLIN

#ifndef READ_ONCE
#define READ_ONCE(x) (*(const volatile typeof(x) *)&(x))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION (3, 15, 0)
#define task_ppid_nr(a) (pid_t)sys_getppid()
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION (3, 17, 0)
static inline u64 ksu_ktime_get_ns(void) { return ktime_to_ns(ktime_get()); }
#define ktime_get_ns ksu_ktime_get_ns
#endif

// WARNING: no overflow safety!
#ifndef struct_size
#define struct_size(p, member, n) (sizeof(*(p)) + (n) * sizeof(*(p)->member))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION (4, 12, 0)
#ifndef ALIGN_DOWN
#define ALIGN_DOWN(x, a) __ALIGN_KERNEL((x) - ((a) - 1), (a))
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
// https://elixir.bootlin.com/linux/v4.14.336/source/fs/read_write.c#L418
static noinline ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count, loff_t *pos)
{
	mm_segment_t old_fs;
	old_fs = get_fs();
	set_fs(get_ds());
	ssize_t result = vfs_read(p, (void __user *)buf, count, pos);
	set_fs(old_fs);
	return result;
}
// https://elixir.bootlin.com/linux/v4.14.336/source/fs/read_write.c#L512
static noinline ssize_t ksu_kernel_write_compat(struct file *p, const void *buf, size_t count, loff_t *pos)
{
	mm_segment_t old_fs;
	old_fs = get_fs();
	set_fs(get_ds());
	ssize_t res = vfs_write(p, (__force const char __user *)buf, count, pos);
	set_fs(old_fs);
	return res;
}
#define kernel_read ksu_kernel_read_compat
#define kernel_write ksu_kernel_write_compat
#endif // < 4.14

static inline void ksu_kfree_byref(void *buf) { kfree(*(void **)buf); }

#if LINUX_VERSION_CODE < KERNEL_VERSION (3, 9, 0)
// hashtable.h, list.h, rculist.h
// ref: https://github.com/torvalds/linux/commit/b67bfe0d42cac56c512dd5da4b1b347a23f4b70a
#include "linux_hashtable.h"
static inline int __must_check ksu_kref_get_unless_zero(struct kref *kref)
{ 
	return atomic_add_unless(&kref->refcount, 1, 0); 
}
#define kref_get_unless_zero ksu_kref_get_unless_zero
#endif // < 3.9

/**
 *  kver agnostic workaround for < 3.14's CONFIG_UIDGID_STRICT_TYPE_CHECKS=n
 *
 *  - force dereferences an unsigned int (uid_t)
 *  - redefines current_uid / current_euid macros
 *
 * ref
 *  - https://elixir.bootlin.com/linux/v3.13/source/include/linux/uidgid.h
 *  - https://elixir.bootlin.com/linux/v3.13/source/include/linux/cred.h#L331
 */
#define ksu_get_uid_t(x) *(unsigned int *)&(x)

#if LINUX_VERSION_CODE < KERNEL_VERSION (3, 14, 0)
#undef current_uid
#undef current_euid
typedef struct { uid_t val; } ksu_kuid_t;
static inline ksu_kuid_t current_uid() { return *(ksu_kuid_t *)(&current_cred()->uid); }
static inline ksu_kuid_t current_euid() { return *(ksu_kuid_t *)(&current_cred()->euid); }
#endif // < 3.14

#endif // __KSU_H_KERNEL_COMPAT
