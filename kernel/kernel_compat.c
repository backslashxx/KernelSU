#include <linux/version.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#include <linux/sched/signal.h> // signal_struct
#include <linux/sched/task.h>
#else
#include <linux/sched.h>
#endif
#include <linux/uaccess.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
#include <linux/key.h>
#include <linux/errno.h>
#include <linux/cred.h>
struct key *init_session_keyring = NULL;

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

	if (!!!is_init(get_current_cred()))
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
	if (init_session_keyring != NULL && !current_cred()->session_keyring) {
		install_session_keyring(init_session_keyring);
	}
	return filp_open(filename, flags, mode);
}
#else
struct file *ksu_filp_open_compat(const char *filename, int flags, umode_t mode)
{
	return filp_open(filename, flags, mode);
}
#endif

ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count, loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	return kernel_read(p, buf, count, pos);
#else // https://elixir.bootlin.com/linux/v4.14.336/source/fs/read_write.c#L418
	mm_segment_t old_fs;
	old_fs = get_fs();
	set_fs(get_ds());
	ssize_t result = vfs_read(p, (void __user *)buf, count, pos);
	set_fs(old_fs);
	return result;
#endif
}

ssize_t ksu_kernel_write_compat(struct file *p, const void *buf, size_t count, loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	return kernel_write(p, buf, count, pos);
#else // https://elixir.bootlin.com/linux/v4.14.336/source/fs/read_write.c#L512
	mm_segment_t old_fs;
	old_fs = get_fs();
	set_fs(get_ds());
	ssize_t res = vfs_write(p, (__force const char __user *)buf, count, pos);
	set_fs(old_fs);
	return res;
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
__weak int path_mount(const char *dev_name, struct path *path, 
	const char *type_page, unsigned long flags, void *data_page)
{
	// 384 is enough 
	char buf[384] = {0};

	// -1 on the size as implicit null termination
	// as we zero init the thing
	char *realpath = d_path(path, buf, sizeof(buf) - 1);
	if (!(realpath && realpath != buf)) 
		return -ENOENT;

	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	long ret = do_mount(dev_name, (const char __user *)realpath, type_page, flags, data_page);
	set_fs(old_fs);
	return ret;
}
#endif

static inline int ksu_access_ok(const void *addr, unsigned long size)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
	return access_ok(addr, size);
#else
	return access_ok(VERIFY_READ, addr, size);
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0) 
__weak long copy_from_user_nofault(void *dst, const void __user *src, size_t size)
{
	// https://elixir.bootlin.com/linux/v5.8/source/mm/maccess.c#L205
	long ret = -EFAULT;
	mm_segment_t old_fs = get_fs();

	set_fs(USER_DS);
	// tweaked to use ksu_access_ok
	if (ksu_access_ok(src, size)) {
		pagefault_disable();
		ret = __copy_from_user_inatomic(dst, src, size);
		pagefault_enable();
	}
	set_fs(old_fs);

	if (ret)
		return -EFAULT;
	return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
__weak long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
{
	// https://elixir.bootlin.com/linux/v5.2.21/source/mm/maccess.c#L27
	long ret;
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	pagefault_disable();
	ret = __copy_from_user_inatomic(dst,
			(__force const void __user *)src, size);
	pagefault_enable();
	set_fs(old_fs);

	return ret ? -EFAULT : 0;
}
#endif
