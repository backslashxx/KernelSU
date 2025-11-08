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
#include "klog.h" // IWYU pragma: keep

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
#include "linux/key.h"
#include "linux/errno.h"
#include "linux/cred.h"
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

void ksu_grab_init_session_keyring(const char *filename)
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

	// TODO: put_key / key_put? check refcount?
	// maybe not, we keep it for the whole lifetime?
	// ALSO: maybe print init_session_keyring->index_key.description again? 
	// its a union so init_session_keyring->description is the same?
	
}
#endif

struct file *ksu_filp_open_compat(const char *filename, int flags, umode_t mode)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
	// normally we only put this on ((current->flags & PF_WQ_WORKER) || (current->flags & PF_KTHREAD))
	// but in the grand scale of things, this does NOT matter.
	if (init_session_keyring != NULL && !current_cred()->session_keyring) {
		// pr_info("installing init session keyring for older kernel\n");
		install_session_keyring(init_session_keyring);
	}
#endif
	struct file *fp = filp_open(filename, flags, mode);
	return fp;
}

ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count,
			       loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	return kernel_read(p, buf, count, pos);
#else
	loff_t offset = pos ? *pos : 0;
	ssize_t result = kernel_read(p, offset, (char *)buf, count);
	if (pos && result > 0) {
		*pos = offset + result;
	}
	return result;
#endif
}

ssize_t ksu_kernel_write_compat(struct file *p, const void *buf, size_t count,
				loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	return kernel_write(p, buf, count, pos);
#else
	loff_t offset = pos ? *pos : 0;
	ssize_t result = kernel_write(p, buf, count, offset);
	if (pos && result > 0) {
		*pos = offset + result;
	}
	return result;
#endif
}

static int ksu_access_ok(const void *addr, unsigned long size)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
	return access_ok(addr, size);
#else
	return access_ok(VERIFY_READ, addr, size);
#endif
}

long ksu_copy_from_user_nofault(void *dst, const void __user *src, size_t size)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	return copy_from_user_nofault(dst, src, size);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
	return probe_user_read(dst, src, size);
#else 
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
#endif
}
