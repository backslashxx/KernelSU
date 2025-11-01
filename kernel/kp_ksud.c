#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/binfmts.h>
#include <linux/kthread.h>
#include <linux/sched.h>

#include "arch.h"
#include "klog.h"
#include "ksud.h"
#include "kernel_compat.h"

static struct task_struct *unregister_thread;

#if 0
static int sys_execve_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	/*
	asmlinkage int sys_execve(const char __user *filenamei,
				  const char __user *const __user *argv,
				  const char __user *const __user *envp, struct pt_regs *regs)
	*/
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	const char __user *filename_user = (const char __user *)PT_REGS_PARM1(real_regs);
	const char __user *const __user *__argv = (const char __user *const __user *)PT_REGS_PARM2(real_regs);
	const char __user *const __user *__envp = (const char __user *const __user *)PT_REGS_PARM3(real_regs);

	char path[32];

	if (!filename_user)
		return 0;

// filename stage
	if (ksu_copy_from_user_retry(path, filename_user, sizeof(path)))
		return 0;

	path[sizeof(path) - 1] = '\0';

	// not /system/bin/init, not /init, not /system/bin/app_process (64/32 thingy)
	// we dont care !!
	if (likely(strcmp(path, "/system/bin/init") && strcmp(path, "/init")
		&& !strstarts(path, "/system/bin/app_process") ))
		return 0;

// argv stage
	char argv1[32] = {0};
	// memzero_explicit(argv1, 32);
	if (__argv) {
		const char __user *arg1_user = NULL;
		// grab argv[1] pointer
		// this looks like
		/* 
		 * 0x1000 ./program << this is __argv
		 * 0x1001 -o 
		 * 0x1002 arg
		*/
		if (ksu_copy_from_user_retry(&arg1_user, __argv + 1, sizeof(arg1_user)))
			goto no_argv1; // copy argv[1] pointer fail, probably no argv1 !!

		if (arg1_user)
			ksu_copy_from_user_retry(argv1, arg1_user, sizeof(argv1));
	}

no_argv1:
	argv1[sizeof(argv1) - 1] = '\0';

// envp stage
	#define ENVP_MAX 256
	char envp[ENVP_MAX] = {0};
	char *dst = envp;
	size_t envp_len = 0;
	int i = 0; // to track user pointer offset from __envp

	// memzero_explicit(envp, ENVP_MAX);

	if (__envp) {
		do {
			const char __user *env_entry_user = NULL;
			// this is also like argv above
			/*
			 * 0x1001 PATH=/bin
			 * 0x1002 VARIABLE=value
			 * 0x1002 some_more_env_var=1
			 */

			// check if pointer exists
			if (ksu_copy_from_user_retry(&env_entry_user, __envp + i, sizeof(env_entry_user)))
				break; 

			// check if no more env entry
			if (!env_entry_user)
				break; 
			
			// probably redundant to while condition but ok
			if (envp_len >= ENVP_MAX - 1)
				break;

			// copy strings from env_entry_user pointer that we collected
			// also break if failed
			if (ksu_copy_from_user_retry(dst, env_entry_user, ENVP_MAX - envp_len))
				break;

			// get the length of that new copy above
			// get lngth of dst as far as ENVP_MAX - current collected envp_len
			size_t len = strnlen(dst, ENVP_MAX - envp_len);
			if (envp_len + len + 1 > ENVP_MAX)
				break; // if more than 255 bytes, bail

			dst[len] = '\0';
			// collect total number of copied strings
			envp_len = envp_len + len + 1;
			// increment dst address since we need to put something on next iter
			dst = dst + len + 1;
			// pointer walk, __envp + i
			i++;
		} while (envp_len < ENVP_MAX);
	}

	/*
	at this point, we shoul've collected envp from
		* 0x1001 PATH=/bin
		* 0x1002 VARIABLE=value
		* 0x1002 some_more_env_var=1
	to
		* 0x1234 PATH=/bin\0VARIABLE=value\0some_more_env_var=1\0\0\0\0
	*/

	envp[ENVP_MAX - 1] = '\0';

	return ksu_handle_bprm_ksud(path, argv1, envp, envp_len);
}
static struct kprobe sys_execve_kp = {
	.symbol_name = SYS_EXECVE_SYMBOL,
	.pre_handler = sys_execve_handler_pre,
};
#endif

// vfs_read
extern int ksu_handle_vfs_read(struct file **file_ptr, char __user **buf_ptr,
			size_t *count_ptr, loff_t **pos);

static int vfs_read_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file **file_ptr = (struct file **)&PT_REGS_PARM1(regs);
	char __user **buf_ptr = (char **)&PT_REGS_PARM2(regs);
	size_t *count_ptr = (size_t *)&PT_REGS_PARM3(regs);
	loff_t **pos_ptr = (loff_t **)&PT_REGS_CCALL_PARM4(regs);

	return ksu_handle_vfs_read(file_ptr, buf_ptr, count_ptr, pos_ptr);
}

static struct kprobe vfs_read_kp = {
	.symbol_name = "vfs_read",
	.pre_handler = vfs_read_handler_pre,
};

// input_event
extern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value);

static int input_handle_event_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	unsigned int *type = (unsigned int *)&PT_REGS_PARM2(regs);
	unsigned int *code = (unsigned int *)&PT_REGS_PARM3(regs);
	int *value = (int *)&PT_REGS_CCALL_PARM4(regs);

	return ksu_handle_input_handle_event(type, code, value);

};

static struct kprobe input_event_kp = {
	.symbol_name = "input_event",
	.pre_handler = input_handle_event_handler_pre,
};

// key_permission
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
static int key_permission_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	const struct cred *cred = (const struct cred *)PT_REGS_PARM2(regs);

	if (init_session_keyring != NULL) {
		return 0;
	}
	if (strcmp(current->comm, "init")) {
		// we are only interested in `init` process
		return 0;
	}
	init_session_keyring = cred->session_keyring;
	pr_info("kernel_compat: got init_session_keyring\n");
	return 0;
};

static struct kprobe key_permission_kp = {
	.symbol_name = "key_task_permission",
	.pre_handler = key_permission_handler_pre,
};
#endif // key_permission

// security_bounded_transition
#if defined(CONFIG_KRETPROBES) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#include "avc_ss.h"
#include "selinux/selinux.h"

static u32 init_sid = 0;
static u32 su_sid = 0;

// get sids outside of kprobe context
static int grab_sids()
{
	int error = security_secctx_to_secid("u:r:init:s0", strlen("u:r:init:s0"), &init_sid);
	if (error)
		return 1;

	pr_info("kp_ksud/grab_sids: got init sid: %d\n", init_sid);

	error = security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &su_sid);
	if (error)
		return 1;

	pr_info("kp_ksud/grab_sids: got su sid: %d\n", su_sid);
	
	return 0;
}

// int security_bounded_transition(u32 old_sid, u32 new_sid)
static int bounded_transition_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	// grab sids on entry
	u32 *sid = (u32 *)ri->data;
	sid[0] = PT_REGS_PARM1(regs);  // old_sid
	sid[1] = PT_REGS_PARM2(regs);  // new_sid
	return 0;
}

static int bounded_transition_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	u32 *sid = (u32 *)ri->data;
	u32 old_sid = sid[0];
	u32 new_sid = sid[1];

	if (!ss_initialized)
		return 0;

	// so if old sid is 'init' and trying to transition to a new sid of 'su'
	// force the function to return 0 
	if (old_sid == init_sid && new_sid == su_sid) {
		pr_info("kp_ksud: security_bounded_transition: allowing init (%d) -> su (%d)\n", init_sid, su_sid);
		PT_REGS_RC(regs) = 0;  // make the original func return 0
	}

	return 0;
}

static struct kretprobe bounded_transition_rp = {
	.kp.symbol_name = "security_bounded_transition",
	.handler = bounded_transition_ret_handler,
	.entry_handler = bounded_transition_entry_handler,
	.data_size = sizeof(u32) * 2, // need to keep 2x u32's, one per sid
	.maxactive = 20,
};

// unused for now 
void kp_ksud_transition_routine_end()
{
	unregister_kretprobe(&bounded_transition_rp);
	pr_info("kp_ksud: unregister kretprobe: security_bounded_transition ret: ??\n");
}

void kp_ksud_transition_routine_start()
{
	// we only need to run this once.
	// once we got sids, we are ready
	if (su_sid != 0)
		return;

	int ret = grab_sids();
	if (ret)
		return;
	
	ret = register_kretprobe(&bounded_transition_rp);
	pr_info("kp_ksud: register kretprobe: security_bounded_transition ret: %d\n", ret);
}
#endif // security_bounded_transition

// sys_reboot
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);

static int sys_reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int magic1 = (int)PT_REGS_PARM1(real_regs);
	int magic2 = (int)PT_REGS_PARM2(real_regs);
	int cmd = (int)PT_REGS_PARM3(real_regs);
	void __user **arg = (void __user **)&PT_REGS_SYSCALL_PARM4(real_regs);

	return ksu_handle_sys_reboot(magic1, magic2, cmd, arg);
}

static struct kprobe sys_reboot_kp = {
	.symbol_name = SYS_REBOOT_SYMBOL,
	.pre_handler = sys_reboot_handler_pre,
};

static void unregister_kprobe_logged(struct kprobe *kp)
{
	const char *symbol_name = kp->symbol_name;
	if (!kp->addr) {
		pr_info("unregister_kprobe: %s not registered in the first place!\n", symbol_name);
		return;
	}
	unregister_kprobe(kp); // this fucking shit has no return code
	pr_info("kp_ksud: unregister kprobe: %s ret: ??\n", symbol_name);
}

static int unregister_kprobe_function(void *data)
{
	pr_info("kp_ksud: unregistering kprobes...\n");

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
	unregister_kprobe_logged(&key_permission_kp);
#endif

	unregister_kprobe_logged(&input_event_kp);
	// unregister_kprobe_logged(&sys_execve_kp);
	unregister_kprobe_logged(&vfs_read_kp);
	
	return 0;
}

void unregister_kprobe_thread()
{
	unregister_thread = kthread_run(unregister_kprobe_function, NULL, "kprobe_unregister");
	if (IS_ERR(unregister_thread)) {
		unregister_thread = NULL;
		return;
	}
}

static void register_kprobe_logged(struct kprobe *kp)
{
	int ret;
	ret = register_kprobe(kp);
	pr_info("kp_ksud: register kprobe: %s ret: %d\n", kp->symbol_name, ret);

}

void kp_ksud_init()
{
	// dont unreg this one
	register_kprobe_logged(&sys_reboot_kp);

	register_kprobe_logged(&vfs_read_kp);
	register_kprobe_logged(&input_event_kp);
	// register_kprobe_logged(&sys_execve_kp);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
	register_kprobe_logged(&key_permission_kp);
#endif
}
