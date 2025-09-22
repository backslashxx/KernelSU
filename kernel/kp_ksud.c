#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/binfmts.h>
#include <linux/kthread.h>
#include <linux/sched.h>

static struct task_struct *unregister_thread;

#ifndef CONFIG_KSU_TAMPER_SYSCALL_TABLE
// sys_newfstat rp
// upstream: https://github.com/tiann/KernelSU/commit/df640917d11dd0eff1b34ea53ec3c0dc49667002

// this is a bit different from copy_from_user_retry
// here we just disable preempt and try nofault again
// we use this inside context that can't sleep
static long ksu_copy_from_user_nofault_retry(void *to, const void __user *from, unsigned long count)
{
	long ret = copy_from_user_nofault(to, from, count);
	if (likely(!ret))
		return ret;

	preempt_disable();
	ret = copy_from_user_nofault(to, from, count);
	preempt_enable();

	return ret;
}

static int sys_newfstat_handler_pre(struct kretprobe_instance *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	unsigned int fd = PT_REGS_PARM1(real_regs);
	void *statbuf = PT_REGS_PARM2(real_regs);
	*(void **)&p->data = NULL;

	if (!is_init(get_current_cred()))
		return 0;

	struct file *file = fget(fd);
	if (!file)
		return 0;

	if (is_init_rc(file)) {
		pr_info("kp_ksud: stat init.rc \n");
		fput(file);
		*(void **)&p->data = statbuf;
		return 0;
	}
	fput(file);

	return 0;
}

static int sys_newfstat_handler_post(struct kretprobe_instance *p, struct pt_regs *regs)
{
	void __user *statbuf = *(void **)&p->data;
	if (!statbuf)
		return 0;

	void __user *st_size_ptr = statbuf + offsetof(struct stat, st_size);
	long size, new_size;

	if (ksu_copy_from_user_nofault_retry(&size, st_size_ptr, sizeof(long))) {
		pr_info("kp_ksud: read statbuf 0x%lx failed \n", (unsigned long)st_size_ptr);
		return 0;
	}

	new_size = size + ksu_rc_len;
	pr_info("kp_ksud: adding ksu_rc_len: %ld -> %ld \n", size, new_size);

	// I do NOT think this matters much for now, we can use copy_to_user
	// if SHTF then we backport cope_to_user_nofault
	if (!copy_to_user(st_size_ptr, &new_size, sizeof(long)))
		pr_info("kp_ksud: added ksu_rc_len \n");
	else
		pr_info("kp_ksud: add ksu_rc_len failed: statbuf 0x%lx \n", (unsigned long)st_size_ptr);

	return 0;
}

static struct kretprobe sys_newfstat_rp = {
	.kp.symbol_name = SYS_NEWFSTAT_SYMBOL,
	.entry_handler = sys_newfstat_handler_pre,
	.handler = sys_newfstat_handler_post,
	.data_size = sizeof(void *),
};

#ifdef CONFIG_COMPAT // compat_sys_newfstat rp
static int compat_sys_newfstat_handler_pre(struct kretprobe_instance *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	unsigned int fd = PT_REGS_PARM1(real_regs);
	void *statbuf = PT_REGS_PARM2(real_regs);
	*(void **)&p->data = NULL;

	if (!is_init(get_current_cred()))
		return 0;

	struct file *file = fget(fd);
	if (!file)
		return 0;

	if (is_init_rc(file)) {
		pr_info("kp_ksud: stat init.rc \n");
		fput(file);
		*(void **)&p->data = statbuf;
		return 0;
	}
	fput(file);

	return 0;
}

static int compat_sys_newfstat_handler_post(struct kretprobe_instance *p, struct pt_regs *regs)
{
	void __user *statbuf = *(void **)&p->data;
	if (!statbuf)
		return 0;

	// compat_stat
	void __user *st_size_ptr = statbuf + offsetof(struct compat_stat, st_size);
	long size, new_size;

	if (ksu_copy_from_user_nofault_retry(&size, st_size_ptr, sizeof(long))) {
		pr_info("kp_ksud: read statbuf 0x%lx failed \n", (unsigned long)st_size_ptr);
		return 0;
	}

	new_size = size + ksu_rc_len;
	pr_info("kp_ksud: adding ksu_rc_len: %ld -> %ld \n", size, new_size);

	if (!copy_to_user(st_size_ptr, &new_size, sizeof(long)))
		pr_info("kp_ksud: added ksu_rc_len \n");
	else
		pr_info("kp_ksud: add ksu_rc_len failed: statbuf 0x%lx \n", (unsigned long)st_size_ptr);

	return 0;
}

static struct kretprobe compat_sys_newfstat_rp = {
	.kp.symbol_name = SYS_COMPAT_NEWFSTAT_SYMBOL,
	.entry_handler = compat_sys_newfstat_handler_pre,
	.handler = compat_sys_newfstat_handler_post,
	.data_size = sizeof(void *),
};
#endif

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
#endif

static int unregister_kprobe_function(void *data)
{
	pr_info("kp_ksud: unregistering kprobes...\n");

#ifndef CONFIG_KSU_TAMPER_SYSCALL_TABLE
	unregister_kretprobe(&sys_newfstat_rp);
	pr_info("kp_ksud: unregister sys_newfstat_rp!\n");

#ifdef CONFIG_COMPAT
	unregister_kretprobe(&compat_sys_newfstat_rp);
	pr_info("kp_ksud: unregister compat_sys_newfstat_rp!\n");
#endif

#endif	
	unregister_thread = NULL;
	
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

void kp_ksud_init()
{

#ifndef CONFIG_KSU_TAMPER_SYSCALL_TABLE
	int ret = register_kprobe(&sys_reboot_kp); // dont unreg this one
	pr_info("kp_ksud: sys_reboot_kp: %d\n", ret);

	ret = register_kretprobe(&sys_newfstat_rp);
	pr_info("kp_ksud: sys_newfstat_rp: %d\n", ret);

#ifdef CONFIG_COMPAT	
	ret = register_kretprobe(&compat_sys_newfstat_rp);
	pr_info("kp_ksud: compat_sys_newfstat_rp: %d\n", ret);
#endif

#endif

	// ret = register_kprobe(&input_event_kp);
	// pr_info("kp_ksud: input_event_kp: %d\n", ret);
}
