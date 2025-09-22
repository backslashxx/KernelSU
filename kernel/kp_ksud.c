#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/binfmts.h>
#include <linux/kthread.h>
#include <linux/sched.h>

static struct task_struct *unregister_thread;

static void unregister_kprobe_logged(struct kprobe *kp)
{
	const char *symbol_name = kp->symbol_name;
	if (!kp->addr) {
		pr_info("kp_ksud: kp: %s not registered in the first place!\n", symbol_name);
		return;
	}
	unregister_kprobe(kp); // this fucking shit has no return code
	pr_info("kp_ksud: unregister kp: %s ret: ??\n", symbol_name);
}

static void register_kprobe_logged(struct kprobe *kp)
{
	int ret = register_kprobe(kp);
	pr_info("kp_ksud: register kp: %s ret: %d\n", kp->symbol_name, ret);

}

#if 0
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
#endif

// security_bounded_transition
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)

static int bounded_transition_handler_pre(struct kprobe *p, struct pt_regs *regs) {
	u32 *old_sid = (u32 *)&PT_REGS_PARM1(regs);
	u32 *new_sid = (u32 *)&PT_REGS_PARM2(regs);

	// so if old sid is 'init' and trying to transition to a new sid of 'su'
	// mutate old to make it equal and force the function to return 0 
	if (*old_sid == cached_init_sid && *new_sid == cached_su_sid) {
		pr_info("kp_ksud: security_bounded_transition: forcing init (%d) -> su (%d) transition\n", cached_init_sid, cached_su_sid);
		*old_sid = *new_sid;
	}

	return 0;
}

static struct kprobe bounded_transition_kp = {
	.symbol_name = "security_bounded_transition",
	.pre_handler = bounded_transition_handler_pre,
};

static struct task_struct *unregister_kp_thread;

static int kp_ksud_transition_unregister()
{
	unregister_kprobe_logged(&bounded_transition_kp);
	
	unregister_kp_thread = NULL;
	return 0;
}

void kp_ksud_transition_routine_end()
{
	unregister_kp_thread = kthread_run(kp_ksud_transition_unregister, NULL, "kp_unregister");
	if (IS_ERR(unregister_kp_thread)) {
		unregister_kp_thread = NULL;
		return;
	}
}

void kp_ksud_transition_routine_start()
{
	// once we got sids, we are ready
	if (!cached_init_sid)
		return;

	if (!cached_su_sid)
		return;

	register_kprobe_logged(&bounded_transition_kp);
}
#endif // security_bounded_transition

#ifndef CONFIG_KSU_TAMPER_SYSCALL_TABLE
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
	//pr_info("kp_ksud: unregistering kprobes...\n");

	// unregister_kprobe_logged(&input_event_kp);
	
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
	register_kprobe_logged(&sys_reboot_kp); // dont unreg this one
#endif

	// register_kprobe_logged(&input_event_kp);
}
