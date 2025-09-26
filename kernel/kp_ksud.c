#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/binfmts.h>
#include <linux/kthread.h>
#include <linux/sched.h>

static struct task_struct *unregister_thread;

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

// security_bounded_transition
#if defined(CONFIG_KRETPROBES) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
extern u32 ksud_init_sid;
extern u32 ksud_su_sid;
extern int grab_transition_sids();

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
	if (old_sid == ksud_init_sid && new_sid == ksud_su_sid) {
		pr_info("kp_ksud: security_bounded_transition: allowing init (%d) -> su (%d)\n", ksud_init_sid, ksud_su_sid);
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

static struct task_struct *unregister_rp_thread;

static int rp_ksud_transition_unregister()
{
	unregister_kretprobe(&bounded_transition_rp);
	pr_info("kp_ksud: unregister rp: security_bounded_transition\n");
	
	unregister_rp_thread = NULL;
	return 0;
}

void kp_ksud_transition_routine_end()
{
	unregister_rp_thread = kthread_run(rp_ksud_transition_unregister, NULL, "rp_unregister");
	if (IS_ERR(unregister_rp_thread)) {
		unregister_rp_thread = NULL;
		return;
	}
}

void kp_ksud_transition_routine_start()
{
	// we only need to run this once.
	// once we got sids, we are ready
	if (ksud_su_sid != 0)
		return;

	// grab sids outside of kretprobe context
	int ret = grab_transition_sids();
	if (ret)
		return;
	
	ret = register_kretprobe(&bounded_transition_rp);
	pr_info("kp_ksud: register rp: security_bounded_transition ret: %d\n", ret);
}
#endif // security_bounded_transition

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

static int unregister_kprobe_function(void *data)
{
	//pr_info("kp_ksud: unregistering kprobes...\n");

	unregister_kprobe_logged(&input_event_kp);
	
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

static void register_kprobe_logged(struct kprobe *kp)
{
	int ret = register_kprobe(kp);
	pr_info("kp_ksud: register kp: %s ret: %d\n", kp->symbol_name, ret);

}

void kp_ksud_init()
{
	register_kprobe_logged(&input_event_kp);
}
