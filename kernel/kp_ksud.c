#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/binfmts.h>
#include <linux/kthread.h>
#include <linux/sched.h>

static struct task_struct *unregister_thread;

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
	unregister_kprobe_logged(&vfs_read_kp);
	
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
	register_kprobe_logged(&vfs_read_kp);
	register_kprobe_logged(&input_event_kp);
}
