#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/namei.h>

#include "arch.h"
#include "klog.h"
#include "ksud.h"
#include "kernel_compat.h"

static DEFINE_MUTEX(ksu_rp_sucompat_lock);

// struct filename *getname_flags(const char __user *filename, int flags, int *empty)
// https://elixir.bootlin.com/linux/v4.9.337/source/samples/kprobes/kretprobe_example.c

extern int ksu_getname_flags_kernel(char **kname, int flags);

struct kretprobe *getname_rp;

static int getname_flags_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int *flags = (int *)ri->data;

	struct filename *ret = (struct filename *)PT_REGS_RC(regs);
	if (IS_ERR(ret) || !ret || !ret->name)
		return 0;

	ksu_getname_flags_kernel((char **)&ret->name, *flags);
	return 0;
}

static int getname_flags_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int *flags = (int *)ri->data; // as per sample, we store everything on ri->data ?
	*flags = (int)PT_REGS_PARM2(regs); // keep a copy of arg2

	return 0;
}

#if 0
static struct kretprobe getname_kretprobe = {
	.kp.symbol_name = "getname_flags",
	.entry_handler = getname_flags_entry_handler,
	.handler = getname_flags_ret_handler,
	.data_size = sizeof(int),
	.maxactive = 20,
};
#endif

// kanged from upstrteam
// this method allows high volume register/unregister
static struct kretprobe *init_kretprobe(const char *symbol,
					kretprobe_handler_t entry_handler,
					kretprobe_handler_t ret_handler,
					size_t data_size,
					int maxactive)
{
	struct kretprobe *rp = kzalloc(sizeof(struct kretprobe), GFP_KERNEL);
	if (!rp)
		return NULL;

	rp->kp.symbol_name = symbol;
	rp->entry_handler = entry_handler;
	rp->handler = ret_handler;
	rp->data_size = data_size;
	rp->maxactive = maxactive;

	mutex_lock(&ksu_rp_sucompat_lock);
	int ret = register_kretprobe(rp);
	mutex_unlock(&ksu_rp_sucompat_lock);
	if (ret) {
		kfree(rp);
		return NULL;
	}
	pr_info("rp_sucompat: planted kretprobe at %s: %p\n", rp->kp.symbol_name, rp->kp.addr);

	return rp;
}

static void destroy_kretprobe(struct kretprobe **rp_ptr)
{
	if (!rp_ptr || !*rp_ptr)
		return;

	mutex_lock(&ksu_rp_sucompat_lock);
	unregister_kretprobe(*rp_ptr);
	mutex_unlock(&ksu_rp_sucompat_lock);
	kfree(*rp_ptr);
	*rp_ptr = NULL;
}

void rp_sucompat_exit()
{
	pr_info("rp_sucompat: unregister getname_flags!\n");
	destroy_kretprobe(&getname_rp);
}

void rp_sucompat_init()
{
	pr_info("%s: register getname_flags!\n", __func__);
	getname_rp = init_kretprobe("getname_flags", getname_flags_entry_handler,
			getname_flags_ret_handler, sizeof(int), 20);
}
