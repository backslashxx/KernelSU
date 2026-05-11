/**
 *  NOTE: this isnt the fullblown thing like upstream's where we straight up backport
 *  SELinux. This is just questionable to do when we want to support a plethora of
 *  non-standard kernels.
 *
 *  While what we are doing here is kinda improper, for most cases
 *  this should be mroe than enough.
 *
 *  this will include write_op / selinux_transaction_write spoofing and then avc spoofing.
 *  our goal for this one is to be self contained as much as possible
 *  with only one call from ksu's initcall.
 *
 */

// enabled by default
static bool ksu_selinux_hide_enabled __read_mostly = true;

// sids for avc spoofing
static u32 su_sid __read_mostly = 0;
static u32 ksu_sid __read_mostly = 0;
static u32 priv_app_sid __read_mostly = 0;

static inline int ksu_selinux_get_sids()
{
	// dont load at all if we cant get sids
	int err = security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &su_sid);
	if (!err)
		pr_info("selinux_hide: su_sid: %u\n", su_sid);

	err = security_secctx_to_secid("u:r:ksu:s0", strlen("u:r:ksu:s0"), &ksu_sid);
	if (!err)
		pr_info("selinux_hide: ksu_sid: %u\n", su_sid);

	err = security_secctx_to_secid("u:r:priv_app:s0:c512,c768", strlen("u:r:priv_app:s0:c512,c768"), &priv_app_sid);
	if (!err)
		pr_info("selinux_hide: priv_app_sid: %u\n", su_sid);

	if (!su_sid || !ksu_sid || !priv_app_sid)
		return -1;

	return 0;
}

// deprecate in a month
int ksu_handle_slow_avc_audit_new(u32 tsid, u16 *tclass)
{
	if (!ksu_selinux_hide_enabled)
		return 0;

	if (tsid != su_sid && tsid != ksu_sid)
		return 0;

	pr_info("selinux_hide: prevent log for sid: %u\n", tsid);
	*tclass = 0;

	return 0;
}

void ksu_slow_avc_audit(u32 *tsid)
{
	if (!ksu_selinux_hide_enabled)
		return;

	// if tsid is su, we just replace it
	// unsure if its enough, but this is how it is aye?
	if (*tsid == su_sid || *tsid == ksu_sid) {
		pr_info("selinux_hide: slow_avc_audit: replace tsid: %u with priv_app_sid: %u\n", *tsid, priv_app_sid);
		*tsid = priv_app_sid;
	}

	return;
}

static inline bool ksu_should_destroy_context(char *str)
{
	if (!str || !strchr(str, ':'))
		return false;

	if (strstr(str, "u:r:ksu:s0"))
		return true;

	if (strstr(str, "u:object_r:ksu_file:s0"))
		return true;

	struct ksu_hidden_node *node;

	read_lock(&ksu_sepolicy_shitlist_lock);
	list_for_each_entry(node, &ksu_sepolicy_rule_list, list) {
		if (strstr(str, node->name)) {
			read_unlock(&ksu_sepolicy_shitlist_lock);
			return true;
		}
	}
	read_unlock(&ksu_sepolicy_shitlist_lock);

	return false;
}

// for manual hook
void ksu_sel_write_context(struct file **file, char **buf, size_t *size)
{
	if (!ksu_selinux_hide_enabled)
		return;

	// only hook when seccomp is enabled
	if (!test_thread_flag(TIF_SECCOMP))
		return;

	// only appuid
	if (current_uid().val < 10000)
		return;

	// upstream doesnt do this, so we should also not.
	//if (!ksu_uid_should_umount(current_uid().val))
	//	return;

	char *mbuf = *buf;

	if (!mbuf)
		return;

	if (!ksu_should_destroy_context(mbuf))
		return;

	pr_info("selinux_hide: destroy: %s \n", mbuf);
	mbuf[1] = '1';
	return;

}

#if defined(CONFIG_KPROBES)

#include <linux/kprobes.h>
static struct kprobe *slow_avc_audit_kp;
static struct kprobe *sel_write_context_kp;
static struct kprobe *sel_write_access_kp;

static int slow_avc_audit_pre_handler(struct kprobe *p, struct pt_regs *regs)
{

#if defined(KSU_COMPAT_HAS_SELINUX_STATE)
	u32 *tsid = (u32 *)&PT_REGS_PARM3(regs);
#else
	u32 *tsid = (u32 *)&PT_REGS_PARM2(regs);
#endif

	ksu_slow_avc_audit(tsid);

	return 0;
}

static int sel_write_context_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	char **buf = (char **)&PT_REGS_PARM2(regs);

	ksu_sel_write_context(NULL, buf, NULL);
	return 0;
}


// this deals with __user, this is here in case its really needed.
#if 0
static int selinux_transaction_write_pre_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	
	bool *should_destroy = (bool *)ri->data;
	*should_destroy = false;

	if (!test_thread_flag(TIF_SECCOMP))
		return 0;

	if (current_uid().val < 10000)
		return 0;

	if (!ksu_uid_should_umount(current_uid().val))
		return 0;

	const char __user **buf = (const char __user **)&PT_REGS_PARM2(regs);
	char __user *uptr = *(char **)buf;

	char kbuf[128] = { 0 };

	if (ksu_copy_from_user_retry(kbuf, uptr, 127))
		return 0;

	// move ptr to the next one after space
	char *target = strchr(kbuf, ' ');
	if (likely(target))
		target++;
	else
		target = kbuf;

	if (!ksu_should_destroy_context(target))
		return 0;

	pr_info("selinux_transaction_write: destroy: %s \n", kbuf);
	*should_destroy = true;

	return 0;
}

static int selinux_transaction_write_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	// if bool is true, mod PT_REGS_RC to ret EINVAL
	bool *should_destroy = (bool *)ri->data;
	
	if (*should_destroy)
		PT_REGS_RC(regs) = -EINVAL;

	return 0;
}

static struct kretprobe selinux_transaction_write_rp = {
	.kp.symbol_name = "selinux_transaction_write",
	.handler = selinux_transaction_write_ret_handler,
	.entry_handler = selinux_transaction_write_pre_handler,
	.data_size = sizeof(bool),
	.maxactive = 20,
};
#endif

// copied from upstream
static struct kprobe *init_kprobe(const char *name, kprobe_pre_handler_t handler)
{
	struct kprobe *kp = kzalloc(sizeof(struct kprobe), GFP_KERNEL);
	if (!kp)
		return NULL;
	kp->symbol_name = name;
	kp->pre_handler = handler;

	int ret = register_kprobe(kp);
	pr_info("%s: register %s kprobe: %d\n", __func__, name, ret);
	if (ret) {
		kfree(kp);
		return NULL;
	}

	return kp;
}
static void destroy_kprobe(struct kprobe **kp_ptr)
{
	struct kprobe *kp = *kp_ptr;
	if (!kp)
		return;
	unregister_kprobe(kp);
	synchronize_rcu();
	kfree(kp);
	*kp_ptr = NULL;
}
#endif // CONFIG_KPROBES


static void ksu_selinux_hide_enable() 
{
	int ret = ksu_selinux_get_sids();
	if (ret)
		pr_info("selinux_hide: sid grab fail!\n");

#if defined(CONFIG_KPROBES)
	slow_avc_audit_kp = init_kprobe("slow_avc_audit", slow_avc_audit_pre_handler);

	sel_write_context_kp = init_kprobe("sel_write_context", sel_write_context_pre_handler);
	sel_write_access_kp = init_kprobe("sel_write_access", sel_write_context_pre_handler);
#else
	pr_info("selinux_hide: running without kprobes! make sure manual hooks are in-place!\n");
#endif

	ksu_selinux_hide_enabled = true;
}

static void ksu_selinux_hide_disable()
{
#if defined(CONFIG_KPROBES)
	pr_info("selinux_hide: unregister slow_avc_audit kprobe!\n");
	destroy_kprobe(&slow_avc_audit_kp);

	pr_info("selinux_hide: unregister sel_write_context kprobe!\n");
	destroy_kprobe(&sel_write_context_kp);

	pr_info("selinux_hide: unregister sel_write_access kprobe!\n");
	destroy_kprobe(&sel_write_access_kp);
#endif

	ksu_selinux_hide_enabled = false;
}

// init kthread
static int ksu_hide_init_thread(void *data)
{
	unsigned int i = 0;

	set_user_nice(current, 19); // low prio

start:
	if (!!*(volatile bool *)&ksu_boot_completed)
		goto bail;

	msleep(5000);

	i++;

	if (i < 12)
		goto start;

bail:
	ksu_selinux_hide_enable();
	return 0;
}

static int selinux_hide_feature_get(u64 *value)
{
	*value = ksu_selinux_hide_enabled ? 1 : 0;
	return 0;
}

static int selinux_hide_feature_set(u64 value)
{
	bool enable = value != 0;
	int ret = 0;

	if (enable == ksu_selinux_hide_enabled)
		return 0;

	pr_info("selinux_hide: set to %d\n", enable);

	if (enable)
		ksu_selinux_hide_enable();
	else
		ksu_selinux_hide_disable();

	return ret;
}

static const struct ksu_feature_handler selinux_hide_handler = {
	.feature_id = KSU_FEATURE_SELINUX_HIDE,
	.name = "selinux_hide",
	.get_handler = selinux_hide_feature_get,
	.set_handler = selinux_hide_feature_set,
};

void __init ksu_selinux_hide_init()
{
	// we init this on a kthread
	kthread_run(ksu_hide_init_thread, NULL, "kthread");

	if (ksu_register_feature_handler(&selinux_hide_handler)) {
		pr_err("Failed to register selinux_hide feature handler\n");
	}
}

void __exit ksu_selinux_hide_exit()
{
	ksu_unregister_feature_handler(KSU_FEATURE_SELINUX_HIDE);
}

