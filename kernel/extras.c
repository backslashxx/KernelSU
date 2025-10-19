// sorry for the ifdef hell
// but im too lazy to fragment this out.
// theres only one feature so far anyway
// - xx, 20251019

static u32 su_sid __read_mostly = 0;
static u32 ksu_sid __read_mostly = 0;
static u32 priv_app_sid __read_mostly = 0;

void ksu_avc_spoof_enable();
void ksu_avc_spoof_disable();

static bool ksu_avc_spoof_enabled = true;
static bool boot_completed = false;

static int avc_spoof_feature_get(u64 *value)
{
	*value = ksu_avc_spoof_enabled ? 1 : 0;
	return 0;
}

static int avc_spoof_feature_set(u64 value)
{
	bool enable = value != 0;

	if (enable == ksu_avc_spoof_enabled) {
		pr_info("avc_spoof: no need to change\n");
		return 0;
	}

	ksu_avc_spoof_enabled = enable;

	if (boot_completed) {
		if (enable) {
			ksu_avc_spoof_enable();
		} else {
			ksu_avc_spoof_disable();
		}
	}

	pr_info("avc_spoof: set to %d\n", enable);

	return 0;
}

static const struct ksu_feature_handler avc_spoof_handler = {
	.feature_id = KSU_FEATURE_AVC_SPOOF,
	.name = "avc_spoof",
	.get_handler = avc_spoof_feature_get,
	.set_handler = avc_spoof_feature_set,
};

static int get_sid()
{
	// dont load at all if we cant get sids
	int err = security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &su_sid);
	if (err) {
		pr_info("get_sid: su_sid not found!\n");
		return -1;
	}
	pr_info("get_sid: su_sid: %u\n", su_sid);

	err = security_secctx_to_secid("u:r:ksu:s0", strlen("u:r:ksu:s0"), &ksu_sid);
	if (err) {
		pr_info("get_sid: ksu_sid not found!\n");
		return -1;
	}
	pr_info("get_sid: ksu_sid: %u\n", ksu_sid);

	err = security_secctx_to_secid("u:r:priv_app:s0:c512,c768", strlen("u:r:priv_app:s0:c512,c768"), &priv_app_sid);
	if (err) {
		pr_info("get_sid: priv_app_sid not found!\n");
		return -1;
	}
	pr_info("get_sid: priv_app_sid: %u\n", priv_app_sid);
	return 0;
}

// deprecate in a month
int ksu_handle_slow_avc_audit_new(u32 tsid, u16 *tclass)
{
	if (tsid != su_sid && tsid != ksu_sid)
		return 0;

	pr_info("slow_avc_audit: prevent log for sid: %u\n", tsid);
	*tclass = 0;

	return 0;
}

void ksu_slow_avc_audit(u32 *tsid)
{
	// if tsid is su, we just replace it
	// unsure if its enough, but this is how it is aye?
	if (*tsid == su_sid || *tsid == ksu_sid) {
		pr_info("slow_avc_audit: replace tsid: %u with priv_app_sid: %u\n", *tsid, priv_app_sid);
		*tsid = priv_app_sid;
	}

	return;
}

void ksu_sel_write_context(struct file **file, char **buf, size_t *size)
{
	if (!test_thread_flag(TIF_SECCOMP))
		return;

	char *mbuf = *buf;

	if (!mbuf)
		return;
	
	if (strstarts(mbuf, "u:r:ksu:s0"))
		goto mutate_buf;

	if (strstarts(mbuf, "u:object_r:ksu_file:s0"))
		goto mutate_buf;

	// some modules add this
	if (strstarts(mbuf, "u:object_r:magisk_file:s0"))
		goto mutate_buf;

	return;

mutate_buf:
	pr_info("sel_write_context: destroy: %s \n", mbuf);
	mbuf[1] = '1';
	return;
}


#if defined(CONFIG_KPROBES)

#include <linux/kprobes.h>
static struct kprobe *slow_avc_audit_kp;
static struct kprobe *sel_write_context_kp;

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

// copied from upstream
static struct kprobe *init_kprobe(const char *name,
				  kprobe_pre_handler_t handler)
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

void ksu_avc_spoof_disable(void)
{
#if defined(CONFIG_KPROBES)
	pr_info("extras/exit: unregister slow_avc_audit kprobe!\n");
	destroy_kprobe(&slow_avc_audit_kp);

	pr_info("extras/exit: unregister sel_write_context kprobe!\n");
	destroy_kprobe(&sel_write_context_kp);
#endif

}

void ksu_avc_spoof_enable(void) 
{
	int ret = get_sid();
	if (ret) {
		pr_info("avc_spoof/init: sid grab fail!\n");
		return;
	}

#if defined(CONFIG_KPROBES)
	pr_info("extras/init: register slow_avc_audit kprobe!\n");
	slow_avc_audit_kp = init_kprobe("slow_avc_audit", slow_avc_audit_pre_handler);

	pr_info("extras/init: register sel_write_context kprobe!\n");
	sel_write_context_kp = init_kprobe("sel_write_context", sel_write_context_pre_handler);
#endif
}

void ksu_avc_spoof_late_init()
{
	boot_completed = true;
	
	if (ksu_avc_spoof_enabled) {
		ksu_avc_spoof_enable();
	}
}

// feature reg
void ksu_avc_spoof_init()
{
	if (ksu_register_feature_handler(&avc_spoof_handler)) {
		pr_err("Failed to register avc spoof feature handler\n");
	}
}

void ksu_avc_spoof_exit()
{
	if (ksu_avc_spoof_enabled) {
		ksu_avc_spoof_disable();
	}
	ksu_unregister_feature_handler(KSU_FEATURE_AVC_SPOOF);
}

static int ksu_extras_init_thread(void *data)
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
	ksu_avc_spoof_late_init();
	return 0;
}

static __init int ksu_extras_init()
{
	ksu_avc_spoof_init(); // so the feature is registered

	// late init
	kthread_run(ksu_extras_init_thread, NULL, "kthread");
	return 0;
}
late_initcall(ksu_extras_init);
