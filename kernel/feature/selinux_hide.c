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
static u32 ksu_sid __read_mostly = 0;
static u32 priv_app_sid __read_mostly = 0;

static inline int ksu_selinux_get_sids()
{
	int err;

	err = security_secctx_to_secid("u:r:ksu:s0", strlen("u:r:ksu:s0"), &ksu_sid);
	if (!err)
		pr_info("selinux_hide: ksu_sid: %u\n", ksu_sid);

	err = security_secctx_to_secid("u:r:priv_app:s0:c512,c768", strlen("u:r:priv_app:s0:c512,c768"), &priv_app_sid);
	if (!err)
		pr_info("selinux_hide: priv_app_sid: %u\n", priv_app_sid);

	if (!ksu_sid || !priv_app_sid)
		return -1;

	return 0;
}

static inline void ksu_slow_avc_audit_static(u32 *tsid)
{
	if (unlikely(!ksu_selinux_hide_enabled))
		return;

	if (*tsid != ksu_sid)
		return;

	pr_info("selinux_hide: slow_avc_audit: replace tsid: %u with priv_app_sid: %u\n", *tsid, priv_app_sid);
	*tsid = priv_app_sid;

	return;
}
#ifdef CONFIG_ARM64 // on arm64 we patch insn instead
void ksu_slow_avc_audit(u32 *tsid) { } // no-op
#else
void ksu_slow_avc_audit(u32 *tsid)
{
	ksu_slow_avc_audit_static(tsid);
}
#endif

static inline bool ksu_should_destroy_context(char *str)
{
	if (!str)
		return false;

	bool status = false;

	mutex_lock(&selinux_hide_list_mutex);

	size_t offset = 0;
	while (offset < ksu_hide_type_len) {
		const char *current_entry = ksu_hide_type_list + offset;
		
		if (strstr(str, current_entry)) {
			status = true;
			goto out_unlock;
		}

		offset = offset + strlen(current_entry) + 1;
	}

	// double strstr
	char *str2 = strchr(str, ' ');
	if (!str2)
		goto out_unlock;

	offset = 0;
	while (offset < ksu_hide_rule_len) {
		const char *src_rule = ksu_hide_rule_list + offset;
		size_t src_sz = strlen(src_rule) + 1;
			
		const char *tgt_rule = src_rule + src_sz;
		size_t tgt_sz = strlen(tgt_rule) + 1;

		if (strstr(str, src_rule) && strstr(str2, tgt_rule)) {
			status = true;
			goto out_unlock;
		}

		offset = offset + src_sz + tgt_sz;
	}

out_unlock:
	mutex_unlock(&selinux_hide_list_mutex);
	return status;

}

#if 0
static inline bool ksu_should_destroy_context(char *str)
{
	if (!str)
		return false;

	down_read(&ksu_sepolicy_shitlist_lock);

	struct ksu_type_node *t_node;
	list_for_each_entry(t_node, &ksu_hide_type_list, list) {
		if (strstr(str, t_node->padded_name)) {
			up_read(&ksu_sepolicy_shitlist_lock);
			return true;
		}
	}

	// double strstr
	char *str2 = strchr(str, ' ');
	if (!str2) {
		up_read(&ksu_sepolicy_shitlist_lock);
		return false;
	}		

	struct ksu_rule_node *r_node;
	list_for_each_entry(r_node, &ksu_hide_rule_list, list) {
		if (strstr(str, r_node->src) && strstr(str2, r_node->tgt)) {
			up_read(&ksu_sepolicy_shitlist_lock);
			return true;
		}
	}

	up_read(&ksu_sepolicy_shitlist_lock);
	return false;
}
#endif

// NOTE: this is also available as manual hook for 6.8+
int ksu_hide_setprocattr(const char *name, void *value, size_t size)
{
	if (unlikely(!ksu_selinux_hide_enabled))
		return 0;

	// only hook when seccomp is enabled
	if (!test_thread_flag(TIF_SECCOMP))
		return 0;

	// only appuid
	if (current_uid().val < 10000)
		return 0;

	if (!size)
		return 0;

	if (!name)
		return 0;

	if (!!strcmp(name, "current"))
		return 0;

	char *str = (char *)value;

	if (!str)
		return 0;

	// to make sure its terminated
	char buf[64] = { 0 };
	size_t len = (size < 63) ? size : 63;

	memcpy(buf, str, len);

	if (!ksu_should_destroy_context(buf))
		return 0;
	
	pr_info("selinux_hide: setprocattr: destroy: %s\n", buf);
	str[1] = '1';

	return 0;
}

// for manual hook, remove this in a month
void ksu_sel_write_context(struct file **file, char **buf, size_t *size)
{
	return;
}

#if defined(CONFIG_KPROBES) && !defined(CONFIG_ARM64)

#include <linux/kprobes.h>
static struct kprobe *slow_avc_audit_kp;

static int slow_avc_audit_pre_handler(struct kprobe *p, struct pt_regs *regs)
{

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0) && defined(KSU_COMPAT_HAS_SELINUX_STATE)
	u32 *tsid = (u32 *)&PT_REGS_PARM3(regs);
#else
	u32 *tsid = (u32 *)&PT_REGS_PARM2(regs);
#endif

	ksu_slow_avc_audit(tsid);

	return 0;
}

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
		pr_info("selinux_hide: sid grab fail?\n");

#if defined(CONFIG_KPROBES) && !defined(CONFIG_ARM64)
	slow_avc_audit_kp = init_kprobe("slow_avc_audit", slow_avc_audit_pre_handler);
#endif

	ksu_selinux_hide_enabled = true;
}

static void ksu_selinux_hide_disable()
{
#if defined(CONFIG_KPROBES) && !defined(CONFIG_ARM64)
	pr_info("selinux_hide: unregister slow_avc_audit kprobe!\n");
	destroy_kprobe(&slow_avc_audit_kp);
#endif

	pr_info("selinux_hide: closing down hooks!\n");

	ksu_selinux_hide_enabled = false;
}

// selinux_transaction_write hijack

static ssize_t (*selinux_transaction_write_fn)(struct file *file, const char __user *buf, size_t size, loff_t *pos) __read_mostly = NULL;
static __nocfi ssize_t ksu_selinux_transaction_write(struct file *file, const char __user *buf, size_t size, loff_t *pos)
{
	if (unlikely(!ksu_selinux_hide_enabled))
		goto skip_destroy;

	if (!test_thread_flag(TIF_SECCOMP))
		goto skip_destroy;

	if (current_uid().val < 10000)
		goto skip_destroy;

	char kbuf[128] = { 0 };
	if (ksu_copy_from_user_retry(kbuf, buf, 127))
		goto skip_destroy;

	if (!ksu_should_destroy_context(kbuf))
		goto skip_destroy;

	// or copy_to_user? is it writable? or we vm_mmap? or hunt for writable section on start_stack again?
	// NOTE: if this is 'timeable', to equalize, we should call selinux_transaction_write_fn before ret EINVAL
	pr_info("selinux_hide: selinux_transaction_write: destroy: %s \n", kbuf);
	return -EINVAL;

skip_destroy:
	return selinux_transaction_write_fn(file, buf, size, pos);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0) && defined(KSU_COMPAT_HAS_SELINUX_STATE)
extern struct selinux_state selinux_state;
#define ksu_selinux_kernel_status_page() selinux_kernel_status_page(&selinux_state)
#else
#define ksu_selinux_kernel_status_page() selinux_kernel_status_page()
#endif

static struct page *ksu_fake_status_page __read_mostly = NULL;

static int ksu_prepare_fake_status_page()
{
	struct page *real_page = ksu_selinux_kernel_status_page();
	if (!real_page)
		return -ENOMEM;

	// this is the page we present
	struct page *new_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!new_page)
		return -ENOMEM;

	// we will leak one page but thats fine
	// not a leak when it is used forever :)
	struct selinux_kernel_status *real_status = page_address(real_page);
	struct selinux_kernel_status *fake_status = page_address(new_page);
    
	memcpy(fake_status, real_status, sizeof(*real_status));

	fake_status->enforcing = 1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	fake_status->sequence = 4;
	fake_status->policyload = 1;
#else
	fake_status->sequence = 0;
	fake_status->policyload = 0;
#endif

	ksu_fake_status_page = new_page;
    
	pr_info("selinux_hide: ksu_fake_status_page ready! seq=%d\n", fake_status->sequence);
            
	return 0;
}

static int (*sel_open_handle_status_fn)(struct inode *inode, struct file *filp) __read_mostly = NULL;
static __nocfi int ksu_sel_open_handle_status(struct inode *inode, struct file *filp)
{
	if (unlikely(!ksu_selinux_hide_enabled))
		goto orig_page;

	if (!test_thread_flag(TIF_SECCOMP))
		goto orig_page;

	if (current_uid().val < 10000)
		goto orig_page;

	// won't happen! we check this on hook init!
	// if (unlikely(!ksu_fake_status_page))
	//	goto orig_page;

	filp->private_data = ksu_fake_status_page;

	pr_info("selinux_hide: sel_open_handle_status: served fake_page\n");
	return 0;

orig_page:
	return sel_open_handle_status_fn(inode, filp);
}

#if defined(CONFIG_AUDIT) && defined(CONFIG_ARM64)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
extern noinline int slow_avc_audit(u32 ssid, u32 tsid, u16 tclass,
			    u32 requested, u32 audited, u32 denied, int result,
			    struct common_audit_data *a);

static int (*slow_avc_audit_fn)(u32 ssid, u32 tsid, u16 tclass,
			    u32 requested, u32 audited, u32 denied, int result,
			    struct common_audit_data *a) __read_mostly = NULL;

__attribute__((used))
static int ksu_hook_slow_avc_audit(u32 ssid, u32 tsid, u16 tclass,
				   u32 requested, u32 audited, u32 denied, int result,
				   struct common_audit_data *a)
{
	ksu_slow_avc_audit_static(&tsid);
	return slow_avc_audit_fn(ssid, tsid, tclass, requested, audited, denied, result, a);
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
extern noinline int slow_avc_audit(struct selinux_state *state,
			    u32 ssid, u32 tsid, u16 tclass,
			    u32 requested, u32 audited, u32 denied, int result,
			    struct common_audit_data *a);

static int (*slow_avc_audit_fn)(struct selinux_state *state,
			    u32 ssid, u32 tsid, u16 tclass,
			    u32 requested, u32 audited, u32 denied, int result,
			    struct common_audit_data *a) __read_mostly = NULL;

__attribute__((used))
static int ksu_hook_slow_avc_audit(struct selinux_state *state,
				   u32 ssid, u32 tsid, u16 tclass,
				   u32 requested, u32 audited, u32 denied, int result,
				   struct common_audit_data *a)
{
	ksu_slow_avc_audit_static(&tsid);
	return slow_avc_audit_fn(state, ssid, tsid, tclass, requested, audited, denied, result, a);
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && defined(KSU_COMPAT_HAS_SELINUX_STATE)
extern noinline int slow_avc_audit(struct selinux_state *state,
			    u32 ssid, u32 tsid, u16 tclass,
			    u32 requested, u32 audited, u32 denied, int result,
			    struct common_audit_data *a,
			    unsigned int flags);

static int (*slow_avc_audit_fn)(struct selinux_state *state,
			    u32 ssid, u32 tsid, u16 tclass,
			    u32 requested, u32 audited, u32 denied, int result,
			    struct common_audit_data *a,
			    unsigned int flags) __read_mostly = NULL;

__attribute__((used))
static int ksu_hook_slow_avc_audit(struct selinux_state *state,
				   u32 ssid, u32 tsid, u16 tclass,
				   u32 requested, u32 audited, u32 denied, int result,
				   struct common_audit_data *a,
				   unsigned int flags)
{
	ksu_slow_avc_audit_static(&tsid);
	return slow_avc_audit_fn(state, ssid, tsid, tclass, requested, audited, denied, result, a, flags);
}
#else
extern noinline int slow_avc_audit(u32 ssid, u32 tsid, u16 tclass,
			    u32 requested, u32 audited, u32 denied, int result,
			    struct common_audit_data *a,
			    unsigned int flags);

static int (*slow_avc_audit_fn)(u32 ssid, u32 tsid, u16 tclass,
			    u32 requested, u32 audited, u32 denied, int result,
			    struct common_audit_data *a,
			    unsigned int flags) __read_mostly = NULL;

__attribute__((used))
static int ksu_hook_slow_avc_audit(u32 ssid, u32 tsid, u16 tclass,
				   u32 requested, u32 audited, u32 denied, int result,
				   struct common_audit_data *a,
				   unsigned int flags)
{
	ksu_slow_avc_audit_static(&tsid);
	return slow_avc_audit_fn(ssid, tsid, tclass, requested, audited, denied, result, a, flags);
}
#endif

/*

https://godbolt.org/z/Eh8vfrdns

__attribute__((noinline)) 
void target_fn() {
    volatile int x = 0;
}

int main() {
    target_fn();
    return 0;
}

target_fn:
        sub     sp, sp, #16
        str     wzr, [sp, 12]
        nop
        add     sp, sp, 16
        ret
main:
        stp     x29, x30, [sp, -16]!
        mov     x29, sp
        bl      target_fn   << hunt for this!
        mov     w0, 0
        ldp     x29, x30, [sp], 16
        ret
*/

// bl is 94 ~ 97

static void hunt_slow_avc_audit_callsite(uintptr_t target_address)
{
	extern char _stext[], _etext[];

	uintptr_t start_addr = (uintptr_t)_stext;
	uintptr_t end_addr = (uintptr_t)_etext;
	uintptr_t curr_addr = start_addr;
	uint32_t raw_instruction; // arm64 wordsize

start_scan:
	if (curr_addr >= end_addr)
		goto bail;

	if (copy_from_kernel_nofault(&raw_instruction, (void *)curr_addr, sizeof(uint32_t)))
		goto step_up;

	// aarch64_insn_is_##abbr
	if (!aarch64_insn_is_bl(raw_instruction))
		goto step_up;

	// signed
	long offset = aarch64_get_branch_offset(raw_instruction);
	uintptr_t calculated_destination = curr_addr + offset;

	if (calculated_destination != (uintptr_t)&slow_avc_audit)
		goto step_up;

	pr_info("selinux_hide: found slow_avc_audit call site at 0x%lx\n", curr_addr);

	u32 insn = aarch64_insn_gen_branch_imm(curr_addr, (uintptr_t)&ksu_hook_slow_avc_audit, AARCH64_INSN_BRANCH_LINK);
	void *arr_addr[] = { (void*)curr_addr };
	uint32_t arr_insn[] = { insn };

	int res = aarch64_insn_patch_text(arr_addr, arr_insn, 1);

	pr_info("selinux_hide: patched callsite at 0x%lx to hook!\n", curr_addr);

step_up:
	curr_addr = curr_addr + sizeof(uint32_t);
	goto start_scan;

bail:
	pr_info("selinux_hide: callsite scan done!\n");
	return;
}
#endif

#define FORCE_VOLATILE(x) *(volatile typeof(x) *)&(x)

static void ksu_init_hook_selinux_transaction_write()
{
	struct path path;
	const char *selinux_context = "/sys/fs/selinux/context";

	int error = kern_path(selinux_context, LOOKUP_FOLLOW, &path);
	if (error) {
		pr_info("selinux_hide: kern_path err: %d\n", error);
		return;
	}

	pr_info("selinux_hide: kern_path %s ok!\n", selinux_context);

	if (!path.dentry)
		goto bail_out;

	if (!d_inode(path.dentry))
		goto bail_out;		

	struct file_operations *fops = (struct file_operations *)d_inode(path.dentry)->i_fop;
	if (!fops)
		goto bail_out;

	if (!fops->write)
		goto bail_out;

	pr_info("selinux_hide: found transaction_ops->write at 0x%lx \n", (uintptr_t)fops->write);
	selinux_transaction_write_fn = fops->write;

	unsigned long addr = (unsigned long)&fops->write;
	unsigned long base = addr & PAGE_MASK;
	unsigned long offset = addr & ~PAGE_MASK;

	struct page *page = phys_to_page(__pa(base));
	if (!page)
		goto bail_out;

	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		goto bail_out;

	void **target_slot = (void **)((unsigned long)writable_addr + offset);
				
	preempt_disable();
	local_irq_disable();
					
	FORCE_VOLATILE(*target_slot) = (void *)ksu_selinux_transaction_write;
					
	local_irq_enable();
	preempt_enable();

	vunmap(writable_addr);
	smp_mb();

	pr_info("selinux_hide: transaction_ops->write hijacked!\n");

bail_out:
	path_put(&path);
}

static void ksu_init_hook_selinux_status_open()
{
	struct path path;
	const char *selinux_status = "/sys/fs/selinux/status";

	int error = kern_path(selinux_status, LOOKUP_FOLLOW, &path);
	if (error) {
		pr_info("selinux_hide: kern_path err: %d\n", error);
		return;
	}
	
	pr_info("selinux_hide: kern_path %s ok!\n", selinux_status);

	if (!path.dentry)
		goto bail_out;

	if (!d_inode(path.dentry))
		goto bail_out;	

	struct file_operations *fops = (struct file_operations *)d_inode(path.dentry)->i_fop;
	if (!fops)
		goto bail_out;

	if (!fops->open)
		goto bail_out;

	pr_info("selinux_hide: found sel_handle_status_ops->open at 0x%lx\n", (uintptr_t)fops->open);

	sel_open_handle_status_fn = fops->open;

	unsigned long addr = (unsigned long)&fops->open;
	unsigned long base = addr & PAGE_MASK;
	unsigned long offset = addr & ~PAGE_MASK;

	struct page *page = phys_to_page(__pa(base));
	if (!page)
		goto bail_out;

	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		goto bail_out;

	void **target_slot = (void **)((unsigned long)writable_addr + offset);
				
	preempt_disable();
	local_irq_disable();
					
	FORCE_VOLATILE(*target_slot) = (void *)ksu_sel_open_handle_status;
					
	local_irq_enable();
	preempt_enable();

	vunmap(writable_addr);
	smp_mb();

	pr_info("selinux_hide: sel_handle_status_ops->open hijacked!\n");

bail_out:
	path_put(&path);
}

// init kthread
static int ksu_hide_init_thread(void *data)
{
	set_user_nice(current, 19); // low prio

wait_start:
	// in input hook got turned off means we have ksud!
	if (!*(volatile bool *)&ksu_input_hook)
		goto init_hooks;

	msleep(5000);

	goto wait_start;

init_hooks:
	;
	// apply_kernelsu_rules_fn
	const char *ksu_domain_args[] = { KERNEL_SU_DOMAIN, NULL };
	ksu_add_shit_to_list(KSU_SEPOLICY_CMD_TYPE, ksu_domain_args);

	const char *ksu_file_args[] = { KERNEL_SU_FILE, NULL };
	ksu_add_shit_to_list(KSU_SEPOLICY_CMD_TYPE, ksu_file_args);

	const char *init_adb_args[] = { "init", "adb_data_file", NULL };
	ksu_add_shit_to_list(KSU_SEPOLICY_CMD_NORMAL_PERM, init_adb_args);

	// we move this to a module instead
	// const char *adbroot_args[] = { "adbroot", NULL };
	// ksu_add_shit_to_list(KSU_SEPOLICY_CMD_TYPE, adbroot_args);

	ksu_selinux_hide_enable();
	ksu_init_hook_selinux_transaction_write();

#if defined(CONFIG_AUDIT) && defined(CONFIG_ARM64)
	slow_avc_audit_fn = slow_avc_audit;
	pr_info("selinux_hide: slow_avc_audit found at 0x%lx\n", (uintptr_t)slow_avc_audit_fn);
	hunt_slow_avc_audit_callsite((uintptr_t)slow_avc_audit_fn);
#endif

	int tries = 0;
try_again:
	if (!ksu_prepare_fake_status_page())
		goto page_ok;
		
	msleep(1000);
	tries = tries + 1;
	if (tries > 10)
		return 0;

	goto try_again;

page_ok:
	ksu_init_hook_selinux_status_open();

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

