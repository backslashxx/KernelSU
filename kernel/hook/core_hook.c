#ifdef CONFIG_KSU_LSM_SECURITY_HOOKS
#define LSM_HANDLER_TYPE static int
#else
#define LSM_HANDLER_TYPE int
#endif

LSM_HANDLER_TYPE ksu_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			    struct inode *new_inode, struct dentry *new_dentry)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return 0;
}

LSM_HANDLER_TYPE ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	// see sys_setresuid
	if (flags == LSM_SETID_RES)
		ksu_handle_setresuid_cred(new, old);

	return 0;
}

LSM_HANDLER_TYPE ksu_bprm_check(struct linux_binprm *bprm)
{

#ifdef CONFIG_KSU_FEATURE_SULOG
	ksu_sulog_emit_bprm((const char *)bprm->filename);
#endif

	return 0;
}

LSM_HANDLER_TYPE ksu_file_permission(struct file *file, int mask)
{
#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE)
#ifdef KSU_CAN_USE_JUMP_LABEL
	if (static_branch_likely(&ksud_vfs_read_key))
		ksu_install_rc_hook(file);
#else
	if (unlikely(ksu_vfs_read_hook))
		ksu_install_rc_hook(file);
#endif
#endif

	return 0;
}

#ifdef CONFIG_KSU_LSM_SECURITY_HOOKS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
static struct security_hook_list ksu_hooks[] = {
	LSM_HOOK_INIT(inode_rename, ksu_inode_rename),
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
#ifdef CONFIG_KSU_FEATURE_SULOG
	LSM_HOOK_INIT(bprm_check_security, ksu_bprm_check),
#endif
#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE)
	LSM_HOOK_INIT(file_permission, ksu_file_permission),
#endif
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
static void ksu_lsm_hook_init(void)
{
	// security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
}

#else
static void ksu_lsm_hook_init(void)
{
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
}
#endif //  < 4.11

#else // 4.2

// selinux_ops (LSM), security_operations struct tampering for ultra legacy

static uintptr_t selinux_ops_addr = NULL;

static int (*orig_inode_rename) (struct inode *old_dir, struct dentry *old_dentry,
			     struct inode *new_dir, struct dentry *new_dentry) = NULL;
static int hook_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			    struct inode *new_inode, struct dentry *new_dentry)
{
	ksu_inode_rename(old_inode, old_dentry, new_inode, new_dentry);
	return orig_inode_rename(old_inode, old_dentry, new_inode, new_dentry);
}

static int (*orig_task_fix_setuid) (struct cred *new, const struct cred *old, int flags) = NULL;
static int hook_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	ksu_task_fix_setuid(new, old, flags);
	return orig_task_fix_setuid(new, old, flags);
}

static int (*orig_bprm_check_security)(struct linux_binprm *bprm) = NULL;
static int hook_bprm_check_security(struct linux_binprm *bprm)
{
	ksu_bprm_check(bprm);
	return orig_bprm_check_security(bprm);
}

static int (*orig_file_permission) (struct file *file, int mask) = NULL;
static int hook_file_permission(struct file *file, int mask)
{

	ksu_file_permission(file, mask);
	return orig_file_permission(file, mask);
}

static inline bool verify_selinux_cred_free(void *fn_ptr)
{
	bool success = false;

	if (!fn_ptr)
		return false;

	// ref: https://elixir.bootlin.com/linux/v3.18.140/source/security/selinux/hooks.c#L3474
	void (*selinux_cred_free_fn)(struct cred *) = fn_ptr;

	struct cred dummy_cred;

	// explicitly set it to NULL
	// make sure this happens!
	// #1. it wont trigger BUG_ON
	// #2. this way it will kfree(NULL), which does nothing
	*(volatile void **)&dummy_cred.security = NULL;
	barrier();

	selinux_cred_free_fn(&dummy_cred);

	// check if selinux_cred_free is successful
	if ((unsigned long)*(volatile void **)&dummy_cred.security == 0x7UL)
		success = true;

	pr_info("selinux_cred_free: 0x%lx cred->security: 0x%lx success: %d\n", (unsigned long)fn_ptr, (unsigned long)dummy_cred.security, success);

	return success;
}

// we should see a lot of pointers that is inside stext && etext
// basically we check for "pointer density"
static inline bool is_selinux_ops_valid(uintptr_t addr)
{
	extern char _stext[], _etext[];
	int total_slots = sizeof(struct security_operations) / sizeof(void *); 
	int valid_ptr = 0;
	int i = 0;

	uintptr_t member_ptr = 0;
	uintptr_t current_slot_addr;

	// we will be off by one or off by two due to sizeof("selinux")
	// thats 8 bytes, on 32 bit, this is two pointers worth, not a big deal

density_verify_start:
	current_slot_addr = addr + (i * sizeof(void *));

	member_ptr = 0;
	if (copy_from_kernel_nofault(&member_ptr, (void *)current_slot_addr, sizeof(uintptr_t) ))
		goto next_iter; // if it fails, just try next slot

	// give up early
	if (!valid_ptr && i >= 20)
		return false;

	// pr_info("%s: member_ptr: 0x%lx \n", __func__, (long)member_ptr);
	if (member_ptr >= (uintptr_t)_stext && member_ptr <= (uintptr_t)_etext)
		valid_ptr++;

next_iter:
	i++;	
	if (i < total_slots)
		goto density_verify_start;

	pr_info("%s: density: valid: %lu slots: %lu \n", __func__, valid_ptr, total_slots);

	// maybe increase to 75% or something?
	return (valid_ptr > (total_slots / 2));
}

static inline bool check_candidate(uintptr_t addr)
{
	struct security_operations *candidate = (struct security_operations *)addr;

	char char_buf[sizeof("selinux")] = { 0 };

	if (copy_from_kernel_nofault(char_buf, (void *)addr, sizeof("selinux") ))
		return false;

	if (!!memcmp(char_buf, "selinux", sizeof("selinux")))
		return false;

	// candidate found!
	pr_info("%s: candidate selinux_ops at 0x%lx\n", __func__, (long)addr);

	// check ptr density	
	if (!is_selinux_ops_valid(addr))
		return false;

	if (!candidate->cred_free)
		return false;

#ifdef CONFIG_KALLSYMS // not always available, can also fail, but it wont hurt to try.
	uintptr_t ksym_ptr = (uintptr_t)kallsyms_lookup_name("selinux_cred_free");
	if (unlikely(ksym_ptr != (uintptr_t)candidate->cred_free))
		goto test_fn;

	pr_info("%s: selinux_cred_free found via ksym_lookup: 0x%lx probe_result: 0x%lx \n", __func__, (long)ksym_ptr, (long)candidate->cred_free);
	return true;

test_fn:
#endif

	pr_info("%s: candidate selinux_cred_free at 0x%lx\n", __func__, (long)candidate->cred_free);
	return verify_selinux_cred_free((void *)candidate->cred_free);
}

/** 
 * we do this in blocks of sequential 10k pointers.
 * 10k pointers up, 10k pointers down
 * this is predictable, more cache friendly, no trashing.
 *
 * one up, one down oscillating scan isn't as friendly to teh cahce.
 * once ptrdiff of up vs down is larger than L1, it will be trashy.
 *
 */
static noinline void *hunt_for_selinux_ops(void *heuristic_ptr)
{
	uintptr_t anchor = (uintptr_t)heuristic_ptr;
	uintptr_t curr;
	unsigned long iter_count = 0;
	unsigned long max_index = 10000; // max number of pointers to test, one way
	unsigned long i = 0;

	uintptr_t start = anchor - max_index * sizeof(void *);
	uintptr_t end = anchor + max_index * sizeof(void *);
	pr_info("%s: scan range: 0x%lx - 0x%lx anchor: 0x%lx\n", __func__, (long)start, (long)end, (long)anchor);

scan_up:
	if (i >= max_index) {
		i = 1;
		goto scan_down;
	}

	curr = anchor + (i * sizeof(void *));
	i++;
	iter_count++;

	if (check_candidate(curr))
		goto found;

	goto scan_up;

scan_down:
	if (i >= max_index)
		goto not_found;

	curr = anchor - (i * sizeof(void *));
	i++;
	iter_count++;

	if (check_candidate(curr))
		goto found;

	goto scan_down;

found:
	pr_info("%s: found selinux_ops at 0x%lx iter_count: %lu \n", __func__, curr, iter_count);
	return (void *)curr;

not_found:
	pr_info("%s: selinux_ops not found in range! iter_count: %lu \n", __func__, iter_count);
	return NULL;
}

static inline void set_selinux_ops()
{
	extern int selinux_enabled;
	extern struct security_class_mapping secclass_map[];
	extern struct list_head crypto_alg_list;
	extern unsigned int avc_cache_threshold;
	
	struct security_operations *ops = NULL;

// if user exports selinux_ops, we just go for it!
#ifdef KSU_HAS_EXPORTED_SELINUX_OPS
	extern struct security_operations selinux_ops;
	if (!ops)
		ops = (struct security_operations *)&selinux_ops;
#endif

// not always available, can also fail, but it wont hurt to try.
#ifdef CONFIG_KALLSYMS
	if (!ops)
		ops = (struct security_operations *)kallsyms_lookup_name("selinux_ops");
#endif

#ifdef CONFIG_KEYS
	extern struct key_user root_key_user;
	if (!ops)
		ops = (struct security_operations *)hunt_for_selinux_ops((void *)&root_key_user);
#endif

	if (!ops)
		ops = (struct security_operations *)hunt_for_selinux_ops((void *)&avc_cache_threshold);

	if (!ops)
		ops = (struct security_operations *)hunt_for_selinux_ops((void *)&crypto_alg_list);

	if (!ops)
		ops = (struct security_operations *)hunt_for_selinux_ops((void *)&selinux_enabled);

	if (!ops)
		ops = (struct security_operations *)hunt_for_selinux_ops((void *)&secclass_map);

	if (!ops)
		return;

	selinux_ops_addr = (uintptr_t)ops;	
}

// stop_machine
static int ksu_unregister_lsm_hook(void *data)
{
	struct security_operations *ops = (struct security_operations *)selinux_ops_addr;

	if (orig_file_permission) {
		pr_info("%s: restoring file_permission 0x%lx -> 0x%lx\n", __func__, (long)ops->file_permission, (long)orig_file_permission);
		ops->file_permission = orig_file_permission;
	}
	
	return 0;
}

static int ksu_lsm_hook_restore(void *data)
{
	struct security_operations *ops = (struct security_operations *)selinux_ops_addr;
	if (!ops)
		return 0;

	if (!!strcmp((char *)ops, "selinux"))
		return 0;

loop_start:

	msleep(1000);

	if (*(volatile bool *)&ksu_vfs_read_hook)
		goto loop_start;

	pr_info("%s: selinux_ops: 0x%lx .name = %s\n", __func__, (long)ops, (const char *)ops );

	stop_machine(ksu_unregister_lsm_hook, NULL, NULL);

	return 0;
}

// stop_machine
static int ksu_register_lsm_hook(void *data)
{
	struct security_operations *ops = (struct security_operations *)selinux_ops_addr;

	orig_bprm_set_creds = ops->bprm_set_creds;
	ops->bprm_set_creds = hook_bprm_set_creds;

	orig_inode_rename = ops->inode_rename;
	ops->inode_rename = hook_inode_rename;

	orig_task_fix_setuid = ops->task_fix_setuid;
	ops->task_fix_setuid = hook_task_fix_setuid;

#ifdef CONFIG_KSU_FEATURE_SULOG
	orig_bprm_check_security = ops->bprm_check_security;
	ops->bprm_check_security = hook_bprm_check_security;
#endif

#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE)
	orig_file_permission = ops->file_permission;
	ops->file_permission = hook_file_permission;
#endif

	return 0;
}

static void ksu_lsm_hook_init(void)
{
	set_selinux_ops();

	struct security_operations *ops = (struct security_operations *)selinux_ops_addr;
	if (!ops)
		return;

	if (!!strcmp((char *)ops, "selinux"))
		return;

	pr_info("%s: selinux_ops: 0x%lx .name = %s\n", __func__, (long)ops, (const char *)ops );

	stop_machine(ksu_register_lsm_hook, NULL, NULL);
	
	kthread_run(ksu_lsm_hook_restore, NULL, "unhook");
	return;
}

#endif // < 4.2

#else /* ! CONFIG_KSU_LSM_SECURITY_HOOKS */
// TEMP hooks, remove this in a month.
int ksu_handle_setuid(struct cred *new, const struct cred *old)
{
	ksu_handle_setresuid_cred(new, old);
	return 0;
}
int ksu_handle_rename(struct dentry *old_dentry, struct dentry *new_dentry)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return 0;
}
static inline void ksu_lsm_hook_init(void) { } // nothing, no-op
#endif // CONFIG_KSU_LSM_SECURITY_HOOKS


static int override_security_head(void *head, const void *new_head, size_t len)
{
	unsigned long base = (unsigned long)head & PAGE_MASK;
	unsigned long offset = offset_in_page(head);

	// this is impossible for our case because the page alignment
	// but be careful for other cases!
	BUG_ON(offset + len > PAGE_SIZE);
	struct page *page = phys_to_page(__pa(base));
	if (!page) {
		return -EFAULT;
	}

	void *addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!addr) {
		return -ENOMEM;
	}
	local_irq_disable();
	memcpy(addr + offset, new_head, len);
	local_irq_enable();
	vunmap(addr);
	return 0;
}

static void free_security_hook_list(struct hlist_head *head)
{
	struct hlist_node *temp;
	struct security_hook_list *entry;

	if (!head)
		return;

	hlist_for_each_entry_safe (entry, temp, head, list) {
		hlist_del(&entry->list);
		kfree(entry);
	}

	kfree(head);
}

struct hlist_head *copy_security_hlist(struct hlist_head *orig)
{
	struct hlist_head *new_head = kmalloc(sizeof(*new_head), GFP_KERNEL);
	if (!new_head)
		return NULL;

	INIT_HLIST_HEAD(new_head);

	struct security_hook_list *entry;
	struct security_hook_list *new_entry;

	hlist_for_each_entry (entry, orig, list) {
		new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
		if (!new_entry) {
			free_security_hook_list(new_head);
			return NULL;
		}

		*new_entry = *entry;

		hlist_add_tail_rcu(&new_entry->list, new_head);
	}

	return new_head;
}

#define LSM_SEARCH_MAX 180 // This should be enough to iterate
static void *find_head_addr(void *security_ptr, int *index)
{
	if (!security_ptr)
		return NULL;

	struct hlist_head *head_start = (struct hlist_head *)&security_hook_heads;

	int i;
	for (i = 0; i < LSM_SEARCH_MAX; i++) {
		struct hlist_head *head = head_start + i;
		struct security_hook_list *pos;
		hlist_for_each_entry (pos, head, list) {
			if (pos->hook.capget == security_ptr) {
				if (index) {
					*index = i;
				}
				return head;
			}
		}
	}

	return NULL;
}

#define GET_SYMBOL_ADDR(sym)					\
({								\
	void *addr = kallsyms_lookup_name(#sym ".cfi_jt");	\
	if (!addr)						\
		addr = kallsyms_lookup_name(#sym);		\
	addr;							\
})

#define KSU_LSM_HOOK_HACK_INIT(head_ptr, name, ksu_func)					\
do {												\
	static struct security_hook_list hook = {  .hook = { .name = ksu_func } };		\
	hook.head = head_ptr;									\
	hook.lsm = "ksu";									\
	struct hlist_head *new_head = copy_security_hlist(hook.head);				\
	if (!new_head) {									\
		pr_info("Failed to copy security list: %s\n", #name);				\
		break;										\
	}											\
	hlist_add_tail_rcu(&hook.list, new_head);						\
	if (override_security_head(hook.head, new_head, sizeof(*new_head))) {			\
		free_security_hook_list(new_head);						\
		pr_info("Failed to hack lsm for: %s\n", #name);					\
	} else	{										\
		pr_info("LSM hack done for: %s\n", #name);					\
	}											\
} while (0)

void ksu_lsm_hack(void)
{
	void *cap_setuid = GET_SYMBOL_ADDR(cap_task_fix_setuid);
	void *setuid_head = find_head_addr(cap_setuid, NULL);
	if (!setuid_head)
		return;

	if (setuid_head == &security_hook_heads.task_fix_setuid) {
		pr_info("setuid address: 0x%lx \n", (uintptr_t)setuid_head);
		KSU_LSM_HOOK_HACK_INIT(setuid_head, task_fix_setuid, ksu_task_fix_setuid);
	} else
		pr_info("setuid's address has shifted!\n");

	void *inode_rename = GET_SYMBOL_ADDR(selinux_inode_rename);
	void *inode_rename_head = find_head_addr(inode_rename, NULL);
	if (!inode_rename)
		return;

	if (inode_rename_head == &security_hook_heads.inode_rename) {
		pr_info("inode_rename address: 0x%lx \n", (uintptr_t)inode_rename_head);
		KSU_LSM_HOOK_HACK_INIT(inode_rename_head, inode_rename, ksu_inode_rename);
	} else
		pr_info("inode_rename's address has shifted!\n");

}

void __init ksu_core_init(void)
{
	ksu_lsm_hack();
	ksu_lsm_hook_init();
}
