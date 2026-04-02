static int ksu_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			    struct inode *new_inode, struct dentry *new_dentry)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return 0;
}

static int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	// see sys_setresuid
	if (flags == LSM_SETID_RES)
		ksu_handle_setresuid_cred(new, old);

	return 0;
}

static int ksu_bprm_check(struct linux_binprm *bprm)
{
#ifdef CONFIG_KSU_FEATURE_SULOG
	ksu_sulog_emit_bprm((const char *)bprm->filename);
#endif
	return 0;
}

static int ksu_file_permission(struct file *file, int mask)
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static uintptr_t cap_bprm_set_creds_slot __read_mostly = NULL;
extern int cap_bprm_set_creds(struct linux_binprm *bprm);

static __nocfi int ksu_bprm_set_creds(struct linux_binprm *bprm)
{
	if (likely(ksu_boot_completed))
		goto capability_fn;

	if (likely(!is_init(current_cred())))
		goto capability_fn;

	if (!bprm->filename)
		goto capability_fn;

	if (!!strcmp(bprm->filename, "/data/adb/ksud"))
		goto capability_fn;

	pr_info("bprm_set_creds: escape init executing %s with pid: %d\n", bprm->filename, current->pid);
	escape_to_root_forced(); // give this context all permissions

capability_fn:
	return cap_bprm_set_creds(bprm);
}

static struct security_hook_list ksu_hooks_bprm_set_creds[] __ro_after_init = {
	LSM_HOOK_INIT(bprm_set_creds, ksu_bprm_set_creds),
};

static int ksu_restore_bprm_set_creds(void *data)
{
	set_user_nice(current, 19); // low prio

loop_start:
	msleep(5000);
	if (!*(volatile bool *)&ksu_boot_completed)
		goto loop_start;

	msleep(1000);

	// now we write capability back into its slot
	uintptr_t addr = cap_bprm_set_creds_slot;
	uintptr_t base = addr & PAGE_MASK;
	uintptr_t offset = addr & ~PAGE_MASK;

	struct page *page = phys_to_page(__pa(base));
	if (!page)
		return 0;

	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		return 0;

	void **target_slot = (void **)(writable_addr + offset);
				
	preempt_disable();
	local_irq_disable();
					
	WRITE_ONCE(*target_slot, (uintptr_t)cap_bprm_set_creds);
					
	local_irq_enable();
	preempt_enable();

	vunmap(writable_addr);
	smp_mb();
	
	pr_info("ksu_bprm_set_creds: restored cap_bprm_set_creds: *0x%lx = 0x%lx\n", (uintptr_t)addr, *(uintptr_t *)addr);

	return 0;
}
#endif // < 4.14

static struct security_hook_list ksu_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(inode_rename, ksu_inode_rename),
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
#ifdef CONFIG_KSU_FEATURE_SULOG
	LSM_HOOK_INIT(bprm_check_security, ksu_bprm_check),
#endif
};

// vfs_read hook
static struct security_hook_list ksu_hooks_file_permission[] __ro_after_init = {
	LSM_HOOK_INIT(file_permission, ksu_file_permission),
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0) || defined(KSU_COMPAT_SECURITY_ADD_HOOKS_V2)
#define ksu_security_add_hooks security_add_hooks
#else
#define ksu_security_add_hooks(a, b, c) security_add_hooks(a, b)
#endif

/**
 * LSMs are actually unhookable, however, it requires CONFIG_SECURITY_SELINUX_DISABLE
 * ref: security_delete_hooks(), lsm_hooks.h
 *
 * when that is disabled, we get an issue as we will be writing to ro memory.
 * "Unable to handle kernel write to read-only memory at virtual address fffffffffffuckyou"
 *
 * however we can just do vmap-as-rw trick to create another reality where this memory segment is rw.
 *
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) || defined(KSU_COMPAT_SECURITY_DELETE_HOOKS_HLIST)
static void ksu_hlist_del_safe(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;

	if (!pprev)
		return;

	// this is here so we don't get lost
	/**
	 *	original state
	 * n			ptr	*ptr
	 * H	hlist_head	0x1000	0xA000
	 *
	 * A	node->next	0xA000	0xB000
	 *	node->pprev	0xA008	0x1000
	 *
	 * B	node->next	0xB000	0xC000
	 *	node->pprev	0xB008	0xA000
	 *
	 * C	node->next	0xC000	0xFFFF
	 *	node->pprev	0xC008	0xB000
	 *
	 */

	// on hlist, pprev is the address of the 'next' pointer in the previous element
	// so what we do is:
	// 	write the value 0xC000 (next) into address 0xA000 (A->next)
	// 	write the value 0xA000 (pprev) into address 0xC008 (C->pprev)

	/**
	 * 	after this routine
	 *
	 * H	hlist_head	0x1000	0xA000
	 *
	 * A	node->next	0xA000	0xC000  <-- now points to C
	 *	node->pprev	0xA008	0x1000
	 *
	 * B	node->next	0xB000	0xC000  <-- orphaned
	 *	node->pprev	0xB008	0xA000  <-- orphaned
	 *
	 * C	node->next	0xC000	0xFFFF
	 *	node->pprev	0xC008	0xA000  <-- now points to A's next
	 *
	 */

	// NOTE: pprev is **
	uintptr_t addr = (uintptr_t)pprev;
	uintptr_t base = addr & PAGE_MASK;
	uintptr_t offset = addr & ~PAGE_MASK;

	struct page *page = phys_to_page(__pa(base));
	if (!page)
		return;

	// vmap pprev
	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		return;

	uintptr_t target_slot = (uintptr_t)((uintptr_t)writable_addr + offset);

	preempt_disable();
	local_irq_disable();

	WRITE_ONCE(*(struct hlist_node **)target_slot, next);

	local_irq_enable();
	preempt_enable();

	vunmap(writable_addr);

	smp_mb();

	if (!next)
		return;

	// NOTE: pprev is **, taking ref, it becomes ***
	addr = (uintptr_t)&next->pprev;
	base = addr & PAGE_MASK;
	offset = addr & ~PAGE_MASK;

	page = phys_to_page(__pa(base));
	if (!page)
		return;

	writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		return;

	target_slot = (uintptr_t)((uintptr_t)writable_addr + offset);

	preempt_disable();
	local_irq_disable();

	// use our pprev as the new pprev for the next in chain
	WRITE_ONCE(*(struct hlist_node ***)target_slot, pprev);

	local_irq_enable();
	preempt_enable();

	vunmap(writable_addr);

	smp_mb();
}

// see security_delete_hooks
static inline void ksu_security_delete_hooks(struct security_hook_list *hooks, int count)
{
	int i;
	for (i = 0; i < count; i++)
		ksu_hlist_del_safe(&hooks[i].list);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static void ksu_grab_cap_bprm_set_creds_slot()
{
	struct hlist_head *head = ksu_hooks_bprm_set_creds[0].head; 
	struct security_hook_list *pos;
	struct hlist_node *tmp;

	if (!head)
		return;

	hlist_for_each_entry_safe(pos, tmp, head, list) {
		// look for capabilities
		if (pos->hook.bprm_set_creds != cap_bprm_set_creds)
			continue;

		cap_bprm_set_creds_slot = &pos->hook.bprm_set_creds;
		pr_info("ksu_bprm_set_creds: found cap_bprm_set_creds slot at 0x%lx\n", (uintptr_t)cap_bprm_set_creds_slot);
	}
	
	// now that we got the slot, we can unreg ourself
	ksu_security_delete_hooks(ksu_hooks_bprm_set_creds, ARRAY_SIZE(ksu_hooks_bprm_set_creds));
	
	// then we write our fn ptr over on capability slot
	uintptr_t addr = cap_bprm_set_creds_slot;
	uintptr_t base = addr & PAGE_MASK;
	uintptr_t offset = addr & ~PAGE_MASK;

	struct page *page = phys_to_page(__pa(base));
	if (!page)
		return;

	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		return;

	void **target_slot = (void **)((unsigned long)writable_addr + offset);

	preempt_disable();
	local_irq_disable();
					
	FORCE_VOLATILE(*target_slot) = (void *)ksu_bprm_set_creds;
					
	local_irq_enable();
	preempt_enable();

	vunmap(writable_addr);
	smp_mb();

	pr_info("ksu_bprm_set_creds: cap_bprm_set_creds hijacked!\n");

}
#endif

#else // ! KSU_COMPAT_SECURITY_DELETE_HOOKS_HLIST 

static void ksu_list_del_safe(struct list_head *entry)
{
	struct list_head *next = entry->next;
	struct list_head *prev = entry->prev;

	// on a linked list we have to patch both the before us and the next to us
	if (!prev)
		return;

	// smash prev->next, basically we write 'next' into 'prev->next'
	unsigned long addr_p = (unsigned long)&prev->next;
	unsigned long base_p = addr_p & PAGE_MASK;
	unsigned long offset_p = addr_p & ~PAGE_MASK;

	struct page *page_p = phys_to_page(__pa(base_p));
	if (!page_p)
		return;

	void *w_page = vmap(&page_p, 1, VM_MAP, PAGE_KERNEL);
	if (!w_page)
		return;

	struct list_head **target = (void *)((unsigned long)w_page + offset_p);
	
	preempt_disable();
	local_irq_disable();

	WRITE_ONCE(*target, next);

	local_irq_enable();
	preempt_enable();

	vunmap(w_page);
	
	smp_mb();

	if (!next)
		return;

	// smash next->prev, basically we need to write 'prev' into 'next->prev'
	unsigned long addr_n = (unsigned long)&next->prev;
	unsigned long base_n = addr_n & PAGE_MASK;
	unsigned long offset_n = addr_n & ~PAGE_MASK;

	struct page *page_n = phys_to_page(__pa(base_n));
	if (!page_n)
		return;

	w_page = vmap(&page_n, 1, VM_MAP, PAGE_KERNEL);
	if (!w_page)
		return;
	
	target = (void *)((unsigned long)w_page + offset_n);

	preempt_disable();
	local_irq_disable();

	WRITE_ONCE(*target, prev);

	local_irq_enable();
	preempt_enable();

	vunmap(w_page);

	smp_mb();

}

// see security_delete_hooks
static inline void ksu_security_delete_hooks(struct security_hook_list *hooks, int count)
{
	int i;
	for (i = 0; i < count; i++)
		ksu_list_del_safe(&hooks[i].list);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static void ksu_grab_cap_bprm_set_creds_slot()
{
	struct list_head *head = ksu_hooks_bprm_set_creds[0].head;
	struct security_hook_list *pos, *tmp;

	if (!head)
		return;

	if (list_empty(head))
		return;

	list_for_each_entry_safe(pos, tmp, head, list) {
		// look for capabilities
		if (pos->hook.bprm_set_creds != cap_bprm_set_creds)
			continue;

		cap_bprm_set_creds_slot = &pos->hook.bprm_set_creds;
		pr_info("ksu_bprm_set_creds: found cap_bprm_set_creds slot at 0x%lx\n", (uintptr_t)cap_bprm_set_creds_slot);
	}
	
	// now that we got the slot, we can unreg ourself
	ksu_security_delete_hooks(ksu_hooks_bprm_set_creds, ARRAY_SIZE(ksu_hooks_bprm_set_creds));
	
	// then we write our fn ptr over on capability slot
	uintptr_t addr = cap_bprm_set_creds_slot;
	uintptr_t base = addr & PAGE_MASK;
	uintptr_t offset = addr & ~PAGE_MASK;

	struct page *page = phys_to_page(__pa(base));
	if (!page)
		return;

	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		return;

	void **target_slot = (void **)((unsigned long)writable_addr + offset);

	preempt_disable();
	local_irq_disable();
					
	FORCE_VOLATILE(*target_slot) = (void *)ksu_bprm_set_creds;
					
	local_irq_enable();
	preempt_enable();

	vunmap(writable_addr);
	smp_mb();

	pr_info("ksu_bprm_set_creds: cap_bprm_set_creds hijacked!\n");

}
#endif

#endif // KSU_COMPAT_SECURITY_DELETE_HOOKS_HLIST

static int ksu_lsm_hook_restore(void *data)
{
	set_user_nice(current, 19); // low prio

loop_start:
	msleep(1000);
	if (*(volatile bool *)&ksu_vfs_read_hook)
		goto loop_start;

	msleep(1000);

	pr_info("ksu_file_permission: unhook!\n");

	ksu_security_delete_hooks(ksu_hooks_file_permission, ARRAY_SIZE(ksu_hooks_file_permission));

	return 0;
}

static __init void ksu_lsm_hook_init(void)
{
	ksu_security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
	pr_info("core_hook: initialized %d LSMs \n", ARRAY_SIZE(ksu_hooks));

#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE)
	ksu_security_add_hooks(ksu_hooks_file_permission, ARRAY_SIZE(ksu_hooks_file_permission), "ksu_file_permission");
	kthread_run(ksu_lsm_hook_restore, NULL, "kthread");
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	ksu_security_add_hooks(ksu_hooks_bprm_set_creds, ARRAY_SIZE(ksu_hooks_bprm_set_creds), "ksu");
	ksu_grab_cap_bprm_set_creds_slot();
	kthread_run(ksu_restore_bprm_set_creds, NULL, "kthread");
#endif

}

static void __init ksu_core_init(void)
{
	ksu_lsm_hook_init();
}
