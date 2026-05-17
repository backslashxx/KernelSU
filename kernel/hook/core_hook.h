#ifndef __KSU_H_CORE_HOOK
#define __KSU_H_CORE_HOOK

#ifdef CONFIG_KSU_LSM_SECURITY_HOOKS

/*
 * LSMs are actually unhookable, however, it requires CONFIG_SECURITY_SELINUX_DISABLE
 * ref: security_delete_hooks(), lsm_hooks.h
 *
 * when that is disabled, we get an issue as we will be writing to ro memory.
 * "Unable to handle kernel write to read-only memory at virtual address fffffffffffuckyou"
 *
 * however we can just do vmap-as-rw trick to create another reality where this memory segment is rw.
 *
 */

#if defined(KSU_COMPAT_SECURITY_DELETE_HOOKS_HLIST)
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

	WRITE_ONCE(*(struct hlist_node **)target_slot, next);

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

	// use our pprev as the new pprev for the next in chain
	WRITE_ONCE(*(struct hlist_node ***)target_slot, pprev);

	preempt_enable();

	vunmap(writable_addr);

	smp_mb();
}

#else // ! KSU_COMPAT_SECURITY_DELETE_HOOKS_HLIST 

static void ksu_list_del_safe(struct list_head *entry)
{
	struct list_head *next = entry->next;
	struct list_head *prev = entry->prev;

	// on a linked list we have to patch both the before us and the next to us
	if (!prev || !next)
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

	WRITE_ONCE(*target, next);

	preempt_enable();
	vunmap(w_page);

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

	WRITE_ONCE(*target, prev);

	preempt_enable();
	vunmap(w_page);

	smp_mb();

}

#endif // ! KSU_COMPAT_SECURITY_DELETE_HOOKS_HLIST

#endif // CONFIG_KSU_LSM_SECURITY_HOOKS

#endif // __KSU_H_CORE_HOOK
