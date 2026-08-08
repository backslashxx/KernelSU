// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 \xx
 *
 * This file is a downstream extension and NOT affiliated, endorsed by,
 * or maintained by the official KernelSU developers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef __KSU_H_MODULE_BLACKLIST
#define __KSU_H_MODULE_BLACKLIST

// split with ,
#define MODULES_TO_BLOCK "ksu,kernelsu"

static int ksu_prepare_new_blacklist(uintptr_t blacklist_pptr)
{

	const char *modules = MODULES_TO_BLOCK;
	size_t old_len = strlen(*(char **)blacklist_pptr);
	size_t new_len = old_len + strlen(modules) + 2; // + 2 for extra , and \0
	char *new_blacklist = kzalloc(new_len, GFP_KERNEL);
	if (!new_blacklist)
		return -ENOMEM;

	memcpy(new_blacklist, *(char **)blacklist_pptr, old_len);
	new_blacklist[old_len] = ',';
	memcpy(new_blacklist + old_len + 1, modules, strlen(modules));

	uintptr_t addr = (uintptr_t)blacklist_pptr;
	uintptr_t base = addr & PAGE_MASK;
	uintptr_t offset = addr & ~PAGE_MASK;

	struct page *page = phys_to_page(__pa(base));
	if (!page)
		return -EFAULT;

	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		return -ENOMEM;

	void **target_slot = (void **)((unsigned long)writable_addr + offset);

	WRITE_ONCE(*target_slot, new_blacklist);

	vunmap(writable_addr);
	smp_mb();

	return 0x0;
}

static uintptr_t ksu_read_module_blacklist()
{
	char **module_blacklist_pptr = kallsyms_lookup_name("module_blacklist");
	if (!module_blacklist_pptr)
		return 0x0;

	char *module_blacklist = *module_blacklist_pptr;
	pr_info("module_blackist: 0x%lx with %s\n", (uintptr_t)module_blacklist, module_blacklist);
	
	return module_blacklist_pptr;
}

static noinline void ksu_extend_module_blacklist()
{
	uintptr_t blacklist_pptr = ksu_read_module_blacklist();
	if (!blacklist_pptr)
		return;

	ksu_prepare_new_blacklist(blacklist_pptr);
	
	pr_info("module_blackist: 0x%lx extended with %s\n", (uintptr_t)*(void **)blacklist_pptr, *(char **)blacklist_pptr);
	return;
}


#endif // __KSU_H_MODULE_BLACKLIST
