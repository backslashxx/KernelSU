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

// TODO

static noinline uintptr_t ksu_extend_module_blacklist()
{
	return 0x0;
}


static noinline uintptr_t ksu_read_module_blacklist()
{
	char **module_blacklist_pptr = kallsyms_lookup_name("module_blacklist");
	if (!module_blacklist_pptr)
		return 0x0;

	char *module_blacklist = *module_blacklist_pptr;
	pr_info("module_blackist: 0x%lx with %s\n", (uintptr_t)module_blacklist, module_blacklist);
	
	return module_blacklist_pptr;
}

#endif // __KSU_H_MODULE_BLACKLIST
