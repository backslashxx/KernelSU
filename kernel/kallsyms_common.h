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

#ifndef __KSU_H_KALLSYMS_COMMON
#define __KSU_H_KALLSYMS_COMMON

// kallsyms_lookup_name / sprint_symbol hacky AF symbol bruteforce
// WARNING: use only when needed! brittle code!
// it is recommended to offload the whole scanning to a kthread

static uintptr_t kallsyms_hunt_for_name(const char *prefix)
{
	extern char _stext[], _etext[];
	uintptr_t start = (uintptr_t)_stext;
	uintptr_t end = (uintptr_t)_etext;
	uintptr_t iter_count = 0;
	uintptr_t curr;
	uintptr_t dummy_buf;
	char symbol_buf[KSYM_SYMBOL_LEN];

	if (!prefix)
		return NULL;

	might_sleep();

	curr = start;

scan_start:
	iter_count++;

	memset(symbol_buf, 0, sizeof(symbol_buf));

	sprint_symbol(symbol_buf, curr);

	if (!strstarts(symbol_buf, prefix))
		goto step_up;

	// however we should not use cfi_jt for this
	// what we want is the target of that cfi_jt
	if (strstr(symbol_buf, "cfi_jt"))
		goto step_up;

	// TODO: better matching for llvm ('$' thing)
	// GCC LTO is a-ok!

	// cut it with these to make sure its a match
	// .llvm.505034 or .lto_priv.0
	if (symbol_buf[strlen(prefix)] != '.')
		goto step_up;

	pr_info("%s: %s at 0x%lx iter_count: %lu\n", __func__, symbol_buf, (uintptr_t)curr, iter_count);
	return curr;

step_up:
	curr = curr + 4;
	if (curr < end)
		goto scan_start;

	pr_info("%s: %s symbol prefix not found! iter_count: %lu \n", __func__, prefix, iter_count);
	return NULL;
}

static uintptr_t kallsyms_lookup_retry(const char *name)
{
	char namebuf[KSYM_NAME_LEN];
	if (!name)
		return NULL;

	uintptr_t addr = (uintptr_t)kallsyms_lookup_name(name);
	if (addr)
		goto found;

	// quick look for .lto_priv.0
	snprintf(namebuf, sizeof(namebuf), "%s.lto_priv.0", name);
	addr = (uintptr_t)kallsyms_lookup_name(namebuf);
	if (addr)
		goto found;

	return (uintptr_t)kallsyms_hunt_for_name(name);
found:
	pr_info("kallsyms_lookup_name: %s addr: 0x%lx \n", name, addr);
	return addr;
}

#endif // __KSU_H_KALLSYMS_COMMON
