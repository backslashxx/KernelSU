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

#ifndef __H_ARM64_TINY_TRAMPOLINE
#define __H_ARM64_TINY_TRAMPOLINE

#include <linux/version.h>
#include <linux/uaccess.h>
#include <asm/insn.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
#include <asm/text-patching.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
#include <asm/patching.h>
#endif

static void hunt_entry_text_code_cave(void)
{
	// look for code cave inside __entry_text_start[], __entry_text_end[];
	uintptr_t entry_text_start_p = (uintptr_t)kallsyms_lookup_name("__entry_text_start");
	uintptr_t entry_text_end_p = (uintptr_t)kallsyms_lookup_name("__entry_text_end");
	if (!entry_text_start_p || !entry_text_end_p)
		return nullptr;

	// d503201f
	uintptr_t start = entry_text_start_p;
	uintptr_t end = entry_text_end_p;
	uintptr_t curr = start;

	uint32_t raw_insn;
	uint32_t cnt = 0; 

	uintptr_t best_addr_end = 0;
	uintptr_t addr_end = 0;
	uint32_t highest = 0;

start_scan:
	if (curr >= end)
		goto bail;


	if (!!copy_from_kernel_nofault(&raw_insn, (void *)curr, sizeof(uint32_t)))
		goto reset_cnt;

	if (raw_insn != 0xd503201fU) // aarch64 nop
		goto reset_cnt;

	cnt++;
	addr_end = curr;
	goto increment;

reset_cnt:
	if (cnt > highest) {
		highest = cnt;
		best_addr_end = addr_end;
	}

	cnt = 0;
increment:
	curr = curr + 4;
	goto start_scan;
bail:;
	char cbuf[KSYM_SYMBOL_LEN];
	sprint_symbol(cbuf, best_addr_end);
	pr_info("%s: highest: %u end_addr: 0x%lx owned by: %s\n", __func__, highest, best_addr_end, cbuf);
	return (void *)best_addr_end;
}


#endif // __H_ARM64_TINY_TRAMPOLINE
