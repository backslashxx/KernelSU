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

static void *hunt_entry_text_code_cave(void)
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
	if (highest > 32)
		return (void *)best_addr_end;

	return nullptr;
}

/**
 *  printf '%s\n' '.text' '.global tp' 'tp:' 'ldr x16, #8' 'br x16' '.quad 0x12345678FFFFFFFF' | aarch64-linux-gnu-as -o test.o
 *
 * 0:	58000050 	ldr	x16, #8 
 * 4:	d61f0200 	br	x16
 * 8:	ffffffff 	.word	0xffffffff
 * c:	12345678 	.word	0x12345678
 *
 * alternative: printf '%s\n' '.text' '.global tp' 'tp:' 'adrp x16, 0x0' 'add x16, x16, #123' 'br x16' | aarch64-linux-gnu-as -o test.o
 * hiwever encoding/decoding and offset_in_age has to be handled. maybe later.
 */
#if !defined(__aarch64__)
static_assert(1 == 0, "ARM64 only!");
#endif

nodiscard static int generate_trampoline(uint32_t buf[], uint64_t target)
{
	if (!buf || !target)
		return -EINVAL;

	uint32_t ibuf; // test that target is reachable
	if (!!copy_from_kernel_nofault(&ibuf, (void *)target, sizeof(uint32_t)))
		return -EFAULT;

	buf[0] = 0x58000050u;
	buf[1] = 0xd61f0200u;

	// now cut it up
	buf[2] = (uint32_t)(target & 0xFFFFFFFFULL);
	buf[3] = (uint32_t)(target >> 32);

	return 0;
}

static int patch_and_create_landing_pad(uintptr_t target)
{
	if (!target)
		return -EINVAL;

	void *cave_end = hunt_entry_text_code_cave();
	if (!cave_end) {
		pr_info("no sizeable code cave found! \n");
		return -ENXIO;
	}

	uintptr_t trampoline_end  = (uintptr_t)cave_end;
	uintptr_t trampoline_start = trampoline_end - 4 * sizeof(uint32_t);

	uint32_t arr_insn[4] = { 0 };
	void *arr_addr[] = { 
		(void*)(trampoline_start + 0 * sizeof(uint32_t)),
		(void*)(trampoline_start + 1 * sizeof(uint32_t)),
		(void*)(trampoline_start + 2 * sizeof(uint32_t)),
		(void*)(trampoline_start + 3 * sizeof(uint32_t))
	};

	int gen = generate_trampoline(arr_insn, target);
	if (gen) {
		pr_info("generate_trampoline: ret: %d\n", gen);	
		return gen;
	}

	// debug
	pr_info("%s: insn0: 0x%x to 0x%lx\n", __func__, arr_insn[0], (uintptr_t)arr_addr[0]);
	pr_info("%s: insn1: 0x%x to 0x%lx\n", __func__, arr_insn[1], (uintptr_t)arr_addr[1]);
	pr_info("%s: insn2: 0x%x to 0x%lx\n", __func__, arr_insn[2], (uintptr_t)arr_addr[2]);
	pr_info("%s: insn3: 0x%x to 0x%lx\n", __func__, arr_insn[3], (uintptr_t)arr_addr[3]);
	return 0;
}

#endif // __H_ARM64_TINY_TRAMPOLINE
