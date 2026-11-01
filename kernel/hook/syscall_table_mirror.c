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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0) && defined(CONFIG_KALLSYMS) && defined(CONFIG_ARM64)

#define sct_slots 512

static uintptr_t sys_call_table_mirror[sct_slots] __aligned(4096);
#if defined(CONFIG_COMPAT)
static uintptr_t compat_sys_call_table_mirror[sct_slots] __aligned(4096);
#endif

static int bruteforce_sct_adrp(uintptr_t *target_table, uintptr_t insn_addr_start, ptrdiff_t scan_depth, uintptr_t *new_table)
{
	uintptr_t insn_p = insn_addr_start;
	uintptr_t insn_end = insn_addr_start + scan_depth;
	uint32_t raw_insn = 0;

scan:
	if (insn_p >= insn_end)
		goto bail;

	if (copy_from_kernel_nofault((void *)&raw_insn, (void *)insn_p, sizeof(uint32_t)))
		goto increment;

	// aarch64_insn_is_##abbr, arch/arm64/include/asm/insn.h
	if (!aarch64_insn_is_adrp(raw_insn))
		goto increment;

	pr_info("0x%lx insn is adrp! .inst 0x%lx \n", insn_p, raw_insn);

	uintptr_t pc_pg = insn_p & ~0xFFFUL; // target, aligned to 4096
	uintptr_t tgt = pc_pg + (long)aarch64_insn_adrp_get_offset(raw_insn);

	pr_info("tgt: 0x%lx target_table: 0x%lx\n", tgt, *target_table);
	if (tgt != *target_table)
		goto increment;

	// max distance is 4GB
	int64_t offset = (int64_t)new_table - (int64_t)pc_pg;
	if (offset < -(1LL << 32) || offset >= (1LL << 32))
		return -ERANGE;
	
	pr_info("tgt 0x%lx to new_table: 0x%lx in range! delta: %ld bytes\n", tgt, (uintptr_t)new_table, offset);

	uint32_t new_insn = aarch64_insn_adrp_set_offset(raw_insn, (int32_t)offset);

	pr_info("new_insn: .inst 0x%lx \n", new_insn);

	void *arr_addr[] = { (void *)insn_p };
	uint32_t arr_insn[] = { new_insn };
	
	int res = aarch64_insn_patch_text(arr_addr, arr_insn, 1);
	pr_info("%s: patched insn! ret: %d\n", __func__, res);

	patch_ptr_slot_kick_cpu((void **)target_table, (void *)new_table);

// debug verify
//	copy_from_kernel_nofault((void *)&raw_insn, (void *)insn_p, sizeof(uint32_t));
//	pr_info("verify: .inst 0x%lx \n", raw_insn);
	return 0;

increment:
	insn_p = insn_p + sizeof(uint32_t);
	goto scan;

bail:
	pr_info("%s: insn not found!\n", __func__);
	return -ENOENT;	
}

static int do_mirror_syscall_table(const char *native_sym, const char *compat_sym, ptrdiff_t scan_depth)
{
	if (!!copy_from_kernel_nofault((void *)sys_call_table_mirror, native_sct, 4096))
		return -EFAULT;

	uintptr_t target = kallsyms_lookup_name(native_sym);
	if (!target)
		return -ENOENT;

	pr_info("target: %s @ 0x%lx\n", native_sym, target);
	int ret = bruteforce_sct_adrp((uintptr_t *)&native_sct, target, scan_depth, (uintptr_t *)&sys_call_table_mirror);
	if (ret)
		return ret;

	pr_info("%s: sys_call_table mirrored! adrp insn patched!\n", __func__);

#if defined(CONFIG_COMPAT)
	if (!!copy_from_kernel_nofault((void *)compat_sys_call_table_mirror, compat_sct, 4096))
		return -EFAULT;

	target = kallsyms_lookup_name(compat_sym);
	if (!target)
		return -ENOENT;

	pr_info("target: %s @ 0x%lx\n", compat_sym, target);
	ret = bruteforce_sct_adrp((uintptr_t *)&compat_sct, target, scan_depth, (uintptr_t *)&compat_sys_call_table_mirror);
	if (ret)
		return ret;

	pr_info("%s: compat_sys_call_table mirrored! adrp insn patched!\n", __func__);
#endif
	return 0;
}

static void try_mirror_syscall_table(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
	int ret = do_mirror_syscall_table("do_el0_svc", "do_el0_svc_compat", 64 * 4);
	if (!ret)
		return;

	ret = do_mirror_syscall_table("el0_svc_handler", "el0_svc_compat_handler", 64 * 4);
	if (!ret)
		return;

	// for heavily inlined shit
	do_mirror_syscall_table("el0_svc", "el0_svc_compat", 256 * 4);
#else
	do_mirror_syscall_table("el0_svc", "el0_svc_compat", 16 * 4);
#endif
}

#else 

#define try_mirror_syscall_table()	do { } while(0)
#endif


