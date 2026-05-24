#ifndef __KSU_H_ARM64_BL_PATCH
#define __KSU_H_ARM64_BL_PATCH

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)

#include <asm/insn.h>

/**
 * arm64_bl_patch(): hunt and patch first bl insn found with target
 *
 * @target_callsite: callsite on where to start scanning for (ptr / fn_ptr)
 * @target_width: how far to scan for (bytes / ptrdiff)
 * @symbol_addr: symbol being called to look for at the site (fn_ptr)
 * @hook_addr: symbol to redirect "bl symbol_addr" to (fn_ptr)
 *
 * CONTEXT:
 * - do NOT call inside atomic context! (stop_machine)
 * - safe to run early or within kernel threads.
 *
 * NOTES:
 * - both symbol_addr and hook_addr must be inside +/-128MB ptrdiff to callsite!
 * - this is unchecked!
 *
 * 'Can' bypass kCFI and PAC limitations by patching static branch-with-link insn directly.
 * returns 0 on successful branch patching, 1 if callsite isn't found.
 */
static int arm64_bl_patch(uintptr_t target_callsite, ptrdiff_t target_width, uintptr_t symbol_addr, uintptr_t hook_addr)
{
	if (!target_callsite || !symbol_addr) {
		pr_info("%s: no callsite or symbol addr specified!\n", __func__);
		return 1;
	}

	might_sleep();

	uintptr_t start_addr = (uintptr_t)target_callsite;
	uintptr_t end_addr = start_addr + target_width;
	uintptr_t curr_addr = start_addr;
	uint32_t raw_instruction; // arm64 wordsize

start_scan:
	if (curr_addr >= end_addr)
		goto bail;

	if (copy_from_kernel_nofault(&raw_instruction, (void *)curr_addr, sizeof(uint32_t)))
		goto step_up;

#if 0
	// bl
	if ((raw_instruction & 0xFC000000) != 0x94000000)
		goto step_up;

	// 26-bit signed relative jump offset
	// FC, D, E, F, so 3
	int32_t imm26 = raw_instruction & 0x03FFFFFF;

	// in case of backward jumps
	if (imm26 & 0x02000000)
		imm26 |= 0xFC000000;

	long byte_delta = (long)imm26 * 4;
	uintptr_t calculated_destination = curr_addr + byte_delta;
#endif

	// aarch64_insn_is_##abbr
	if (!aarch64_insn_is_bl(raw_instruction))
		goto step_up;

	// signed
	long offset = aarch64_get_branch_offset(raw_instruction);
	uintptr_t calculated_destination = curr_addr + offset;

	if (calculated_destination != symbol_addr)
		goto step_up;

	pr_info("%s: found call site at 0x%lx\n", __func__, curr_addr);

	u32 insn = aarch64_insn_gen_branch_imm(curr_addr, hook_addr, AARCH64_INSN_BRANCH_LINK);
	void *arr_addr[] = { (void*)curr_addr };
	uint32_t arr_insn[] = { insn };

	int res = aarch64_insn_patch_text(arr_addr, arr_insn, 1);
	pr_info("%s: patched callsite: 0x%lx ret: %d\n", __func__, curr_addr, res);

	return 0;

step_up:
	curr_addr = curr_addr + sizeof(uint32_t);
	goto start_scan;

bail:
	pr_info("%s: callsite scan done!\n", __func__);
	return 1;
}

#endif // 6.8

#endif // __KSU_H_ARM64_BL_PATCH
