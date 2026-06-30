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

#ifndef __KSU_H_SLOW_AVC_AUDIT_HOOK
#define __KSU_H_SLOW_AVC_AUDIT_HOOK

static bool ksu_selinux_hide_enabled;
static u32 ksu_sid;
static u32 priv_app_sid;

static __always_inline void ksu_slow_avc_audit_inline(u32 *tsid)
{
	if (unlikely(!ksu_selinux_hide_enabled))
		return;

	if (*tsid != ksu_sid)
		return;

	pr_info("selinux_hide: slow_avc_audit: replace tsid: %u with priv_app_sid: %u\n", *tsid, priv_app_sid);
	*tsid = priv_app_sid;
}

#if defined(CONFIG_AUDIT) && defined(CONFIG_ARM64) && defined(CONFIG_KALLSYMS) && !defined(MODULE)

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(KSU_COMPAT_HAS_SELINUX_STATE)
struct selinux_state { uintptr_t dummy; };
#endif

__maybe_unused void ksu_slow_avc_audit(u32 *tsid) { return; } // dummy

static void *slow_avc_audit_fn __read_mostly = NULL;

#define SLOW_AVC_AUDIT_TYPE_1 u32, u32, u16, u32, u32, u32, int, struct common_audit_data *
static int __nocfi ksu_hook_slow_avc_audit_1(u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a)
{
	int (*orig_fn)(SLOW_AVC_AUDIT_TYPE_1) = slow_avc_audit_fn;

	ksu_slow_avc_audit_inline(&tsid);
	return orig_fn(ssid, tsid, tclass, requested, audited, denied, result, a);
}

#define SLOW_AVC_AUDIT_TYPE_2 struct selinux_state *, u32, u32, u16, u32, u32, u32, int, struct common_audit_data *
static int __nocfi ksu_hook_slow_avc_audit_2(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a)
{
	int (*orig_fn)(SLOW_AVC_AUDIT_TYPE_2) = slow_avc_audit_fn;

	ksu_slow_avc_audit_inline(&tsid);
	return orig_fn(state, ssid, tsid, tclass, requested, audited, denied, result, a);
}

#define SLOW_AVC_AUDIT_TYPE_3 struct selinux_state *, u32, u32, u16, u32, u32, u32, int, struct common_audit_data *, unsigned int
static int __nocfi ksu_hook_slow_avc_audit_3(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a, unsigned int flags)
{
	int (*orig_fn)(SLOW_AVC_AUDIT_TYPE_3) = slow_avc_audit_fn;

	ksu_slow_avc_audit_inline(&tsid);
	return orig_fn(state, ssid, tsid, tclass, requested, audited, denied, result, a, flags);
}

#define SLOW_AVC_AUDIT_TYPE_4 u32, u32, u16, u32, u32, u32, int, struct common_audit_data *, unsigned int
static int __nocfi ksu_hook_slow_avc_audit_4(u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a, unsigned int flags)
{
	int (*orig_fn)(SLOW_AVC_AUDIT_TYPE_4) = slow_avc_audit_fn;

	ksu_slow_avc_audit_inline(&tsid);
	return orig_fn(ssid, tsid, tclass, requested, audited, denied, result, a, flags);
}

#define OVERLOAD_SLOW_AVC_AUDIT(fn) _Generic					\
((fn),										\
	int (*)(SLOW_AVC_AUDIT_TYPE_1): (void *)ksu_hook_slow_avc_audit_1, 	\
	int (*)(SLOW_AVC_AUDIT_TYPE_2): (void *)ksu_hook_slow_avc_audit_2, 	\
	int (*)(SLOW_AVC_AUDIT_TYPE_3): (void *)ksu_hook_slow_avc_audit_3, 	\
	int (*)(SLOW_AVC_AUDIT_TYPE_4): (void *)ksu_hook_slow_avc_audit_4	\
)

static void ksu_init_slow_avc_audit_hook(void)
{
	int ret;
	*(void **)&slow_avc_audit_fn = kallsyms_lookup_retry("slow_avc_audit");

	if (!slow_avc_audit_fn)
		return;

	// now select the type we have
	typeof(slow_avc_audit) *hook_ptr = OVERLOAD_SLOW_AVC_AUDIT(slow_avc_audit);

//	ret = arm64_bl_patch_everything((uintptr_t)slow_avc_audit_fn, (uintptr_t)hook_ptr);
//	pr_info("avc_spoof: hook slow_avc_audit ret: %d\n", ret);

//	ret = arm64_bl_patch(kallsyms_lookup_retry("audit_inode_permission"), 64 * sizeof(uint32_t), kallsyms_lookup_retry("slow_avc_audit"), (uintptr_t)hook_ptr);
//	pr_info("avc_spoof: hook on slow_avc_audit on audit_inode_permission ret: %d\n", ret);

//	ret = arm64_bl_patch(kallsyms_lookup_retry("avc_has_extended_perms"), 384 * sizeof(uint32_t), (uintptr_t)slow_avc_audit_fn, (uintptr_t)hook_ptr);
//	pr_info("avc_spoof: hook on slow_avc_audit on avc_has_extended_perms ret: %d\n", ret);

//	ret = arm64_bl_patch(kallsyms_lookup_retry("avc_has_perm_flags"), 384 * sizeof(uint32_t), (uintptr_t)slow_avc_audit_fn, (uintptr_t)hook_ptr);
//	pr_info("avc_spoof: hook on slow_avc_audit on avc_has_perm_flags ret: %d\n", ret);

	ret = arm64_bl_patch(kallsyms_lookup_retry("avc_has_perm"), 384 * sizeof(uint32_t), (uintptr_t)slow_avc_audit_fn, (uintptr_t)hook_ptr);
	pr_info("avc_spoof: hook on slow_avc_audit on avc_has_perm ret: %d\n", ret);



}

#undef SLOW_AVC_AUDIT_TYPE_4
#undef SLOW_AVC_AUDIT_TYPE_3
#undef SLOW_AVC_AUDIT_TYPE_2
#undef SLOW_AVC_AUDIT_TYPE_1
#undef OVERLOAD_SLOW_AVC_AUDIT

#elif defined(CONFIG_KPROBES)
__maybe_unused void ksu_slow_avc_audit(u32 *tsid) { return; } // dummy

static struct kprobe *slow_avc_audit_kp;
static int slow_avc_audit_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) || defined(KSU_COMPAT_HAS_SELINUX_STATE))
	u32 *tsid = (u32 *)&PT_REGS_PARM3(regs);
#else
	u32 *tsid = (u32 *)&PT_REGS_PARM2(regs);
#endif
	ksu_slow_avc_audit_inline(tsid);

	return 0;
}

static void ksu_init_slow_avc_audit_hook(void) 
{
	slow_avc_audit_kp = init_kprobe("slow_avc_audit", slow_avc_audit_pre_handler);
}

#else /* ! CONFIG_KPROBES */

void ksu_slow_avc_audit(u32 *tsid)
{
	ksu_slow_avc_audit_inline(tsid);
}
#define ksu_init_slow_avc_audit_hook() do { } while (0)

#endif

#endif // __KSU_H_SLOW_AVC_AUDIT_HOOK
