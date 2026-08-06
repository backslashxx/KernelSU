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
#pragma once
#ifndef __KSU_H_SLOW_AVC_AUDIT_HOOK
#define __KSU_H_SLOW_AVC_AUDIT_HOOK

#include <linux/kallsyms.h>
#include "avc.h"

static bool ksu_avc_spoof_enabled;
static u32 ksu_sid __read_mostly = 0;
static u32 priv_app_sid __read_mostly = 0;

static inline int ksu_selinux_get_sids()
{
	int err = security_secctx_to_secid("u:r:priv_app:s0:c512,c768", strlen("u:r:priv_app:s0:c512,c768"), &priv_app_sid);
	if (!err)
		pr_info("selinux_hide: priv_app_sid: %u\n", priv_app_sid);

	err = security_secctx_to_secid("u:r:ksu:s0", strlen("u:r:ksu:s0"), &ksu_sid);
	if (err)
		pr_info("selinux_hide: ksu_sid: %u\n", ksu_sid);

	if (!priv_app_sid || !ksu_sid)
		return -1;

	return 0;
}

static __always_inline void ksu_slow_avc_audit_inline(u32 *tsid)
{
	if (unlikely(!ksu_avc_spoof_enabled))
		return;

	// won't happen. this is unreachable if so
	//if (unlikely(!priv_app_sid))
	//	return;

	if (*tsid != ksu_sid)
		return;

	pr_info("selinux_hide: slow_avc_audit: replace tsid: %u with priv_app_sid: %u\n", *tsid, priv_app_sid);
	*tsid = priv_app_sid;
}

#if defined(CONFIG_ARM64)

#ifndef __overloadable
#define __overloadable __attribute__((overloadable))
#endif

struct selinux_state;
static void *slow_avc_audit_fn __read_mostly = NULL;

static int __nocfi __overloadable ksu_slow_avc_audit_handler(u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a)
{
	int (*orig_fn)(u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a) = slow_avc_audit_fn;
	ksu_slow_avc_audit_inline(&tsid);
	return orig_fn(ssid, tsid, tclass, requested, audited, denied, result, a);
}

static int __nocfi __overloadable ksu_slow_avc_audit_handler(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a)
{
	int (*orig_fn)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a) = slow_avc_audit_fn;
	ksu_slow_avc_audit_inline(&tsid);
	return orig_fn(state, ssid, tsid, tclass, requested, audited, denied, result, a);
}

static int __nocfi __overloadable ksu_slow_avc_audit_handler(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a, unsigned int flags)
{
	int (*orig_fn)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a, unsigned int flags) = slow_avc_audit_fn;
	ksu_slow_avc_audit_inline(&tsid);
	return orig_fn(state, ssid, tsid, tclass, requested, audited, denied, result, a, flags);
}

static int __nocfi __overloadable ksu_slow_avc_audit_handler(u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a, unsigned int flags)
{
	int (*orig_fn)(u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a, unsigned int flags) = slow_avc_audit_fn;
	ksu_slow_avc_audit_inline(&tsid);
	return orig_fn(ssid, tsid, tclass, requested, audited, denied, result, a, flags);
}

// now choose what we have
static typeof(slow_avc_audit) *ksu_slow_avc_audit_hook __read_mostly = ksu_slow_avc_audit_handler;

static void ksu_init_slow_avc_audit_hook(void)
{
	int ret = ksu_selinux_get_sids();
	if (ret) {
		pr_info("selinux_hide: sid grab fail?\n");
		goto bail;
	}

	*(uintptr_t *)&slow_avc_audit_fn = kallsyms_lookup_name("slow_avc_audit");
	if (!slow_avc_audit_fn)
		goto bail;

//	ret = arm64_bl_patch_everything((uintptr_t)slow_avc_audit_fn, (uintptr_t)ksu_slow_avc_audit_hook);
//	pr_info("avc_spoof: hook slow_avc_audit ret: %d\n", ret);

//	ret = arm64_bl_patch(kallsyms_lookup_name("audit_inode_permission"), 64 * sizeof(uint32_t), kallsyms_lookup_name("slow_avc_audit"), (uintptr_t)ksu_slow_avc_audit_hook);
//	pr_info("avc_spoof: hook on slow_avc_audit on audit_inode_permission ret: %d\n", ret);

	ret = arm64_bl_patch(kallsyms_lookup_name("avc_has_extended_perms"), 384 * sizeof(uint32_t), (uintptr_t)slow_avc_audit_fn, (uintptr_t)ksu_slow_avc_audit_hook);
	pr_info("avc_spoof: hook on slow_avc_audit on avc_has_extended_perms ret: %d\n", ret);

	ret = arm64_bl_patch(kallsyms_lookup_name("avc_has_perm_flags"), 384 * sizeof(uint32_t), (uintptr_t)slow_avc_audit_fn, (uintptr_t)ksu_slow_avc_audit_hook);
	pr_info("avc_spoof: hook on slow_avc_audit on avc_has_perm_flags ret: %d\n", ret);

	ret = arm64_bl_patch(kallsyms_lookup_name("avc_has_perm"), 384 * sizeof(uint32_t), (uintptr_t)slow_avc_audit_fn, (uintptr_t)ksu_slow_avc_audit_hook);
	pr_info("avc_spoof: hook on slow_avc_audit on avc_has_perm ret: %d\n", ret);

bail:
	return;
}

#elif defined(CONFIG_KPROBES)

#include <linux/kprobes.h>
#include "include/arch.h"

static struct kprobe *slow_avc_audit_kp;
static int slow_avc_audit_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	u32 *tsid = (u32 *)&PT_REGS_PARM3(regs);
#else
	u32 *tsid = (u32 *)&PT_REGS_PARM2(regs);
#endif
	ksu_slow_avc_audit_inline(tsid);

	return 0;
}

static struct kprobe *__init_kprobe(const char *name, kprobe_pre_handler_t handler)
{
	struct kprobe *kp = kzalloc(sizeof(struct kprobe), GFP_KERNEL);
	if (!kp)
		return NULL;
	kp->symbol_name = name;
	kp->pre_handler = handler;

	int ret = register_kprobe(kp);
	pr_info("%s: register %s kprobe: %d\n", __func__, name, ret);
	if (ret) {
		kfree(kp);
		return NULL;
	}

	return kp;
}

static void ksu_init_slow_avc_audit_hook(void) 
{
	int ret = ksu_selinux_get_sids();
	if (ret)
		pr_info("selinux_hide: sid grab fail?\n");

	slow_avc_audit_kp = __init_kprobe("slow_avc_audit", slow_avc_audit_pre_handler);
}

#else /* ! CONFIG_KPROBES */

#define ksu_init_slow_avc_audit_hook() do { } while (0)

#endif /* ! CONFIG_KPROBES */


#endif // __KSU_H_SLOW_AVC_AUDIT_HOOK
