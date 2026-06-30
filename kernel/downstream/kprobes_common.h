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

#ifndef __KSU_H_KPROBES_COMMON
#define __KSU_H_KPROBES_COMMON

// kprobes based symbol resolver.
// works better than kallsyms_lookup_xxx family
static uintptr_t kp_kallsyms_lookup_name(const char *name)
{
	struct kprobe kp = { .symbol_name = name };
	uintptr_t addr = NULL;

	if (!!register_kprobe(&kp))
		return NULL;

	addr = (uintptr_t)kp.addr;
	unregister_kprobe(&kp);

	return addr;
}

// heapified kprobe registration, copied from upstream
static struct kprobe *init_kprobe(const char *name, kprobe_pre_handler_t handler)
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

static void destroy_kprobe(struct kprobe **kp_ptr)
{
	struct kprobe *kp = *kp_ptr;
	if (!kp)
		return;

	unregister_kprobe(kp);
	synchronize_rcu();
	kfree(kp);
	*kp_ptr = NULL;
}

#endif // __KSU_H_KPROBES_COMMON

