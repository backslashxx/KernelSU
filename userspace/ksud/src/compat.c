// SPDX-License-Identifier: GPL-3.0-or-later
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
#include <stddef.h>
#include <stdint.h>
#include <dlfcn.h>
#include <signal.h>
#include <errno.h>
#include <sys/ucontext.h>

/**
 * compat handling for: https://github.com/tiann/KernelSU/pull/3624
 * - __system_property_read_callback does not exist on Android 7.x
 *
 * ref:
 * - https://t.me/kowchannelchat/281510
 * - https://github.com/GrapheneOS/platform_bionic/blob/b95b08888b9eb6465c21d5840cce59dc463bfdef/libc/bionic/system_property_api.cpp#L78
 * - https://android.googlesource.com/platform/bionic/+/0d787c1fa18c6a1f29ef9840e28a68cf077be1de/libc/bionic/system_properties.c
 *
 */
__attribute__((used))
void compat_system_property_read_callback(const void *pi,
		void (*callback)(void *, const char *, const char *, uint32_t),
		void *cookie)
{
	static typeof(compat_system_property_read_callback) *cb_fn;
	static int (*read_fn)(const void *, char *, char *);

#define PROP_VALUE_MAX 92
#define PROP_NAME_MAX 32
	char value[PROP_VALUE_MAX];
	char name[PROP_NAME_MAX];
	int serial;

	static void *label = &&bootstrap1;
	goto *label;

bootstrap1:
	cb_fn = dlsym(RTLD_DEFAULT, "__system_property_read_callback");
	if (!cb_fn)
		goto bootstrap2;

	label = &&fn1_ok;
fn1_ok:
	cb_fn(pi, callback, cookie);
	return;

bootstrap2:
	read_fn = dlsym(RTLD_DEFAULT, "__system_property_read");
	if (!read_fn)
		__builtin_trap();

	label = &&fn2_ok;
fn2_ok:
	if (!callback)
		return;

	value[0] = 0;
	name[0] = 0;
	serial = 0;

	// NOTE: make sure to check for pi, it is *'d right after
	if (!!pi)
		serial = read_fn(pi, name, value);

	callback(cookie, name, value, (uint32_t)serial);
}

/**
 * HandleSigsysSeccompOverride
 * ref: https://github.com/LineageOS/android_bionic/blob/ff9fe01e7e1e81febaf32b15fa561aec480a112c/libc/bionic/android_profiling_dynamic.cpp#L187
 */

__attribute__((used))
void compat_sigsys_set_return(void *void_context, int ret)
{
	ucontext_t *ctx = (ucontext_t *)void_context;

#if defined(__aarch64__)
	ctx->uc_mcontext.regs[0] = ret;
#elif defined(__arm__)
	ctx->uc_mcontext.arm_r0 = ret;
#elif defined(__i386__)
	ctx->uc_mcontext.gregs[REG_EAX] = ret;
#elif defined(__riscv)
	ctx->uc_mcontext.__gregs[REG_A0] = ret;
#elif defined(__x86_64__)
	ctx->uc_mcontext.gregs[REG_RAX] = ret;
#else
# error "unsupported architecture"
#endif
}
