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
// TODO: implement kallsyms_on_each_symbol before falling back to shitscanning.

static noinline uint64_t chibihash64_wrapper(const char *input, size_t len)
{
	return chibihash64((void *)input, (ptrdiff_t)len, 0xFFFFFFFFFFFFFFFFULL);
}

struct symbol_hash_entry {
	uint64_t hash;
	uintptr_t addr;
};

static void *kallsyms_hash_array = NULL;
static size_t kallsyms_hash_array_entry_count = 0;
static size_t kallsyms_hash_array_capacity = 0;

// TODO: rethink syncronization
static DEFINE_MUTEX(kallsyms_hash_array_mutex);
static volatile bool kallsyms_hash_array_ready __read_mostly = false;

// use this old version of kvrealloc to have full control on old size and new size.
// not a big deal, lets bring it with us.
static inline void *old_kvrealloc(const void *p, size_t oldsize, size_t newsize, gfp_t flags)
{
	void *newp;

	if (oldsize >= newsize)
		return (void *)p;
	newp = kvmalloc(newsize, flags);
	if (!newp)
		return NULL;
	memcpy(newp, p, oldsize);
	kvfree(p);
	return newp;
}

static noinline void insert_to_kallsyms_array(const char *str, uintptr_t addr)
{
	if (!str || !addr)
		return;

	uint64_t hash = chibihash64_wrapper(str, strlen(str));

	if (!kallsyms_hash_array)
		goto skip_anti_dup;

	size_t i;
	struct symbol_hash_entry *entries = (struct symbol_hash_entry *)kallsyms_hash_array;
	for (i = 0; i < kallsyms_hash_array_entry_count; i++) {
		if (entries[i].hash == hash)
			return;
	}

skip_anti_dup:
	;

	struct symbol_hash_entry entry;
	entry.hash = hash; 
	entry.addr = addr;

	if (kallsyms_hash_array_entry_count < kallsyms_hash_array_capacity)
		goto size_is_sufficient;

	// size insufficient, so we need to resize our memery
	// lets just go double everytime
	size_t new_cap;
	if (!kallsyms_hash_array_capacity)
		new_cap = 256; // init 256 slots
	else
		new_cap = kallsyms_hash_array_capacity * 2;

	size_t old_sz = kallsyms_hash_array_capacity * sizeof(struct symbol_hash_entry);
	size_t new_sz = new_cap * sizeof(struct symbol_hash_entry);

	// TODO: free this somewhere
	pr_info("%s: hash array resized! %ld -> %ld bytes \n", __func__, old_sz, new_sz);

	void *new_array = old_kvrealloc(kallsyms_hash_array, old_sz, new_sz, GFP_KERNEL);
	if (!new_array)
		return;

	kallsyms_hash_array = new_array;
	kallsyms_hash_array_capacity = new_cap;

size_is_sufficient:
	;

	uintptr_t tail = kallsyms_hash_array_entry_count * sizeof(struct symbol_hash_entry);
	memcpy((void *)((uintptr_t)kallsyms_hash_array + tail), &entry, sizeof(struct symbol_hash_entry));
	kallsyms_hash_array_entry_count++;
}

static noinline void dotted_kallsyms_build_hash_array(void)
{
	extern char _stext[], _etext[];
	uintptr_t start = (uintptr_t)_stext;
	uintptr_t end = (uintptr_t)_etext;
	uintptr_t iter_count = 0;
	uintptr_t curr;
	char symbol_buf[KSYM_SYMBOL_LEN];

	might_sleep();

	pr_info("%s: hash array init! \n", __func__);

	curr = start;

scan_start:
	iter_count++;

	memset(symbol_buf, 0, sizeof(symbol_buf));

	sprint_symbol(symbol_buf, curr);
	if (!symbol_buf[0])
		goto step_up;

	// however we should not use cfi_jt for this
	// what we want is the target of that cfi_jt
	if (strstr(symbol_buf, "cfi_jt"))
		goto step_up;

	// cut it with these to make sure its a match
	// .llvm.505034 or .lto_priv.0
	char *dot_ptr = strchr(symbol_buf, '.');
	if (!dot_ptr)
		goto step_up;

	dot_ptr[0] = '\0';

	insert_to_kallsyms_array(symbol_buf, curr);

step_up:
	curr = curr + 4;
	if (curr < end)
		goto scan_start;

	pr_info("%s: scan done! total items: %zu, iter_count: %lu\n", __func__, kallsyms_hash_array_entry_count, iter_count);

	return;
}


static noinline uintptr_t kallsyms_lookup_hashed_name(const char *name)
{
	if (!name || !kallsyms_hash_array)
		return 0;

	uint64_t input_hash = chibihash64_wrapper(name, strlen(name));
	struct symbol_hash_entry *entries = (struct symbol_hash_entry *)kallsyms_hash_array;
	char symbol_buf[KSYM_SYMBOL_LEN];
	size_t i;

	for (i = 0; i < kallsyms_hash_array_entry_count; i++) {
		if (entries[i].hash == input_hash)
			goto found;
	}

	pr_info("%s: not found: %s hash: 0x%llx\n", __func__, name, input_hash);
	return 0x0;

found:
	sprint_symbol(symbol_buf, entries[i].addr);
	pr_info("%s: %s hash: 0x%llx at 0x%lx\n", __func__, symbol_buf, input_hash, entries[i].addr);
	return entries[i].addr;
}

#if 0
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
#endif

// kthread context only, we need to scan the kernel for the damn thing if not found!
static noinline uintptr_t kallsyms_lookup_in_kthread(const char *name)
{
	if (!name)
		return 0x0;

	// assert we are in a kthread
	if (!(current->flags & PF_KTHREAD))
		return 0x0;

	uint8_t z = 0;
	uintptr_t addr = (uintptr_t)kallsyms_lookup_name(name);
	if (addr)
		goto found;

#ifdef CONFIG_KPROBES
	z = 1;
	addr = (uintptr_t)kp_kallsyms_lookup_name(name);
	if (addr)
		goto found;
#endif

	z = 2; // quick look for .lto_priv.0
	char namebuf[KSYM_NAME_LEN];
	snprintf(namebuf, sizeof(namebuf), "%s.lto_priv.0", name);
	addr = (uintptr_t)kallsyms_lookup_name(namebuf);
	if (addr)
		goto found;

	if (kallsyms_hash_array_ready)
		return kallsyms_lookup_hashed_name(name);

	mutex_lock(&kallsyms_hash_array_mutex);
	if (!kallsyms_hash_array_ready) {
		dotted_kallsyms_build_hash_array();
		kallsyms_hash_array_ready = true;
		smp_mb();
	}
	mutex_unlock(&kallsyms_hash_array_mutex);

	return kallsyms_lookup_hashed_name(name);
	
found:
	pr_info("%s: %s addr: 0x%lx \n", (!z) ? "kallsyms_lookup_name" : "kp_kallsyms_lookup_name", (z == 2) ? namebuf : name, addr);
	return addr;
}

static noinline uintptr_t kallsyms_lookup_retry(const char *name)
{
	if (!name)
		return 0x0;

	uint8_t z = 0;
	uintptr_t addr = (uintptr_t)kallsyms_lookup_name(name);
	if (addr)
		goto found;

#ifdef CONFIG_KPROBES
	z = 1;
	addr = (uintptr_t)kp_kallsyms_lookup_name(name);
	if (addr)
		goto found;
#endif

	z = 2; // quick look for .lto_priv.0
	char namebuf[KSYM_NAME_LEN];
	snprintf(namebuf, sizeof(namebuf), "%s.lto_priv.0", name);
	addr = (uintptr_t)kallsyms_lookup_name(namebuf);
	if (addr)
		goto found;

	if (kallsyms_hash_array_ready)
		return kallsyms_lookup_hashed_name(name);

	return 0x0;
found:
	pr_info("%s: %s addr: 0x%lx \n", (!z) ? "kallsyms_lookup_name" : "kp_kallsyms_lookup_name", (z == 2) ? namebuf : name, addr);
	return addr;
}

#endif // __KSU_H_KALLSYMS_COMMON
