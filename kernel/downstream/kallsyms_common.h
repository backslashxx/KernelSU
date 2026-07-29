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

static noinline uint64_t chibihash64_wrapper(const char *input)
{
	return chibihash64((void *)input, (ptrdiff_t)strnlen(input, KSYM_SYMBOL_LEN), 0ULL);
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
	__builtin_memcpy(newp, p, oldsize);
	kvfree(p);
	return newp;
}

static noinline void insert_to_kallsyms_array(const char *str, uintptr_t addr)
{
	if (!str || !addr)
		return;

	struct symbol_hash_entry *entries = (struct symbol_hash_entry *)kallsyms_hash_array;
	uint64_t hash = chibihash64_wrapper(str);

	if (!entries)
		goto skip_anti_dup;

	size_t i;
	for (i = 0; i < kallsyms_hash_array_entry_count; i++) {
		if (entries[i].hash == hash)
			return;
	}

skip_anti_dup:
	;

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

	pr_info("%s: hash array resized! %ld -> %ld bytes \n", __func__, old_sz, new_sz);

	void *new_array = old_kvrealloc(kallsyms_hash_array, old_sz, new_sz, GFP_KERNEL);
	if (!new_array)
		return;

	kallsyms_hash_array = new_array;
	kallsyms_hash_array_capacity = new_cap;
	entries = kallsyms_hash_array;

size_is_sufficient:

	entries[kallsyms_hash_array_entry_count].hash = hash;
	entries[kallsyms_hash_array_entry_count].addr = addr;
	kallsyms_hash_array_entry_count++;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)
__weak int sprint_symbol_no_offset(char *buffer, unsigned long address) { return sprint_symbol(buffer, address); }
#endif

static noinline __nocfi void dotted_kallsyms_build_hash_array(void)
{
	extern char _stext[], _etext[];
	uintptr_t start = (uintptr_t)_stext;
	uintptr_t end = (uintptr_t)_etext;
	uintptr_t iter_count = 0;
	uintptr_t curr;

	might_sleep();

	char *membuf __zoffstack(KSYM_SYMBOL_LEN * 2);
	if (!membuf)
		return;

	char *symbol_buf = membuf;
	char *symbol_cache = membuf + KSYM_SYMBOL_LEN;

#ifdef MODULE // https://elixir.bootlin.com/linux/v7.2-rc4/source/kernel/kprobes.c#L1506
	int (*kallsyms_lookup_size_offset_fn)(unsigned long addr, unsigned long *symbolsize, unsigned long *offset) = NULL;
	*(void **)&kallsyms_lookup_size_offset_fn = kallsyms_lookup_name("kallsyms_lookup_size_offset");
	if (!kallsyms_lookup_size_offset_fn)
		pr_info("%s: kallsyms_lookup_size_offset not found! \n", __func__);
#else
	extern int kallsyms_lookup_size_offset(unsigned long addr, unsigned long *symbolsize, unsigned long *offset);
	int (*kallsyms_lookup_size_offset_fn)(unsigned long addr, unsigned long *symbolsize, unsigned long *offset) = kallsyms_lookup_size_offset;
#endif

	pr_info("%s: hash array init! \n", __func__);

	curr = start;

scan_start:
	iter_count++;

	// not needed actually, sprint_symbol terminates.
	// we keep it here as a reminder.
	// memset(symbol_buf, 0, sizeof(symbol_buf));

	sprint_symbol_no_offset(symbol_buf, curr);
	if (!symbol_buf[0])
		goto step_up;

	// however we should not use cfi_jt for this
	// what we want is the target of that cfi_jt
	if (strstr(symbol_buf, ".cfi_jt"))
		goto step_up;

	// we should not use isra for this as gcc folded this functiom
	// to the point that it destroyed calling convention
	// hooking this is catastrophic!
	if (strstr(symbol_buf, ".isra."))
		goto step_up;

	// cut it with these to make sure its a match
	// .llvm.505034 or .lto_priv.0
	char *dot_ptr = strchr(symbol_buf, '.');
	if (!dot_ptr)
		goto step_up;

	// terminate on first dot
	dot_ptr[0] = '\0';

	// if current symbol is same as last entry, skip
	if (!strcmp(symbol_buf, symbol_cache))
		goto step_up;

	// symbol is not the same as the last one!
	// cache this symbol and insert it to our hash array!
	strscpy(symbol_cache, symbol_buf, KSYM_SYMBOL_LEN);

	insert_to_kallsyms_array(symbol_buf, curr);

step_up:
	;

	unsigned long sym_size = 0;
	unsigned long offset = 0;
	if (kallsyms_lookup_size_offset_fn && kallsyms_lookup_size_offset_fn(curr, &sym_size, &offset) && sym_size > offset)
		curr =  curr + (sym_size - offset); // we can do larger jumps
	else
		curr = curr + 4;

	if (curr < end)
		goto scan_start;

	pr_info("%s: scan done! total items: %zu, iter_count: %lu\n", __func__, kallsyms_hash_array_entry_count, iter_count);

	return;
}

static noinline uintptr_t kallsyms_lookup_hashed_name(const char *name)
{
	if (!name || !kallsyms_hash_array)
		return 0x0;

	uint64_t input_hash = chibihash64_wrapper(name);
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
	sprint_symbol_no_offset(symbol_buf, entries[i].addr);

	// sanity check, hash collision might occur
	if (unlikely(!strstarts(symbol_buf, name)))
		goto collision_found;

	pr_info("%s: %s hash: 0x%llx at 0x%lx\n", __func__, symbol_buf, input_hash, entries[i].addr);
	return entries[i].addr;

collision_found:
	// this is unlikely, but hell yeah lets log it if it happens
	pr_info("%s: chibihash64 collision! name: %s symbol_buf: %s hash: 0x%llx\n", __func__, name, symbol_buf, input_hash);
	return 0x0;
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

	sprint_symbol_no_offset(symbol_buf, curr);

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

// ksu says this isnt always available so lets use an fn ptr to try use it
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0) || defined(CONFIG_MODULES)
struct lookup_args {
	const char *target_name;
	uintptr_t target_addr;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
static int noop_kallsyms_on_each_symbol(int (*fn)(void *, const char *, unsigned long),void *data) { return 0; }
static int (*kallsyms_on_each_symbol_fn)(int (*fn)(void *, const char *, unsigned long),void *data) __read_mostly = noop_kallsyms_on_each_symbol;
static int kallsyms_on_each_symbol_cb(void *data, const char *name, unsigned long addr)
#else
static int noop_kallsyms_on_each_symbol(int (*fn)(void *, const char *, struct module *, unsigned long),void *data) { return 0; }
static int (*kallsyms_on_each_symbol_fn)(int (*fn)(void *, const char *, struct module *, unsigned long),void *data) __read_mostly = noop_kallsyms_on_each_symbol;
static int kallsyms_on_each_symbol_cb(void *data, const char *name, struct module *module, unsigned long addr)
#endif
{
	struct lookup_args *args = (struct lookup_args *)data;

	// however we should not use cfi_jt for this
	// what we want is the target of that cfi_jt
	if (strstr(name, ".cfi_jt"))
		return 0;

	// we should not use isra for this as gcc folded this functiom
	// to the point that it destroyed calling convention
	// hooking this is catastrophic!
	if (strstr(name, ".isra."))
		return 0;

	if (strstarts(name, args->target_name)) {
		args->target_addr = addr;
		return 1;
	}

	return 0;
}

static noinline __nocfi uintptr_t try_kallsyms_on_each_symbol(const char *name)
{
	struct lookup_args args;
	args.target_name = name;
	args.target_addr = 0x0;

	int ret = kallsyms_on_each_symbol_fn(kallsyms_on_each_symbol_cb, &args);
	if (ret && args.target_addr)
		pr_info("kallsyms_on_each_symbol: success! %s at 0x%lx\n", name, args.target_addr);

	return args.target_addr;
}
#endif

// if called within kthread, will try to build a kallsyms hash array when everything failed!
static noinline uintptr_t kallsyms_lookup_retry(const char *name)
{
	char namebuf[KSYM_NAME_LEN];
	if (!name)
		return 0x0;

	uintptr_t addr = (uintptr_t)kallsyms_lookup_name(name);
	if (addr)
		goto found;

#ifdef CONFIG_KPROBES
	addr = (uintptr_t)kp_kallsyms_lookup_name(name);
	if (addr)
		goto found;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0) || defined(CONFIG_MODULES)
	uintptr_t fn_ptr = (uintptr_t)kallsyms_lookup_name("kallsyms_on_each_symbol");
	if (!fn_ptr)
		goto skip_on_each_symbol;

	*(uintptr_t *)&kallsyms_on_each_symbol_fn = fn_ptr;
	addr = try_kallsyms_on_each_symbol(name);
	if (addr)
		goto found;

skip_on_each_symbol:
#endif

	smp_mb();
	if (kallsyms_hash_array_ready)
		return kallsyms_lookup_hashed_name(name);

	// only kthread is allowed to go further
	if (!(current->flags & PF_KTHREAD))
		return 0x0;

	mutex_lock(&kallsyms_hash_array_mutex);
	if (!kallsyms_hash_array_ready) {
		dotted_kallsyms_build_hash_array();
		kallsyms_hash_array_ready = true;
		smp_mb();
	}
	mutex_unlock(&kallsyms_hash_array_mutex);

	return kallsyms_lookup_hashed_name(name);
	
found:
	sprint_symbol_no_offset(namebuf, addr);
	pr_info("%s: %s addr: 0x%lx \n", __func__, namebuf, addr);
	return addr;
}

static noinline void dotted_kallsyms_destroy_hash_array(void)
{
	if (!kallsyms_hash_array)
		return;

	pr_info("%s: addr: 0x%lx entries: %u capacity: %u\n", __func__, (uintptr_t)kallsyms_hash_array, kallsyms_hash_array_entry_count, kallsyms_hash_array_capacity);

	memset_explicit(kallsyms_hash_array, 0, kallsyms_hash_array_entry_count * sizeof(struct symbol_hash_entry));

	kvfree(kallsyms_hash_array);

	kallsyms_hash_array = NULL;
	kallsyms_hash_array_entry_count = 0;
	kallsyms_hash_array_capacity = 0;

	const char *hw = "Hello, world!";
	pr_info("chibihash64: '%s' #: 0x%llx \n", hw, chibihash64_wrapper(hw) );
}

#endif // __KSU_H_KALLSYMS_COMMON
