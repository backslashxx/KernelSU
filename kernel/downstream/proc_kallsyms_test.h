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

#ifndef __KSU_H_KSYM_TEST
#define __KSU_H_KSYM_TEST

#include <linux/../../fs/proc/internal.h>

struct uint64_tx7 {
	uint64_t magic;
	uint64_t r0;
	uint64_t r1;
	uint64_t r2;
	uint64_t r3;
	uint64_t r4;
	uint64_t r5;
	uint64_t r6;
};

__attribute__((used))
static __nocfi ssize_t ksym_write(struct file *file, const char __user *reg, size_t size, loff_t *lofft)
{
	uint64_t magic;	
	if (!!copy_from_user(&magic, (void *)reg, sizeof(magic)))
		return size;

	if (magic != 0xFFFFFFFFFFFFFFFF)
		return size;

	pr_info("ksym_test: got shitcall\n");

	struct uint64_tx7 *buf __zoffstack(sizeof(*buf));
	if (!buf)
		return size;

	if (!!copy_from_user(buf, (void *)reg, sizeof(*buf)))
		return size;

	pr_info("0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx\n", buf->r0, buf->r1, buf->r2, buf->r3, buf->r4, buf->r5, buf->r6);

	uint64_t reply = 0xAAAAAAAAAAAAAAAA;
	copy_to_user((void *)reg, &reply, sizeof(reply));

	return size;
}

static int ksu_init_hook_kallsyms_ops(void *unused)
{
	// late init only, we are also on device_initcall
	// msleep(30000);

	struct path path;
	const char *proc_kallsyms = "/proc/kallsyms";

	int error = kern_path(proc_kallsyms, LOOKUP_FOLLOW, &path);
	if (error) {
		pr_info("ksym_test: kern_path err: %d\n", error);
		return 0;
	}
	
	pr_info("ksym_test: kern_path %s ok!\n", proc_kallsyms);

	if (!path.dentry)
		goto bail_out;

	if (!d_inode(path.dentry))
		goto bail_out;	

	pr_info("ksym_test: path_dentry %s ok!\n", proc_kallsyms);

	// https://elixir.bootlin.com/linux/v4.14.1/source/fs/proc/internal.h#L83
	struct proc_dir_entry *pde = PDE(d_inode(path.dentry));
	if (!pde)
		goto bail_out;

	pr_info("ksym_test: pde %s ok!\n", proc_kallsyms);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0) // union but kallsyms_operation uses proc ops, one pointer offset.
	struct proc_ops *ops = (struct proc_ops *)pde->proc_ops;
	if (!ops)
		goto bail_out;

	uintptr_t write_slot_ptr = (uintptr_t)&ops->proc_write;
#else
	struct file_operations *ops = (struct file_operations *)pde->proc_fops;
	if (!ops)
		goto bail_out;

	uintptr_t write_slot_ptr = (uintptr_t)&ops->write;
#endif


	pr_info("ksym_test: ops %s ok!\n", proc_kallsyms);
	pr_info("ksym_test: found kallsyms_operations->write at slot 0x%lx pointing to 0x%lx \n", (uintptr_t)write_slot_ptr, *(uintptr_t *)write_slot_ptr);

	int ret = ksu_write_to_readonly_slot(write_slot_ptr, (uintptr_t)ksym_write);

	pr_info("ksym_test: kallsyms_operations->write hijack ret: %d ops->write: 0x%lx\n", ret, *(uintptr_t *)write_slot_ptr);

bail_out:
	path_put(&path);
	return 0;
}

void __init ksu_ksym_test_init()
{
	kthread_run(ksu_init_hook_kallsyms_ops, NULL, "kthread");
}

#endif // __KSU_H_KSYM_TEST
