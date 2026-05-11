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

#ifndef __KSU_H_SELINUX_HIDE
#define __KSU_H_SELINUX_HIDE

void ksu_selinux_hide_init();
void ksu_selinux_hide_exit();

static int sepol_expected_argc(u32 cmd);

// TODO: move to atomic refcounting or rcu?
// this way readers can be lockless

// flex array
struct ksu_hide_buf {
	size_t len;
	char data[];
};

// types
// :type1:\0:type2:\0:type3:\0
static struct ksu_hide_buf *ksu_hide_type_list __read_mostly = NULL;

// rules
// :src1:\0:tgt1:\0:src2:\0:tgt2:\0:src3:\0:tgt3:\0
static struct ksu_hide_buf *ksu_hide_rule_list __read_mostly = NULL;

static DEFINE_MUTEX(selinux_hide_list_mutex);

static noinline void ksu_add_shit_to_list(u32 cmd, const char *args[])
{
	if (!args || !args[0])
		return;

	guarded_mutex_lock(&selinux_hide_list_mutex);

	int argc = sepol_expected_argc(cmd);

	if (cmd == KSU_SEPOLICY_CMD_TYPE || cmd == KSU_SEPOLICY_CMD_TYPE_ATTR || cmd == KSU_SEPOLICY_CMD_TYPE_STATE || cmd == KSU_SEPOLICY_CMD_ATTR) {
		
		const char *name = args[0];
		size_t needed_len = strlen(name) + 3; // :type:\0

		if (!ksu_hide_type_list)
			goto skip_type_dup_check;

		// anti duplicate
		size_t offset = 0;
		while (ksu_hide_type_list->len > offset) {
			const char *current_type = ksu_hide_type_list->data + offset;

			char tmp_buf[64];
			snprintf(tmp_buf, sizeof(tmp_buf), ":%s:", name);

			if (!strcmp(current_type, tmp_buf))
				return;

			offset = offset + strlen(current_type) + 1;
		}

	skip_type_dup_check:
		;
		size_t old_len = (ksu_hide_type_list) ? ksu_hide_type_list->len : 0;
		size_t new_total_len = old_len + needed_len;

		struct ksu_hide_buf *new_ptr = kmalloc(sizeof(*new_ptr) + new_total_len, GFP_KERNEL);
		if (!new_ptr)
			return;

		new_ptr->len = new_total_len;

		if (ksu_hide_type_list && old_len > 0)
			memcpy(new_ptr->data, ksu_hide_type_list->data, old_len);

		char *w_ptr = new_ptr->data + old_len;
		sprintf(w_ptr, ":%s:", name);

		struct ksu_hide_buf *old_ptr = ksu_hide_type_list;
		ksu_hide_type_list = new_ptr;
		kfree(old_ptr);

		pr_info("selinux_hide: tracking type: %s\n", w_ptr);


	} else if (argc >= 2) {

		if (!args[1])
			return;

		const char *src = args[0];
		const char *tgt = args[1];

		size_t src_needed = strlen(src) + 3; // :src:\0
		size_t tgt_needed = strlen(tgt) + 3; // :tgt:\0
		size_t needed_len = src_needed + tgt_needed;

		if (!ksu_hide_rule_list)
			goto skip_rule_dup_check;

		// anti duplicate
		size_t offset = 0;
		while (ksu_hide_rule_list->len > offset) {
			const char *src_chk = ksu_hide_rule_list->data + offset;
			size_t src_sz = strlen(src_chk) + 1; // for \0

			const char *tgt_chk = src_chk + src_sz;
			size_t tgt_sz = strlen(tgt_chk) + 1; // for \0

			char src_buf[64], tgt_buf[64];
			snprintf(src_buf, sizeof(src_buf), ":%s:", src);
			snprintf(tgt_buf, sizeof(tgt_buf), ":%s:", tgt);

			if (!strcmp(src_chk, src_buf) && !strcmp(tgt_chk, tgt_buf))
				return;

			offset = offset + src_sz + tgt_sz;
		}

	skip_rule_dup_check:
		;
		size_t old_len = (ksu_hide_rule_list) ? ksu_hide_rule_list->len : 0;
		size_t new_total_len = old_len + needed_len;

		struct ksu_hide_buf *new_ptr = kmalloc(sizeof(*new_ptr) + new_total_len, GFP_KERNEL);
		if (!new_ptr)
			return;

		new_ptr->len = new_total_len;

		if (ksu_hide_rule_list && old_len > 0)
			memcpy(new_ptr->data, ksu_hide_rule_list->data, old_len);

		char *w_ptr_src = new_ptr->data + old_len;
		sprintf(w_ptr_src, ":%s:", src);

		char *w_ptr_tgt = w_ptr_src + strlen(w_ptr_src) + 1;
		sprintf(w_ptr_tgt, ":%s:", tgt);

		struct ksu_hide_buf *old_ptr = ksu_hide_rule_list;
		ksu_hide_rule_list = new_ptr;
		kfree(old_ptr);

		pr_info("selinux_hide: tracking rule: %s %s\n", w_ptr_src, w_ptr_tgt);

	}

	return;
}

static bool ksu_should_destroy_context(char *str)
{
	if (!str)
		return false;

	guarded_mutex_lock(&selinux_hide_list_mutex);
	size_t offset;

	if (!ksu_hide_type_list)
		goto rule_check;
	
	offset = 0;
	while (ksu_hide_type_list->len > offset) {
		const char *current_entry = ksu_hide_type_list->data + offset;

		if (strstr(str, current_entry))
			return true;

		offset = offset + strlen(current_entry) + 1;
	}

rule_check:
	; // double strstr
	char *str2 = strchr(str, ' ');
	if (!str2)
		return false;

	if (!ksu_hide_rule_list)
		return false;

	offset = 0;
	while (ksu_hide_rule_list->len > offset) {
		const char *src_rule = ksu_hide_rule_list->data + offset;
		size_t src_sz = strlen(src_rule) + 1;

		const char *tgt_rule = src_rule + src_sz;
		size_t tgt_sz = strlen(tgt_rule) + 1;

		if (strstr(str, src_rule) && strstr(str2, tgt_rule))
			return true;

		offset = offset + src_sz + tgt_sz;
	}

	return false;
}

#endif
