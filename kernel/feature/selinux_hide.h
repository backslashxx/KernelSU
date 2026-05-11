#ifndef __KSU_H_SELINUX_HIDE
#define __KSU_H_SELINUX_HIDE

void ksu_selinux_hide_init();
void ksu_selinux_hide_exit();

// /selinux/rules.c, linked list
LIST_HEAD(ksu_hide_type_list);
LIST_HEAD(ksu_hide_rule_list);

DEFINE_RWLOCK(ksu_sepolicy_shitlist_lock);

struct ksu_type_node {
	struct list_head list;
	char *padded_name;
};

struct ksu_rule_node {
	struct list_head list;
	char *src;
	char *tgt;
};

static int sepol_expected_argc(u32 cmd);

static void ksu_add_shit_to_list(u32 cmd, const char *args[])
{
	if (!args || !args[0])
		return;

	int argc = sepol_expected_argc(cmd);
	write_lock(&ksu_sepolicy_shitlist_lock);

	size_t len;

	if (cmd == KSU_SEPOLICY_CMD_TYPE || cmd == KSU_SEPOLICY_CMD_TYPE_ATTR || cmd == KSU_SEPOLICY_CMD_TYPE_STATE || cmd == KSU_SEPOLICY_CMD_ATTR) {
		
		const char *name = args[0];
		len = strlen(name);

		// no need after rule matching, keep as a reminder though
		//if (!strcmp(name, "zygote") || !strcmp(name, "app_zygote"))
		//	goto out_unlock;

		struct ksu_type_node *t_node;
		list_for_each_entry(t_node, &ksu_hide_type_list, list) {
			if (strlen(t_node->padded_name) == (len + 2) && !memcmp(t_node->padded_name + 1, name, len))
				goto out_unlock;
		}

		t_node = kmalloc(sizeof(*t_node), GFP_ATOMIC);
		if (!t_node)
			goto out_unlock;
		
		t_node->padded_name = kmalloc(len + 3, GFP_ATOMIC);
		if (!t_node->padded_name) {
			kfree(t_node);
			goto out_unlock;
		}
		
		snprintf(t_node->padded_name, len + 3, ":%s:", name);
		list_add(&t_node->list, &ksu_hide_type_list);

		if (IS_ENABLED(CONFIG_KSU_DEBUG))
			pr_info("selinux_hide: tracking type: %s \n", t_node->padded_name);

	} else if (argc >= 2) {
		const char *src = args[0];
		const char *tgt = args[1];

		// for zygote, a x x y rules, we grab x y
		// if (!strcmp(src, "zygote") && args[2] && !strcmp(src, tgt))
		//	tgt = args[2];

		struct ksu_rule_node *r_node;
		list_for_each_entry(r_node, &ksu_hide_rule_list, list) {
			if (strstarts(r_node->src + 1, src) && strstarts(r_node->tgt + 1, tgt))
				goto out_unlock;
		}

		r_node = kmalloc(sizeof(*r_node), GFP_ATOMIC);
		if (!r_node)
			goto out_unlock;

		r_node->src = kmalloc(strlen(src) + 3, GFP_ATOMIC);
		if (!r_node->src) {
			kfree(r_node);
			goto out_unlock;
		}		
		snprintf(r_node->src, strlen(src) + 3, ":%s:", src);

		r_node->tgt = kmalloc(strlen(tgt) + 3, GFP_ATOMIC);
		if (!r_node->tgt) {
			kfree(r_node->src);
			kfree(r_node);
			goto out_unlock;
		}
		snprintf(r_node->tgt, strlen(tgt) + 3, ":%s:", tgt);

		list_add(&r_node->list, &ksu_hide_rule_list);

		if (IS_ENABLED(CONFIG_KSU_DEBUG))
			pr_info("selinux_hide: tracking rule: %s %s \n", r_node->src, r_node->tgt);

	}

out_unlock:
	write_unlock(&ksu_sepolicy_shitlist_lock);
}


#endif
