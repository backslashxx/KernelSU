#ifndef __KSU_H_SELINUX_HIDE
#define __KSU_H_SELINUX_HIDE

void ksu_selinux_hide_init();
void ksu_selinux_hide_exit();

// /selinux/rules.c, linked list
LIST_HEAD(ksu_sepolicy_rule_list);
DEFINE_RWLOCK(ksu_sepolicy_shitlist_lock);

struct ksu_hidden_node {
	struct list_head list;
	char *name;
};

static void ksu_add_shit_to_list(const char *name)
{
	if (!name)
		return;

	if (!strcmp(name, "zygote"))
		return;

	struct ksu_hidden_node *node;
	size_t name_len = strlen(name);

	// check for dupes
	write_lock(&ksu_sepolicy_shitlist_lock);
	list_for_each_entry(node, &ksu_sepolicy_rule_list, list) {
		// ":name:"
		if (strlen(node->name) == (name_len + 2) && !memcmp(node->name + 1, name, name_len))
			goto unlock_list;
	}

	node = kmalloc(sizeof(*node), GFP_ATOMIC);
	if (!node)
		goto unlock_list;

	// ':' + original + ':' + \0
	size_t len = strlen(name);	
	node->name = kmalloc(name_len + 3, GFP_ATOMIC);
	if (!node->name) {
		kfree(node);
		goto unlock_list;
	}

	node->name[0] = ':';
	memcpy(node->name + 1, name, name_len);
	node->name[name_len + 1] = ':';
	node->name[name_len + 2] = '\0';

	list_add(&node->list, &ksu_sepolicy_rule_list);

	if (IS_ENABLED(CONFIG_KSU_DEBUG))
		pr_info("%s: now tracking type: %s, padded: %s \n", __func__, name, node->name);

unlock_list:
	write_unlock(&ksu_sepolicy_shitlist_lock);
	return;
}

#endif
