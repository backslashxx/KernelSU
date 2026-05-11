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

static void ksu_add_shit_to_list(const char *name);

#endif
