#ifndef __KSU_H_KSU_CORE
#define __KSU_H_KSU_CORE

void __init ksu_core_init(void);

// for the umount list
struct mount_entry {
    char *umountable;
    unsigned int flags;
    struct list_head list;
};
extern struct list_head mount_list;
extern struct rw_semaphore mount_list_lock;

#endif
